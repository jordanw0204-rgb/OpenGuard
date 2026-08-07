"""Authenticated, atomic updates for OpenGuard security content."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import tempfile
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import active_content_path, security_content_root
from .yara_engine import YaraEngine

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CONTENT_FILE_BYTES = 64 * 1024 * 1024
VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class UpdateError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ContentFile:
    path: str
    url: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class UpdateManifest:
    schema: int
    version: str
    published_at: str
    files: tuple[ContentFile, ...]
    signature: str


def canonical_manifest_payload(raw: dict[str, Any]) -> bytes:
    payload = {key: value for key, value in raw.items() if key != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


class SecurityContentUpdater:
    def __init__(self, public_key: bytes | None = None, root: Path | None = None) -> None:
        self.root = (root or security_content_root()).resolve()
        self.public_key = public_key or _load_public_key()

    def fetch_and_install(self, manifest_url: str) -> str:
        _require_https(manifest_url)
        manifest_bytes = _download(manifest_url, MAX_MANIFEST_BYTES)
        return self.install(manifest_bytes)

    def install(
        self,
        manifest_bytes: bytes,
        fetcher: Callable[[str, int], bytes] | None = None,
    ) -> str:
        raw, manifest = self.verify_manifest(manifest_bytes)
        fetch = fetcher or _download
        self.root.mkdir(parents=True, exist_ok=True)
        versions_root = self.root / "versions"
        versions_root.mkdir(parents=True, exist_ok=True)
        destination = versions_root / manifest.version
        if destination.exists():
            self._activate(manifest.version)
            return manifest.version

        staging = Path(tempfile.mkdtemp(prefix="update-", dir=self.root))
        try:
            for item in manifest.files:
                data = fetch(item.url, item.size)
                if len(data) != item.size:
                    raise UpdateError(f"Size mismatch for {item.path}")
                digest = hashlib.sha256(data).hexdigest()
                if digest.casefold() != item.sha256.casefold():
                    raise UpdateError(f"SHA-256 mismatch for {item.path}")
                target = staging.joinpath(*PurePosixPath(item.path).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            self._validate_staging(staging)
            (staging / "manifest.json").write_bytes(
                json.dumps(raw, indent=2, sort_keys=True).encode("utf-8")
            )
            os.replace(staging, destination)
            self._activate(manifest.version)
            return manifest.version
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise

    def verify_manifest(self, manifest_bytes: bytes) -> tuple[dict[str, Any], UpdateManifest]:
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise UpdateError("Manifest exceeds the size limit")
        try:
            raw = json.loads(manifest_bytes.decode("utf-8"))
            if not isinstance(raw, dict):
                raise TypeError("manifest must be an object")
            signature = base64.b64decode(str(raw["signature"]), validate=True)
            Ed25519PublicKey.from_public_bytes(self.public_key).verify(
                signature, canonical_manifest_payload(raw)
            )
        except (KeyError, TypeError, ValueError, InvalidSignature) as error:
            raise UpdateError("Manifest signature is invalid") from error

        if raw.get("schema") != 1:
            raise UpdateError("Unsupported manifest schema")
        version = str(raw.get("version", ""))
        if not VERSION_PATTERN.fullmatch(version):
            raise UpdateError("Invalid content version")
        published_at = str(raw.get("published_at", ""))
        items = raw.get("files")
        if not isinstance(items, list) or not items:
            raise UpdateError("Manifest contains no files")
        files: list[ContentFile] = []
        seen: set[str] = set()
        for value in items:
            if not isinstance(value, dict):
                raise UpdateError("Invalid file entry")
            path = _safe_content_path(str(value.get("path", "")))
            if path in seen:
                raise UpdateError(f"Duplicate content path: {path}")
            seen.add(path)
            url = str(value.get("url", ""))
            _require_https(url)
            digest = str(value.get("sha256", "")).casefold()
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise UpdateError(f"Invalid SHA-256 for {path}")
            try:
                size = int(value.get("size", -1))
            except (TypeError, ValueError) as error:
                raise UpdateError(f"Invalid size for {path}") from error
            if size < 0 or size > MAX_CONTENT_FILE_BYTES:
                raise UpdateError(f"Invalid size for {path}")
            files.append(ContentFile(path, url, digest, size))
        return raw, UpdateManifest(1, version, published_at, tuple(files), str(raw["signature"]))

    def rollback(self) -> str:
        state = self.state()
        previous = str(state.get("previous_version", ""))
        if not previous or not (self.root / "versions" / previous).is_dir():
            raise UpdateError("No valid previous content version is available")
        current = str(state.get("active_version", ""))
        _atomic_json(
            self.root / "active.json",
            {"active_version": previous, "previous_version": current},
        )
        return previous

    def state(self) -> dict[str, Any]:
        try:
            value = json.loads((self.root / "active.json").read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}

    def _activate(self, version: str) -> None:
        current = str(self.state().get("active_version", ""))
        _atomic_json(
            self.root / "active.json",
            {"active_version": version, "previous_version": current if current != version else ""},
        )

    @staticmethod
    def _validate_staging(staging: Path) -> None:
        rules = sorted((staging / "rules").glob("*.yar"))
        if rules:
            YaraEngine.validate_sources(rules)
        reputation = staging / "reputation.json"
        if reputation.exists():
            value = json.loads(reputation.read_text(encoding="utf-8"))
            if not isinstance(value, dict) or value.get("schema") != 1:
                raise UpdateError("Invalid reputation feed schema")
            entries = value.get("entries", [])
            if not isinstance(entries, list):
                raise UpdateError("Invalid reputation feed entries")


def _safe_content_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise UpdateError("Unsafe content path")
    normalized = path.as_posix()
    if normalized == "reputation.json":
        return normalized
    if len(path.parts) == 2 and path.parts[0] == "rules" and path.suffix == ".yar":
        return normalized
    raise UpdateError(f"Unsupported content path: {normalized}")


def _require_https(url: str) -> None:
    if not url.casefold().startswith("https://"):
        raise UpdateError("Security content URLs must use HTTPS")


def _download(url: str, expected_max: int) -> bytes:
    _require_https(url)
    request = urllib.request.Request(url, headers={"User-Agent": "OpenGuard/0.2"})
    with urllib.request.urlopen(request, timeout=20) as response:
        _require_https(response.geturl())
        limit = min(max(expected_max, 0), MAX_CONTENT_FILE_BYTES)
        data = response.read(limit + 1)
    if len(data) > limit:
        raise UpdateError("Downloaded content exceeds its declared limit")
    return data


def _load_public_key() -> bytes:
    path = Path(__file__).with_name("data") / "update_public_key.txt"
    try:
        value = base64.b64decode(path.read_text(encoding="ascii").strip(), validate=True)
    except (OSError, ValueError) as error:
        raise UpdateError("Pinned update public key is unavailable") from error
    if len(value) != 32:
        raise UpdateError("Pinned update public key has the wrong length")
    return value


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)
