"""Build and Ed25519-sign an OpenGuard security-content manifest."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--content-root", type=Path, default=Path("security-content"))
    parser.add_argument("--output", type=Path, default=Path("security-content/manifest.json"))
    arguments = parser.parse_args()
    key_text = os.environ.get("OPENGUARD_UPDATE_PRIVATE_KEY", "")
    if not key_text:
        raise SystemExit("OPENGUARD_UPDATE_PRIVATE_KEY is required")
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_text, validate=True))
    relative_paths = (Path("rules/community.yar"), Path("reputation.json"))
    files: list[dict[str, object]] = []
    for relative in relative_paths:
        data = (arguments.content_root / relative).read_bytes()
        files.append(
            {
                "path": relative.as_posix(),
                "url": f"{arguments.base_url.rstrip('/')}/{relative.as_posix()}",
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    manifest: dict[str, object] = {
        "schema": 1,
        "version": arguments.version,
        "published_at": "2026-08-07T00:00:00Z",
        "files": files,
    }
    manifest["signature"] = base64.b64encode(private_key.sign(canonical(manifest))).decode("ascii")
    arguments.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
