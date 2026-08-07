"""Local, transparent file scanner with optional installed-provider AMSI."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import threading
import uuid
from collections import Counter
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from .config import MAX_CONTENT_INSPECTION_BYTES, MAX_HASH_BYTES, quarantine_root
from .models import (
    ScanFinding,
    ScanProfile,
    ScanVerdict,
    SecurityEvent,
    Severity,
    SignatureStatus,
    utc_now,
)
from .storage import Database
from .windows_api import AmsiScanner, WindowsNative
from .yara_engine import YaraEngine
from .profiles import profile_targets

EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".msi"}
SCRIPT_EXTENSIONS = {".ps1", ".psm1", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".hta"}
LURE_EXTENSIONS = {
    ".doc",
    ".docx",
    ".gif",
    ".jpg",
    ".jpeg",
    ".pdf",
    ".png",
    ".txt",
    ".xls",
    ".xlsx",
}

SCRIPT_SIGNALS: tuple[tuple[re.Pattern[str], int, str], ...] = (
    (re.compile(r"(?:-|/)enc(?:odedcommand)?\b", re.I), 28, "Encoded command execution"),
    (re.compile(r"frombase64string\s*\(", re.I), 18, "Base64 payload decoding"),
    (re.compile(r"\b(?:invoke-expression|iex)\b", re.I), 20, "Dynamic expression execution"),
    (re.compile(r"\bdownloadstring\s*\(", re.I), 28, "Downloads executable script content"),
    (re.compile(r"\b(?:virtualalloc|writeprocessmemory|createremotethread)\b", re.I), 35, "Process injection API reference"),
    (re.compile(r"\bmshta(?:\.exe)?\b", re.I), 16, "HTML application host execution"),
    (re.compile(r"\bregsvr32(?:\.exe)?\b.*(?:/i:|/u)", re.I), 18, "Regsvr32 scriptlet-style execution"),
    (re.compile(r"\brundll32(?:\.exe)?\b.*(?:javascript:|http)", re.I), 22, "Rundll32 remote/script execution"),
)


class Scanner:
    def __init__(
        self,
        database: Database | None = None,
        native: WindowsNative | None = None,
        *,
        amsi_enabled: bool = True,
        known_hashes: dict[str, dict[str, Any]] | None = None,
        yara_engine: YaraEngine | None = None,
    ) -> None:
        self.database = database
        self.native = native
        self.amsi_enabled = amsi_enabled
        self.amsi = AmsiScanner() if amsi_enabled else None
        self.known_hashes = known_hashes if known_hashes is not None else _load_known_hashes()
        self.yara = yara_engine if yara_engine is not None else YaraEngine()

    def close(self) -> None:
        if self.amsi is not None:
            self.amsi.close()

    def scan_file(
        self, path: str | Path, cancel: threading.Event | None = None
    ) -> ScanFinding:
        candidate = Path(path)
        if cancel is not None and cancel.is_set():
            return self._finish(
                ScanFinding(str(candidate), ScanVerdict.CANCELLED, 0, ("Scan cancelled",))
            )
        try:
            if not candidate.exists():
                raise FileNotFoundError(f"File does not exist: {candidate}")
            if not candidate.is_file():
                raise IsADirectoryError(f"Not a regular file: {candidate}")
            if self.database is not None and self.database.path_excluded(candidate):
                return self._finish(
                    ScanFinding(
                        str(candidate.resolve()),
                        ScanVerdict.SKIPPED,
                        0,
                        ("Path is excluded by the user",),
                    )
                )
            stat = candidate.stat()
            if stat.st_size > MAX_HASH_BYTES:
                return self._finish(
                    ScanFinding(
                        str(candidate),
                        ScanVerdict.SKIPPED,
                        0,
                        (f"File exceeds the {MAX_HASH_BYTES // (1024**3)} GiB safety limit",),
                        size_bytes=stat.st_size,
                    )
                )
            digest, content, cancelled = _read_hash_and_content(candidate, cancel)
            if cancelled:
                return self._finish(
                    ScanFinding(
                        str(candidate),
                        ScanVerdict.CANCELLED,
                        0,
                        ("Scan cancelled",),
                        size_bytes=stat.st_size,
                    )
                )
            score = 0
            reasons: list[str] = []
            suffix = candidate.suffix.casefold()
            signature = SignatureStatus.NOT_APPLICABLE

            allowed = self.database.allowed_hash(digest) if self.database is not None else None
            if allowed is not None:
                label = str(allowed.get("label") or "user allow-list")
                return self._finish(
                    ScanFinding(
                        path=str(candidate.resolve()),
                        verdict=ScanVerdict.SKIPPED,
                        score=0,
                        reasons=(f"SHA-256 is allowed by the user ({label})",),
                        sha256=digest,
                        size_bytes=stat.st_size,
                        yara_status=self.yara.status,
                    )
                )

            known = self.known_hashes.get(digest.casefold())
            if known:
                score = 100
                reasons.append(f"Known signature match: {known.get('name', 'named threat')}")
            if _eicar_bytes() in content:
                score = 100
                reasons.append("EICAR antivirus test signature detected")

            yara_matches = self.yara.scan(content)
            for match in yara_matches:
                reasons.append(f"YARA-X {match.identifier}: {match.description}")

            double_extension = _double_extension(candidate.name)
            if double_extension:
                score += 25
                reasons.append(f"Executable uses a deceptive double extension ({double_extension})")

            if suffix in EXECUTABLE_EXTENSIONS:
                if self.native is not None:
                    signature = self.native.signature_status(str(candidate), f"scan:{digest}")
                else:
                    signature = SignatureStatus.UNKNOWN
                if signature == SignatureStatus.UNTRUSTED:
                    score += 30
                    reasons.append("Authenticode trust verification failed")
                elif signature == SignatureStatus.UNKNOWN:
                    score += 8
                    reasons.append("No trusted embedded Authenticode signature was confirmed")
                location_score, location_reason = _location_risk(candidate)
                score += location_score
                if location_reason:
                    reasons.append(location_reason)

            if content.startswith(b"MZ"):
                pe_score, pe_reasons = _inspect_pe(content, stat.st_size)
                score += pe_score
                reasons.extend(pe_reasons)

            if suffix in SCRIPT_EXTENSIONS or _looks_like_script(content):
                script_score, script_reasons = _inspect_script(content)
                score += script_score
                reasons.extend(script_reasons)

            amsi_result = "disabled"
            if self.amsi is not None:
                if stat.st_size <= MAX_CONTENT_INSPECTION_BYTES:
                    outcome = self.amsi.scan(content, str(candidate))
                    amsi_result = outcome.status
                    if outcome.status == "detected":
                        score = 100
                        reasons.append("The installed Windows AMSI provider detected malware")
                    elif outcome.status == "blocked_by_admin":
                        score = max(score, 75)
                        reasons.append("The installed Windows AMSI provider blocked this content by policy")
                else:
                    amsi_result = "skipped_size_limit"

            for match in yara_matches:
                if match.severity == "malicious":
                    score = 100
                elif match.severity in {"high", "suspicious"}:
                    score = max(score, 65)
                elif match.severity in {"medium", "low"}:
                    score = max(score, 25)

            score = min(score, 100)
            verdict = _verdict(score)
            if not reasons:
                reasons.append("No configured local or AMSI detection signal matched")
            finding = ScanFinding(
                path=str(candidate.resolve()),
                verdict=verdict,
                score=score,
                reasons=tuple(dict.fromkeys(reasons)),
                sha256=digest,
                size_bytes=stat.st_size,
                signature=signature,
                amsi_result=amsi_result,
                yara_status=self.yara.status,
                yara_matches=tuple(match.identifier for match in yara_matches),
            )
            return self._finish(finding)
        except (OSError, ValueError) as error:
            return self._finish(
                ScanFinding(
                    str(candidate),
                    ScanVerdict.ERROR,
                    0,
                    (f"{type(error).__name__}: {error}",),
                )
            )

    def scan_path(
        self,
        target: str | Path,
        cancel: threading.Event | None = None,
        progress: Callable[[int, int, str], None] | None = None,
        on_result: Callable[[ScanFinding], None] | None = None,
    ) -> list[ScanFinding]:
        candidate = Path(target)
        if candidate.is_file() or not candidate.exists():
            files = [candidate]
        else:
            files = list(_walk_files(candidate))
        total = len(files)
        results: list[ScanFinding] = []
        for index, file_path in enumerate(files, start=1):
            if cancel is not None and cancel.is_set():
                break
            if progress:
                progress(index - 1, total, str(file_path))
            finding = self.scan_file(file_path, cancel)
            results.append(finding)
            if on_result:
                on_result(finding)
        if progress:
            progress(len(results), total, "")
        return results

    def scan_profile(
        self,
        profile: ScanProfile | str,
        cancel: threading.Event | None = None,
        progress: Callable[[int, int, str], None] | None = None,
        on_result: Callable[[ScanFinding], None] | None = None,
    ) -> list[ScanFinding]:
        files: list[Path] = []
        seen: set[str] = set()
        for target in profile_targets(profile):
            candidates = [target] if target.is_file() else _walk_files(target)
            for candidate in candidates:
                key = str(candidate).casefold()
                if key not in seen:
                    seen.add(key)
                    files.append(candidate)
        total = len(files)
        results: list[ScanFinding] = []
        for index, file_path in enumerate(files, start=1):
            if cancel is not None and cancel.is_set():
                break
            if progress:
                progress(index - 1, total, str(file_path))
            finding = self.scan_file(file_path, cancel)
            results.append(finding)
            if on_result:
                on_result(finding)
        if progress:
            progress(len(results), total, "")
        return results

    def quarantine(self, finding: ScanFinding, reason: str | None = None) -> Path:
        if finding.verdict not in {ScanVerdict.SUSPICIOUS, ScanVerdict.MALICIOUS}:
            raise ValueError("Only suspicious or malicious findings can be quarantined")
        requested_source = Path(finding.path)
        if requested_source.is_symlink():
            raise ValueError("Symbolic links cannot be quarantined; scan the resolved file directly")
        source = requested_source.resolve(strict=True)
        if not source.is_file():
            raise ValueError("Only regular files can be quarantined")
        if finding.sha256:
            current_hash = _sha256_file(source)
            if current_hash.casefold() != finding.sha256.casefold():
                raise ValueError("File changed after it was scanned; scan it again before quarantine")
        destination_root = quarantine_root().resolve()
        destination_root.mkdir(parents=True, exist_ok=True)
        try:
            source.relative_to(destination_root)
        except ValueError:
            pass
        else:
            raise ValueError("File is already inside the quarantine directory")
        quarantine_id = uuid.uuid4().hex
        destination = destination_root / f"{quarantine_id}.quarantine"
        shutil.move(str(source), str(destination))
        metadata = {
            "id": quarantine_id,
            "original_path": str(source),
            "quarantine_path": str(destination),
            "sha256": finding.sha256,
            "reason": reason or "; ".join(finding.reasons),
            "created_at": utc_now(),
        }
        metadata_path = destination.with_suffix(".json")
        try:
            metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
            if self.database is not None:
                self.database.record_quarantine(
                    quarantine_id=metadata["id"],
                    original_path=metadata["original_path"],
                    quarantine_path=metadata["quarantine_path"],
                    sha256=metadata["sha256"],
                    reason=metadata["reason"],
                    created_at=metadata["created_at"],
                )
        except Exception:
            # Roll back the move if audit metadata cannot be committed.
            if destination.exists() and not source.exists():
                source.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(destination), str(source))
            metadata_path.unlink(missing_ok=True)
            raise
        return destination

    def allow_finding(self, finding: ScanFinding, label: str = "") -> None:
        if self.database is None:
            raise ValueError("Allow-listing requires a database")
        if not finding.sha256:
            raise ValueError("The finding has no SHA-256 digest")
        self.database.allow_hash(finding.sha256, label or Path(finding.path).name, utc_now())

    def restore_quarantine(
        self,
        quarantine_id: str,
        destination: str | Path | None = None,
    ) -> Path:
        if self.database is None:
            raise ValueError("Restoring quarantine requires a database")
        record = self.database.quarantine_by_id(quarantine_id)
        if record is None or record.get("restored_at"):
            raise ValueError("Quarantine record is missing or already restored")
        source = Path(str(record["quarantine_path"])).resolve(strict=True)
        quarantine = quarantine_root().resolve()
        try:
            source.relative_to(quarantine)
        except ValueError as error:
            raise ValueError("Quarantine record points outside the quarantine directory") from error
        if source.is_symlink() or not source.is_file():
            raise ValueError("Quarantined content is not a regular file")
        expected_hash = str(record.get("sha256") or "")
        if expected_hash and _sha256_file(source).casefold() != expected_hash.casefold():
            raise ValueError("Quarantined content failed its integrity check")
        target = Path(destination) if destination is not None else Path(str(record["original_path"]))
        target = target.expanduser().resolve()
        if target.exists():
            raise FileExistsError(f"Restore destination already exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(target))
        restored_at = utc_now()
        try:
            self.database.mark_quarantine_restored(quarantine_id, restored_at)
        except Exception:
            source.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(target), str(source))
            raise
        metadata_path = source.with_suffix(".json")
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["restored_at"] = restored_at
            metadata["restored_path"] = str(target)
            metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        except (OSError, ValueError, TypeError):
            pass
        return target

    def _finish(self, finding: ScanFinding) -> ScanFinding:
        if self.database is not None:
            self.database.record_scan(finding)
            if finding.verdict in {ScanVerdict.SUSPICIOUS, ScanVerdict.MALICIOUS}:
                severity = Severity.CRITICAL if finding.verdict == ScanVerdict.MALICIOUS else Severity.HIGH
                self.database.record_event(
                    SecurityEvent(
                        event_type="scan_detection",
                        severity=severity,
                        title=f"{finding.verdict.replace('_', ' ').title()}: {Path(finding.path).name}",
                        detail="; ".join(finding.reasons),
                        path=finding.path,
                    )
                )
        return finding


def _read_hash_and_content(
    path: Path, cancel: threading.Event | None
) -> tuple[str, bytes, bool]:
    digest = hashlib.sha256()
    content = bytearray()
    with path.open("rb") as handle:
        while True:
            if cancel is not None and cancel.is_set():
                return "", bytes(content), True
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            if len(content) < MAX_CONTENT_INSPECTION_BYTES:
                remaining = MAX_CONTENT_INSPECTION_BYTES - len(content)
                content.extend(block[:remaining])
    return digest.hexdigest(), bytes(content), False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _load_known_hashes() -> dict[str, dict[str, Any]]:
    path = Path(__file__).with_name("data") / "known_hashes.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return {str(key).casefold(): dict(value) for key, value in raw.items()}
    except (OSError, ValueError, TypeError):
        return {}


def _eicar_bytes() -> bytes:
    # Keep the inert test signature split so source checkouts do not trigger
    # simplistic literal scanners. Tests assemble the same standardized value.
    parts = (
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
        b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    return b"".join(parts)


def _double_extension(name: str) -> str:
    suffixes = [item.casefold() for item in Path(name).suffixes]
    if len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_EXTENSIONS and suffixes[-2] in LURE_EXTENSIONS:
        return "".join(suffixes[-2:])
    return ""


def _location_risk(path: Path) -> tuple[int, str]:
    lowered = str(path.resolve()).casefold().replace("/", "\\")
    temp_values = {os.environ.get("TEMP", ""), os.environ.get("TMP", "")}
    for value in temp_values:
        root = value.casefold().rstrip("\\/")
        if root and (lowered == root or lowered.startswith(f"{root}\\")):
            return 30, "Executable is stored in a temporary directory"
    profile = os.environ.get("USERPROFILE", "").casefold().rstrip("\\/")
    if profile and lowered.startswith(f"{profile}\\downloads\\"):
        return 18, "Executable is stored in Downloads"
    return 0, ""


def _inspect_script(content: bytes) -> tuple[int, list[str]]:
    text = content.decode("utf-8", errors="ignore")
    score = 0
    reasons: list[str] = []
    for pattern, weight, reason in SCRIPT_SIGNALS:
        if pattern.search(text):
            score += weight
            reasons.append(reason)
    return min(score, 80), reasons


def _looks_like_script(content: bytes) -> bool:
    prefix = content[:256].lstrip().lower()
    return prefix.startswith((b"#!", b"<script", b"<?xml"))


def _inspect_pe(content: bytes, file_size: int) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = 0
    if len(content) < 64:
        return 25, ["Truncated DOS/PE header"]
    pe_offset = int.from_bytes(content[0x3C:0x40], "little")
    if pe_offset < 64 or pe_offset + 24 > len(content) or content[pe_offset : pe_offset + 4] != b"PE\0\0":
        return 25, ["Malformed PE header"]
    section_count = int.from_bytes(content[pe_offset + 6 : pe_offset + 8], "little")
    timestamp = int.from_bytes(content[pe_offset + 8 : pe_offset + 12], "little")
    if section_count == 0 or section_count > 32:
        score += 20
        reasons.append(f"Unusual PE section count ({section_count})")
    if timestamp == 0:
        score += 5
        reasons.append("PE build timestamp is zero")
    sample = content[: min(len(content), 2 * 1024 * 1024)]
    entropy = _entropy(sample)
    if len(sample) >= 4096 and entropy >= 7.65:
        score += 18
        reasons.append(f"High file entropy may indicate packing or encryption ({entropy:.2f})")
    if file_size < 512:
        score += 10
        reasons.append("PE file is unusually small")
    return score, reasons


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _verdict(score: int) -> ScanVerdict:
    if score >= 85:
        return ScanVerdict.MALICIOUS
    if score >= 45:
        return ScanVerdict.SUSPICIOUS
    if score >= 15:
        return ScanVerdict.LOW_RISK
    return ScanVerdict.CLEAN


def _walk_files(root: Path) -> Iterable[Path]:
    quarantine = quarantine_root().resolve()
    for current_root, directories, filenames in os.walk(root, followlinks=False):
        current = Path(current_root)
        filtered: list[str] = []
        for directory in directories:
            candidate = current / directory
            try:
                if candidate.resolve() == quarantine or candidate.is_symlink():
                    continue
            except OSError:
                continue
            filtered.append(directory)
        directories[:] = filtered
        for filename in filenames:
            yield current / filename
