"""Immutable domain models shared by native, engine, CLI, and UI layers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any


class SignatureStatus(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanVerdict(StrEnum):
    CLEAN = "clean"
    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    SKIPPED = "skipped"
    ERROR = "error"
    CANCELLED = "cancelled"


class ScanProfile(StrEnum):
    QUICK = "quick"
    FULL = "full"
    STARTUP = "startup"
    DOWNLOADS = "downloads"


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: int
    severity: Severity
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ProcessRecord:
    pid: int
    parent_pid: int
    name: str
    path: str = ""
    thread_count: int = 0
    working_set_bytes: int = 0
    cpu_percent: float = 0.0
    signature: SignatureStatus = SignatureStatus.UNKNOWN
    accessible: bool = True
    identity: str = ""
    is_new: bool = False
    risk: RiskAssessment = RiskAssessment(0, Severity.INFO)


@dataclass(frozen=True, slots=True)
class NetworkEndpoint:
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    pid: int
    process_name: str = ""
    process_path: str = ""
    remote_hostname: str = ""
    reputation: str = "unknown"
    reputation_reason: str = ""


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    event_type: str
    severity: Severity
    title: str
    detail: str
    process_id: int | None = None
    path: str = ""
    created_at: str = ""
    event_id: int | None = None
    resolved: bool = False

    def __post_init__(self) -> None:
        if not self.created_at:
            object.__setattr__(self, "created_at", utc_now())


@dataclass(frozen=True, slots=True)
class ScanFinding:
    path: str
    verdict: ScanVerdict
    score: int
    reasons: tuple[str, ...]
    sha256: str = ""
    size_bytes: int = 0
    signature: SignatureStatus = SignatureStatus.UNKNOWN
    amsi_result: str = "not_scanned"
    yara_status: str = "not_scanned"
    yara_matches: tuple[str, ...] = ()
    scanned_at: str = ""

    def __post_init__(self) -> None:
        if not self.scanned_at:
            object.__setattr__(self, "scanned_at", utc_now())


@dataclass(frozen=True, slots=True)
class SystemSnapshot:
    processes: tuple[ProcessRecord, ...]
    endpoints: tuple[NetworkEndpoint, ...]
    captured_at: str
    elevated: bool
    coverage_notes: tuple[str, ...] = ()


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def executable_identity(path: str) -> str:
    """Create a cheap identity that changes when the file is replaced.

    Full SHA-256 is reserved for explicit scans so process monitoring cannot
    spend minutes hashing every executable during startup.
    """
    if not path:
        return ""
    try:
        candidate = Path(path)
        stat = candidate.stat()
        normalized = os_path_key(candidate)
        return f"{normalized}|{stat.st_size}|{stat.st_mtime_ns}"
    except (OSError, ValueError):
        return os_path_key(Path(path))


def os_path_key(path: Path) -> str:
    return str(path).replace("/", "\\").casefold()


def json_ready(value: Any) -> Any:
    """Convert nested dataclasses/enums/paths to JSON-safe values."""
    if is_dataclass(value):
        return json_ready(asdict(value))
    if isinstance(value, StrEnum):
        return str(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_ready(item) for item in value]
    return value
