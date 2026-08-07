"""Conservative, explainable process risk scoring."""

from __future__ import annotations

import os
from pathlib import Path

from .models import RiskAssessment, Severity, SignatureStatus

DUAL_USE_NAMES = {
    "certutil.exe",
    "cmd.exe",
    "cscript.exe",
    "mshta.exe",
    "powershell.exe",
    "pwsh.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wscript.exe",
}


def severity_for_score(score: int) -> Severity:
    if score >= 90:
        return Severity.CRITICAL
    if score >= 65:
        return Severity.HIGH
    if score >= 35:
        return Severity.MEDIUM
    if score >= 15:
        return Severity.LOW
    return Severity.INFO


def assess_process(name: str, path: str, signature: SignatureStatus, accessible: bool = True) -> RiskAssessment:
    score = 0
    reasons: list[str] = []
    lowered_name = name.casefold()
    lowered_path = path.casefold().replace("/", "\\")

    if not accessible or not path:
        reasons.append("Windows limited access to executable details")
        return RiskAssessment(5, Severity.INFO, tuple(reasons))

    user_profile = os.environ.get("USERPROFILE", "").casefold()
    temp_roots = {
        os.environ.get("TEMP", "").casefold(),
        os.environ.get("TMP", "").casefold(),
    }
    in_temp = any(root and _is_beneath(lowered_path, root) for root in temp_roots)
    in_downloads = bool(user_profile and _is_beneath(lowered_path, f"{user_profile}\\downloads"))
    trusted_roots = _trusted_roots()
    in_trusted_root = any(_is_beneath(lowered_path, root) for root in trusted_roots if root)

    if in_temp:
        score += 35
        reasons.append("Executable is running from a temporary directory")
    elif in_downloads:
        score += 18
        reasons.append("Executable is running directly from Downloads")
    elif user_profile and _is_beneath(lowered_path, user_profile):
        score += 8
        reasons.append("Executable is running from a user-writable profile directory")

    if signature == SignatureStatus.UNTRUSTED:
        score += 25
        reasons.append("Authenticode trust verification failed or no trusted signature was found")
    elif signature == SignatureStatus.UNKNOWN:
        score += 5
        reasons.append("Authenticode trust could not be determined")

    if lowered_name in DUAL_USE_NAMES:
        score += 7
        reasons.append("Process is a legitimate dual-use execution tool")
        if in_temp or in_downloads:
            score += 13
            reasons.append("Dual-use tool was launched from a higher-risk location")

    actual_name = Path(lowered_path).name
    if actual_name and lowered_name and actual_name != lowered_name:
        score += 25
        reasons.append("Reported process name does not match the executable filename")

    if not in_trusted_root and signature == SignatureStatus.UNTRUSTED:
        score += 10
        reasons.append("Unsigned executable is outside Windows and Program Files")

    score = min(score, 100)
    return RiskAssessment(score, severity_for_score(score), tuple(reasons))


def _trusted_roots() -> tuple[str, ...]:
    candidates = (
        os.environ.get("WINDIR", r"C:\Windows"),
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    )
    return tuple(item.casefold().rstrip("\\/") for item in candidates if item)


def _is_beneath(candidate: str, root: str) -> bool:
    clean_root = root.casefold().rstrip("\\/")
    return candidate == clean_root or candidate.startswith(f"{clean_root}\\")
