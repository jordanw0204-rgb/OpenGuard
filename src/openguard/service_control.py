"""Explicit, elevation-aware Windows service management commands."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

from .config import data_root
from .service import SERVICE_NAME


def default_service_binary() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).with_name("OpenGuardService.exe")
    return Path(__file__).resolve().parents[2] / "dist" / "OpenGuard" / "OpenGuardService.exe"


def service_action(action: str, binary: str | Path | None = None) -> dict[str, Any]:
    selected = action.casefold()
    if selected == "status":
        result = _sc("query", SERVICE_NAME, check=False)
        return _result(selected, result)
    if selected == "install":
        _require_elevation()
        executable = Path(binary) if binary is not None else default_service_binary()
        executable = executable.expanduser().resolve(strict=True)
        image_path = f'"{executable}" --service --data-dir "{data_root().resolve()}"'
        result = _sc(
            "create",
            SERVICE_NAME,
            "binPath=",
            image_path,
            "start=",
            "auto",
            "DisplayName=",
            "OpenGuard Monitor",
            check=True,
        )
        _sc(
            "description",
            SERVICE_NAME,
            "OpenGuard background process, endpoint, and security-content monitor",
            check=True,
        )
        _sc("failure", SERVICE_NAME, "reset=", "86400", "actions=", "restart/5000", check=True)
        return _result(selected, result)
    if selected in {"start", "stop", "uninstall"}:
        _require_elevation()
        command = "delete" if selected == "uninstall" else selected
        result = _sc(command, SERVICE_NAME, check=selected != "stop")
        return _result(selected, result)
    raise ValueError(f"Unsupported service action: {action}")


def is_elevated() -> bool:
    import ctypes

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def _require_elevation() -> None:
    if not is_elevated():
        raise PermissionError("This service operation requires an Administrator terminal")


def _sc(*arguments: str, check: bool) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["sc.exe", *arguments], capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if check and result.returncode != 0:
        detail = (result.stdout + result.stderr).strip()
        raise RuntimeError(f"sc.exe failed ({result.returncode}): {detail}")
    return result


def _result(action: str, result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return {
        "action": action,
        "service": SERVICE_NAME,
        "success": result.returncode == 0,
        "exit_code": result.returncode,
        "output": (result.stdout + result.stderr).strip(),
    }
