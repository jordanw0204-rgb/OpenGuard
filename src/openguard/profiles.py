"""Deterministic target resolution for named scan profiles."""

from __future__ import annotations

import ctypes
import os
import re
from pathlib import Path
from typing import Mapping

from .models import ScanProfile


def profile_targets(
    profile: ScanProfile | str,
    *,
    environ: Mapping[str, str] | None = None,
    drive_roots: tuple[Path, ...] | None = None,
) -> tuple[Path, ...]:
    selected = ScanProfile(profile)
    values = environ if environ is not None else os.environ
    user = Path(values.get("USERPROFILE", str(Path.home())))
    downloads = user / "Downloads"
    startup = _startup_targets(values, include_registry=environ is None)
    if selected == ScanProfile.DOWNLOADS:
        candidates = [downloads]
    elif selected == ScanProfile.STARTUP:
        candidates = list(startup)
    elif selected == ScanProfile.QUICK:
        candidates = [downloads, user / "Desktop"] + list(startup)
    else:
        candidates = list(drive_roots if drive_roots is not None else fixed_drive_roots())
    return _existing_unique(candidates)


def fixed_drive_roots() -> tuple[Path, ...]:
    if os.name != "nt":
        return (Path("/"),)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_strings = kernel32.GetLogicalDriveStringsW
    get_strings.argtypes = [ctypes.c_uint32, ctypes.c_wchar_p]
    get_strings.restype = ctypes.c_uint32
    required = get_strings(0, None)
    buffer = ctypes.create_unicode_buffer(required + 1)
    get_strings(len(buffer), buffer)
    get_type = kernel32.GetDriveTypeW
    get_type.argtypes = [ctypes.c_wchar_p]
    get_type.restype = ctypes.c_uint32
    return tuple(Path(item) for item in buffer[:required].split("\0") if item and get_type(item) == 3)


def _startup_targets(
    environ: Mapping[str, str], *, include_registry: bool = True
) -> tuple[Path, ...]:
    candidates: list[Path] = []
    appdata = environ.get("APPDATA")
    programdata = environ.get("PROGRAMDATA")
    if appdata:
        candidates.append(
            Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        )
    if programdata:
        candidates.append(
            Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        )
    if include_registry:
        candidates.extend(_registry_run_targets())
    return _existing_unique(candidates)


def _registry_run_targets() -> tuple[Path, ...]:
    if os.name != "nt":
        return ()
    import winreg

    targets: list[Path] = []
    locations = (
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    )
    for hive, key_name in locations:
        try:
            with winreg.OpenKey(hive, key_name) as key:
                for index in range(winreg.QueryInfoKey(key)[1]):
                    _name, command, _kind = winreg.EnumValue(key, index)
                    target = _command_target(str(command))
                    if target is not None:
                        targets.append(target)
        except OSError:
            continue
    return tuple(targets)


def _command_target(command: str) -> Path | None:
    expanded = os.path.expandvars(command.strip())
    match = re.match(r'^"([^"]+)"|^([^\s]+)', expanded)
    if not match:
        return None
    candidate = Path(match.group(1) or match.group(2))
    return candidate if candidate.exists() else None


def _existing_unique(candidates: list[Path] | tuple[Path, ...]) -> tuple[Path, ...]:
    result: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        key = str(resolved).casefold()
        if resolved.exists() and key not in seen:
            seen.add(key)
            result.append(resolved)
    return tuple(result)
