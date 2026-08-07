"""OpenGuard UI and diagnostic CLI entry point."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile
from pathlib import Path
from typing import Any

from .config import APP_NAME, DEFAULT_UPDATE_MANIFEST_URL, VERSION, data_root, database_path
from .models import ScanProfile, ScanVerdict, json_ready, utc_now
from .monitor import SystemMonitor
from .scanner import Scanner
from .service_control import service_action
from .storage import Database
from .telemetry import EtwProcessEventSource, WfpNetEventMonitor
from .updates import SecurityContentUpdater
from .windows_api import AmsiScanner, IS_WINDOWS, WindowsNative
from .yara_engine import YaraEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="OpenGuard",
        description="Open-source Windows activity monitor and local security scanner",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    commands = parser.add_subparsers(dest="command")

    snapshot = commands.add_parser("snapshot", help="Collect one process/network snapshot as JSON")
    snapshot.add_argument("--pretty", action="store_true", help="Indent JSON output")
    snapshot.add_argument("--no-persist", action="store_true", help="Do not update executable baseline/history")

    scan = commands.add_parser("scan", help="Scan a file or folder")
    scan.add_argument("target", help="File or folder path")
    scan.add_argument("--pretty", action="store_true", help="Indent JSON output")
    scan.add_argument("--no-amsi", action="store_true", help="Use local OpenGuard rules only")

    scan_profile = commands.add_parser("scan-profile", help="Run a named scan profile")
    scan_profile.add_argument("profile", choices=[item.value for item in ScanProfile])
    scan_profile.add_argument("--pretty", action="store_true")
    scan_profile.add_argument("--no-amsi", action="store_true")

    quarantine = commands.add_parser("quarantine", help="List or restore quarantined files")
    quarantine.add_argument("action", choices=["list", "restore"])
    quarantine.add_argument("id", nargs="?")
    quarantine.add_argument("--destination")
    quarantine.add_argument("--pretty", action="store_true")

    allow = commands.add_parser("allow", help="Manage the user SHA-256 allow-list")
    allow.add_argument("action", choices=["list", "add", "remove"])
    allow.add_argument("sha256", nargs="?")
    allow.add_argument("--label", default="")
    allow.add_argument("--pretty", action="store_true")

    exclude = commands.add_parser("exclude", help="Manage user path exclusions")
    exclude.add_argument("action", choices=["list", "add", "remove"])
    exclude.add_argument("path", nargs="?")
    exclude.add_argument("--no-recursive", action="store_true")
    exclude.add_argument("--pretty", action="store_true")

    update = commands.add_parser("update", help="Install, inspect, or roll back signed security content")
    update.add_argument("action", choices=["status", "install", "rollback"])
    update.add_argument("manifest_url", nargs="?")
    update.add_argument("--pretty", action="store_true")

    service = commands.add_parser("service", help="Manage the background Windows service")
    service.add_argument("action", choices=["status", "install", "start", "stop", "uninstall"])
    service.add_argument("--binary")
    service.add_argument("--pretty", action="store_true")

    doctor = commands.add_parser("doctor", help="Report runtime and Windows API health as JSON")
    doctor.add_argument("--pretty", action="store_true", help="Indent JSON output")

    commands.add_parser("ui", help="Launch the desktop dashboard (default)")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if not IS_WINDOWS:
        print(json.dumps({"error": "OpenGuard currently requires Windows"}), file=sys.stderr)
        return 1
    try:
        database = Database()
        native = WindowsNative()
    except Exception as error:
        print(json.dumps({"error": f"Startup failed: {type(error).__name__}: {error}"}), file=sys.stderr)
        return 1

    if arguments.command in (None, "ui"):
        from .ui import run_ui

        return run_ui(database, native)
    if arguments.command == "snapshot":
        return _snapshot_command(database, native, arguments.pretty, not arguments.no_persist)
    if arguments.command == "scan":
        return _scan_command(database, native, arguments.target, arguments.pretty, not arguments.no_amsi)
    if arguments.command == "scan-profile":
        return _scan_profile_command(
            database, native, arguments.profile, arguments.pretty, not arguments.no_amsi
        )
    if arguments.command == "quarantine":
        return _quarantine_command(database, native, arguments)
    if arguments.command == "allow":
        return _allow_command(database, arguments)
    if arguments.command == "exclude":
        return _exclude_command(database, arguments)
    if arguments.command == "update":
        return _update_command(arguments)
    if arguments.command == "service":
        return _service_command(arguments)
    if arguments.command == "doctor":
        return _doctor_command(database, native, arguments.pretty)
    return 1


def _snapshot_command(database: Database, native: WindowsNative, pretty: bool, persist: bool) -> int:
    monitor = SystemMonitor(native, database)
    try:
        snapshot = monitor.collect_snapshot(persist=persist)
        payload = {
            "application": APP_NAME,
            "version": VERSION,
            "summary": {
                "process_count": len(snapshot.processes),
                "endpoint_count": len(snapshot.endpoints),
                "new_executable_count": sum(item.is_new for item in snapshot.processes),
                "elevated": snapshot.elevated,
            },
            "snapshot": snapshot,
        }
        _print_json(payload, pretty)
        return 0
    except Exception as error:
        _print_json({"error": f"{type(error).__name__}: {error}"}, pretty)
        return 1
    finally:
        monitor.stop(timeout=0.1)


def _scan_command(
    database: Database,
    native: WindowsNative,
    target: str,
    pretty: bool,
    amsi_enabled: bool,
) -> int:
    scanner = Scanner(database, native, amsi_enabled=amsi_enabled)
    try:
        findings = scanner.scan_path(target)
        counts = {verdict.value: 0 for verdict in ScanVerdict}
        for finding in findings:
            counts[str(finding.verdict)] += 1
        payload = {
            "application": APP_NAME,
            "version": VERSION,
            "target": str(Path(target)),
            "summary": {"files": len(findings), "verdicts": counts},
            "findings": findings,
        }
        _print_json(payload, pretty)
        if any(item.verdict in {ScanVerdict.SUSPICIOUS, ScanVerdict.MALICIOUS} for item in findings):
            return 2
        if any(item.verdict == ScanVerdict.ERROR for item in findings):
            return 1
        return 0
    finally:
        scanner.close()


def _scan_profile_command(
    database: Database,
    native: WindowsNative,
    profile: str,
    pretty: bool,
    amsi_enabled: bool,
) -> int:
    scanner = Scanner(database, native, amsi_enabled=amsi_enabled)
    try:
        findings = scanner.scan_profile(profile)
        return _print_findings(findings, f"profile:{profile}", pretty)
    finally:
        scanner.close()


def _print_findings(findings: list[Any], target: str, pretty: bool) -> int:
    counts = {verdict.value: 0 for verdict in ScanVerdict}
    for finding in findings:
        counts[str(finding.verdict)] += 1
    _print_json(
        {
            "application": APP_NAME,
            "version": VERSION,
            "target": target,
            "summary": {"files": len(findings), "verdicts": counts},
            "findings": findings,
        },
        pretty,
    )
    if any(item.verdict in {ScanVerdict.SUSPICIOUS, ScanVerdict.MALICIOUS} for item in findings):
        return 2
    return 1 if any(item.verdict == ScanVerdict.ERROR for item in findings) else 0


def _quarantine_command(database: Database, native: WindowsNative, arguments: Any) -> int:
    if arguments.action == "list":
        _print_json({"quarantines": database.quarantines()}, arguments.pretty)
        return 0
    if not arguments.id:
        raise ValueError("quarantine restore requires an id")
    scanner = Scanner(database, native, amsi_enabled=False)
    try:
        restored = scanner.restore_quarantine(arguments.id, arguments.destination)
        _print_json({"restored": str(restored), "id": arguments.id}, arguments.pretty)
        return 0
    finally:
        scanner.close()


def _allow_command(database: Database, arguments: Any) -> int:
    if arguments.action == "list":
        _print_json({"allowed_hashes": database.allowed_hashes()}, arguments.pretty)
    elif arguments.action == "add":
        if not arguments.sha256:
            raise ValueError("allow add requires a SHA-256 digest")
        database.allow_hash(arguments.sha256, arguments.label, utc_now())
        _print_json({"added": arguments.sha256.casefold()}, arguments.pretty)
    else:
        if not arguments.sha256:
            raise ValueError("allow remove requires a SHA-256 digest")
        _print_json({"removed": database.remove_allowed_hash(arguments.sha256)}, arguments.pretty)
    return 0


def _exclude_command(database: Database, arguments: Any) -> int:
    if arguments.action == "list":
        _print_json({"exclusions": database.exclusions()}, arguments.pretty)
    elif arguments.action == "add":
        if not arguments.path:
            raise ValueError("exclude add requires a path")
        database.add_exclusion(arguments.path, not arguments.no_recursive, utc_now())
        _print_json({"added": str(Path(arguments.path).expanduser().resolve())}, arguments.pretty)
    else:
        if not arguments.path:
            raise ValueError("exclude remove requires a path")
        _print_json({"removed": database.remove_exclusion(arguments.path)}, arguments.pretty)
    return 0


def _update_command(arguments: Any) -> int:
    updater = SecurityContentUpdater()
    if arguments.action == "status":
        result: Any = updater.state()
    elif arguments.action == "rollback":
        result = {"active_version": updater.rollback()}
    else:
        result = {
            "active_version": updater.fetch_and_install(
                arguments.manifest_url or DEFAULT_UPDATE_MANIFEST_URL
            )
        }
    _print_json(result, arguments.pretty)
    return 0


def _service_command(arguments: Any) -> int:
    result = service_action(arguments.action, arguments.binary)
    _print_json(result, arguments.pretty)
    return 0 if result["success"] else 1


def _doctor_command(database: Database, native: WindowsNative, pretty: bool) -> int:
    checks: dict[str, Any] = {
        "application": APP_NAME,
        "version": VERSION,
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "frozen": bool(getattr(sys, "frozen", False)),
        "data_root": str(data_root()),
        "database": str(database_path()),
        "elevated": native.is_elevated(),
    }
    ok = True
    try:
        data_root().mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix="doctor-", dir=data_root(), delete=True):
            pass
        checks["data_writable"] = True
    except OSError as error:
        checks["data_writable"] = False
        checks["data_error"] = str(error)
        ok = False
    try:
        processes = native.processes(verify_signatures=False)
        checks["process_api"] = True
        checks["process_count"] = len(processes)
        checks["endpoint_count"] = len(native.endpoints({item.pid: item for item in processes}))
    except Exception as error:
        checks["process_api"] = False
        checks["native_error"] = f"{type(error).__name__}: {error}"
        ok = False
    amsi = AmsiScanner()
    checks["amsi_available"] = amsi.available
    amsi.close()
    yara = YaraEngine()
    checks["yara_x"] = {"status": yara.status, "error": yara.error}
    etw = EtwProcessEventSource()
    checks["etw"] = {"available": etw.start(lambda _event: None), "status": etw.status, "detail": etw.detail}
    etw.stop(timeout=1)
    wfp = WfpNetEventMonitor()
    checks["wfp"] = {"subscribed": wfp.start(), "status": wfp.status, "detail": wfp.detail}
    wfp.stop()
    checks["security_content"] = SecurityContentUpdater().state()
    checks["status"] = "healthy" if ok else "degraded"
    _print_json(checks, pretty)
    return 0 if ok else 1


def _print_json(value: Any, pretty: bool) -> None:
    print(
        json.dumps(
            json_ready(value),
            indent=2 if pretty else None,
            ensure_ascii=False,
            sort_keys=pretty,
        )
    )
