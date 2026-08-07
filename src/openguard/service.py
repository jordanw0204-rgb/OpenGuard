"""Windows Service Control Manager host for background OpenGuard monitoring."""

from __future__ import annotations

import ctypes
import logging
import os
import threading
from ctypes import wintypes
from pathlib import Path

from .config import log_root
from .models import SecurityEvent, Severity
from .monitor import SystemMonitor
from .storage import Database
from .windows_api import WindowsNative

SERVICE_NAME = "OpenGuardMonitor"
SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4
SERVICE_ACCEPT_STOP = 1
SERVICE_ACCEPT_SHUTDOWN = 4
SERVICE_CONTROL_STOP = 1
SERVICE_CONTROL_SHUTDOWN = 5
SERVICE_WIN32_OWN_PROCESS = 0x10


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
HANDLER_EX = ctypes.WINFUNCTYPE(
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID
)


class SERVICE_TABLE_ENTRY(ctypes.Structure):
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", SERVICE_MAIN)]


class OpenGuardServiceHost:
    def __init__(self) -> None:
        self.advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self.stop_event = threading.Event()
        self.status_handle = wintypes.HANDLE()
        self.status = SERVICE_STATUS()
        self.monitor: SystemMonitor | None = None
        self._service_main_callback = SERVICE_MAIN(self._service_main)
        self._handler_callback = HANDLER_EX(self._handler)
        self._configure()

    def _configure(self) -> None:
        self.advapi32.StartServiceCtrlDispatcherW.argtypes = [
            ctypes.POINTER(SERVICE_TABLE_ENTRY)
        ]
        self.advapi32.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
        self.advapi32.RegisterServiceCtrlHandlerExW.argtypes = [
            wintypes.LPCWSTR,
            HANDLER_EX,
            wintypes.LPVOID,
        ]
        self.advapi32.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
        self.advapi32.SetServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(SERVICE_STATUS)]
        self.advapi32.SetServiceStatus.restype = wintypes.BOOL

    def run(self) -> None:
        table = (SERVICE_TABLE_ENTRY * 2)()
        table[0] = SERVICE_TABLE_ENTRY(SERVICE_NAME, self._service_main_callback)
        table[1] = SERVICE_TABLE_ENTRY(None, SERVICE_MAIN())
        if not self.advapi32.StartServiceCtrlDispatcherW(table):
            raise ctypes.WinError(ctypes.get_last_error())

    def _service_main(self, _argc: int, _argv: ctypes.POINTER(wintypes.LPWSTR)) -> None:
        self.status_handle = self.advapi32.RegisterServiceCtrlHandlerExW(
            SERVICE_NAME, self._handler_callback, None
        )
        if not self.status_handle:
            return
        self._set_status(SERVICE_START_PENDING, wait_hint=20_000)
        logger = _service_logger()
        try:
            database = Database()
            native = WindowsNative()

            def on_error(error: Exception) -> None:
                logger.exception("Background monitor failed", exc_info=error)
                database.record_event(
                    SecurityEvent(
                        event_type="service_error",
                        severity=Severity.HIGH,
                        title="OpenGuard background monitor error",
                        detail=f"{type(error).__name__}: {error}",
                    )
                )

            self.monitor = SystemMonitor(native, database, on_error=on_error)
            self.monitor.start()
            database.set_metadata("service_etw_status", self.monitor.process_events.status)
            database.set_metadata("service_etw_detail", self.monitor.process_events.detail)
            database.set_metadata("service_wfp_status", self.monitor.wfp_monitor.status)
            database.set_metadata("service_wfp_detail", self.monitor.wfp_monitor.detail)
            self._set_status(SERVICE_RUNNING)
            logger.info(
                "OpenGuard Monitor service started; ETW=%s; WFP=%s",
                self.monitor.process_events.status,
                self.monitor.wfp_monitor.status,
            )
            self.stop_event.wait()
            self._set_status(SERVICE_STOP_PENDING, wait_hint=15_000)
            self.monitor.stop(timeout=10)
            logger.info("OpenGuard Monitor service stopped")
            self._set_status(SERVICE_STOPPED)
        except Exception as error:
            logger.exception("OpenGuard Monitor service failed")
            self._set_status(SERVICE_STOPPED, win32_exit=1)

    def _handler(self, control: int, _event_type: int, _event: int, _context: int) -> int:
        if control in {SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN}:
            self._set_status(SERVICE_STOP_PENDING, wait_hint=15_000)
            self.stop_event.set()
        return 0

    def _set_status(self, state: int, *, wait_hint: int = 0, win32_exit: int = 0) -> None:
        self.status.dwServiceType = SERVICE_WIN32_OWN_PROCESS
        self.status.dwCurrentState = state
        self.status.dwControlsAccepted = (
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN if state == SERVICE_RUNNING else 0
        )
        self.status.dwWin32ExitCode = win32_exit
        self.status.dwServiceSpecificExitCode = 0
        self.status.dwCheckPoint = 0
        self.status.dwWaitHint = wait_hint
        if self.status_handle:
            self.advapi32.SetServiceStatus(self.status_handle, ctypes.byref(self.status))


def run_service(data_dir: str | Path | None = None) -> None:
    if data_dir is not None:
        os.environ["OPENGUARD_DATA_DIR"] = str(Path(data_dir).expanduser().resolve())
    OpenGuardServiceHost().run()


def _service_logger() -> logging.Logger:
    root = log_root()
    root.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("openguard.service")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.FileHandler(root / "service.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    return logger
