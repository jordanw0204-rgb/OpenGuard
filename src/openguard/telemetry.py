"""Native ETW process events and Windows Filtering Platform capability telemetry."""

from __future__ import annotations

import ctypes
import json
import os
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True, slots=True)
class ProcessEvent:
    event_type: str
    pid: int
    event_id: int


class EtwProcessEventSource:
    def __init__(self, helper: Path | None = None) -> None:
        self.helper = helper or _etw_helper_path()
        self.status = "stopped"
        self.detail = ""
        self._process: subprocess.Popen[str] | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._on_event: Callable[[ProcessEvent], None] | None = None
        self._stop_handle = ctypes.c_void_p()
        self._stop_event_name = ""

    @property
    def running(self) -> bool:
        return bool(self._process and self._process.poll() is None and self.status == "running")

    def start(self, on_event: Callable[[ProcessEvent], None]) -> bool:
        if self.running:
            return True
        if not self.helper.is_file():
            self.status = "unavailable"
            self.detail = f"ETW helper is missing: {self.helper}"
            return False
        self._stop.clear()
        self._ready.clear()
        self._on_event = on_event
        self._stop_event_name = f"Local\\OpenGuardETWStop-{os.getpid()}-{id(self)}"
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
        kernel32.CreateEventW.restype = ctypes.c_void_p
        self._stop_handle = ctypes.c_void_p(
            kernel32.CreateEventW(None, True, False, self._stop_event_name)
        )
        creation_flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            self._process = subprocess.Popen(
                [str(self.helper), "--stop-event", self._stop_event_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=creation_flags,
            )
        except OSError as error:
            self.status = "unavailable"
            self.detail = f"{type(error).__name__}: {error}"
            return False
        self.status = "starting"
        self._thread = threading.Thread(target=self._read, name="OpenGuardETWReader", daemon=True)
        self._thread.start()
        self._ready.wait(3.0)
        if self._process.poll() is not None and self.status != "running":
            self.status = "unavailable"
        return self.running

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        process = self._process
        if process and process.poll() is None:
            try:
                if self._stop_handle:
                    ctypes.windll.kernel32.SetEvent(self._stop_handle)
                else:
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                process.wait(timeout=timeout)
            except (OSError, subprocess.TimeoutExpired):
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
        thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=1)
        if self.status == "running":
            self.status = "stopped"
        if self._stop_handle:
            ctypes.windll.kernel32.CloseHandle(self._stop_handle)
            self._stop_handle = ctypes.c_void_p()

    def _read(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            self._ready.set()
            return
        for line in process.stdout:
            try:
                value = json.loads(line)
            except ValueError:
                continue
            status = str(value.get("status", ""))
            if status:
                self.status = status
                self.detail = json.dumps(value, sort_keys=True)
                self._ready.set()
                continue
            kind = str(value.get("type", ""))
            if kind in {"start", "stop"} and self._on_event and not self._stop.is_set():
                self._on_event(ProcessEvent(kind, int(value.get("pid", 0)), int(value.get("event_id", 0))))
        self._ready.set()
        if not self._stop.is_set() and self.status != "unavailable":
            self.status = "unavailable"
            self.detail = f"ETW helper exited with {process.poll()}"


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class FWPM_NET_EVENT_SUBSCRIPTION0(ctypes.Structure):
    _fields_ = [
        ("enumTemplate", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("sessionKey", GUID),
    ]


class WfpNetEventMonitor:
    """Subscribe read-only to WFP net-event notifications; never installs filters."""

    def __init__(self) -> None:
        self.status = "stopped"
        self.detail = ""
        self.event_count = 0
        self._engine = ctypes.c_void_p()
        self._subscription = ctypes.c_void_p()
        self._callback = None
        self._library = None

    def start(self) -> bool:
        if os.name != "nt":
            self.status = "unavailable"
            self.detail = "WFP is available only on Windows"
            return False
        try:
            library = ctypes.WinDLL("fwpuclnt", use_last_error=True)
            library.FwpmEngineOpen0.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            library.FwpmEngineOpen0.restype = ctypes.c_uint32
            library.FwpmEngineClose0.argtypes = [ctypes.c_void_p]
            library.FwpmEngineClose0.restype = ctypes.c_uint32
            result = int(library.FwpmEngineOpen0(None, 10, None, None, ctypes.byref(self._engine)))
            if result != 0:
                self.status = "unavailable"
                self.detail = f"FwpmEngineOpen0 returned 0x{result:08x}"
                return False
            callback_type = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)

            def on_event(_context: int, _event: int) -> None:
                self.event_count += 1

            self._callback = callback_type(on_event)
            library.FwpmNetEventSubscribe0.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(FWPM_NET_EVENT_SUBSCRIPTION0),
                callback_type,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            library.FwpmNetEventSubscribe0.restype = ctypes.c_uint32
            library.FwpmNetEventUnsubscribe0.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            library.FwpmNetEventUnsubscribe0.restype = ctypes.c_uint32
            subscription = FWPM_NET_EVENT_SUBSCRIPTION0()
            result = int(
                library.FwpmNetEventSubscribe0(
                    self._engine,
                    ctypes.byref(subscription),
                    self._callback,
                    None,
                    ctypes.byref(self._subscription),
                )
            )
            self._library = library
            if result != 0:
                self.status = "engine_only"
                self.detail = f"Net-event subscription requires additional access (0x{result:08x})"
                return False
            self.status = "subscribed"
            self.detail = "Read-only WFP net-event subscription active; no filters installed"
            return True
        except OSError as error:
            self.status = "unavailable"
            self.detail = f"{type(error).__name__}: {error}"
            return False

    def stop(self) -> None:
        if self._library is not None and self._subscription:
            self._library.FwpmNetEventUnsubscribe0(self._engine, self._subscription)
        if self._library is not None and self._engine:
            self._library.FwpmEngineClose0(self._engine)
        self._subscription = ctypes.c_void_p()
        self._engine = ctypes.c_void_p()
        if self.status == "subscribed":
            self.status = "stopped"


def _etw_helper_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).with_name("OpenGuardETW.exe")
    return Path(__file__).resolve().parents[2] / "build" / "native" / "OpenGuardETW.exe"
