"""Small, audited ctypes boundary around supported Windows desktop APIs."""

from __future__ import annotations

import ctypes
import os
import socket
import struct
import sys
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from .models import NetworkEndpoint, ProcessRecord, SignatureStatus, executable_identity
from .risk import assess_process

IS_WINDOWS = sys.platform == "win32"

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_INSUFFICIENT_BUFFER = 122
AF_INET = 2
AF_INET6 = 23
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1

TCP_STATES = {
    1: "CLOSED",
    2: "LISTEN",
    3: "SYN_SENT",
    4: "SYN_RECEIVED",
    5: "ESTABLISHED",
    6: "FIN_WAIT_1",
    7: "FIN_WAIT_2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB",
}


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(GUID)),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", wintypes.LPVOID),
        ("pSIPClientData", wintypes.LPVOID),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", wintypes.LPVOID),
    ]


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("ucRemoteAddr", ctypes.c_ubyte * 16),
        ("dwRemoteScopeId", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwState", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


@dataclass(frozen=True, slots=True)
class AmsiOutcome:
    status: str
    result: int = 0


class WindowsNative:
    """Native collector with per-instance caches and CPU delta state."""

    def __init__(self) -> None:
        if not IS_WINDOWS:
            raise RuntimeError("OpenGuard native monitoring requires Windows")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)
        self.iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
        self.wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
        self.shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        self._configure_prototypes()
        self._signature_cache: dict[str, SignatureStatus] = {}
        self._cpu_previous: dict[int, tuple[int, float]] = {}
        self._lock = threading.RLock()

    def _configure_prototypes(self) -> None:
        self.kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        self.kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self.kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        self.kernel32.Process32FirstW.restype = wintypes.BOOL
        self.kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        self.kernel32.Process32NextW.restype = wintypes.BOOL
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        self.kernel32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        self.kernel32.GetProcessTimes.restype = wintypes.BOOL
        self.psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
            wintypes.DWORD,
        ]
        self.psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        common_table_args = [
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.ULONG),
            wintypes.BOOL,
            wintypes.ULONG,
            ctypes.c_int,
            wintypes.ULONG,
        ]
        self.iphlpapi.GetExtendedTcpTable.argtypes = common_table_args
        self.iphlpapi.GetExtendedTcpTable.restype = wintypes.DWORD
        self.iphlpapi.GetExtendedUdpTable.argtypes = common_table_args
        self.iphlpapi.GetExtendedUdpTable.restype = wintypes.DWORD
        self.wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), wintypes.LPVOID]
        self.wintrust.WinVerifyTrust.restype = wintypes.LONG
        self.shell32.IsUserAnAdmin.argtypes = []
        self.shell32.IsUserAnAdmin.restype = wintypes.BOOL

    def is_elevated(self) -> bool:
        try:
            return bool(self.shell32.IsUserAnAdmin())
        except OSError:
            return False

    def processes(self, verify_signatures: bool = True) -> list[ProcessRecord]:
        handle = self.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not handle or handle == INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        entries: list[tuple[int, int, str, int]] = []
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)
            success = self.kernel32.Process32FirstW(handle, ctypes.byref(entry))
            while success:
                entries.append(
                    (
                        int(entry.th32ProcessID),
                        int(entry.th32ParentProcessID),
                        str(entry.szExeFile),
                        int(entry.cntThreads),
                    )
                )
                entry.dwSize = ctypes.sizeof(entry)
                success = self.kernel32.Process32NextW(handle, ctypes.byref(entry))
        finally:
            self.kernel32.CloseHandle(handle)

        now = time.monotonic()
        active_pids = {pid for pid, _, _, _ in entries}
        records: list[ProcessRecord] = []
        for pid, parent_pid, name, thread_count in entries:
            path, accessible, working_set, cpu_time = self._process_details(pid)
            identity = executable_identity(path)
            signature = (
                self.signature_status(path, identity)
                if verify_signatures and path
                else SignatureStatus.UNKNOWN
            )
            cpu_percent = self._cpu_percent(pid, cpu_time, now)
            risk = assess_process(name, path, signature, accessible)
            records.append(
                ProcessRecord(
                    pid=pid,
                    parent_pid=parent_pid,
                    name=name or f"PID {pid}",
                    path=path,
                    thread_count=thread_count,
                    working_set_bytes=working_set,
                    cpu_percent=cpu_percent,
                    signature=signature,
                    accessible=accessible,
                    identity=identity,
                    risk=risk,
                )
            )
        with self._lock:
            self._cpu_previous = {
                pid: value for pid, value in self._cpu_previous.items() if pid in active_pids
            }
        return records

    def _process_details(self, pid: int) -> tuple[str, bool, int, int | None]:
        if pid == 0:
            return "", False, 0, None
        handle = self.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return "", False, 0, None
        path = ""
        cpu_time: int | None = None
        try:
            size = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if self.kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                path = buffer.value
            cpu_time = self._read_cpu_time(handle)
        finally:
            self.kernel32.CloseHandle(handle)

        working_set = 0
        metrics_handle = self.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
        )
        if metrics_handle:
            try:
                counters = PROCESS_MEMORY_COUNTERS()
                counters.cb = ctypes.sizeof(counters)
                if self.psapi.GetProcessMemoryInfo(
                    metrics_handle, ctypes.byref(counters), counters.cb
                ):
                    working_set = int(counters.WorkingSetSize)
            finally:
                self.kernel32.CloseHandle(metrics_handle)
        return path, bool(path), working_set, cpu_time

    def _read_cpu_time(self, handle: int) -> int | None:
        created = wintypes.FILETIME()
        exited = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        if not self.kernel32.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            return None
        return _filetime_value(kernel) + _filetime_value(user)

    def _cpu_percent(self, pid: int, cpu_time: int | None, now: float) -> float:
        if cpu_time is None:
            return 0.0
        with self._lock:
            previous = self._cpu_previous.get(pid)
            self._cpu_previous[pid] = (cpu_time, now)
        if previous is None:
            return 0.0
        previous_cpu, previous_wall = previous
        wall_delta = max(now - previous_wall, 0.000001)
        cpu_delta_seconds = max(cpu_time - previous_cpu, 0) / 10_000_000
        cores = max(os.cpu_count() or 1, 1)
        return round(min((cpu_delta_seconds / wall_delta / cores) * 100.0, 100.0), 1)

    def signature_status(self, path: str, identity: str = "") -> SignatureStatus:
        if not path or not Path(path).is_file():
            return SignatureStatus.UNKNOWN
        suffix = Path(path).suffix.casefold()
        if suffix not in {".exe", ".dll", ".sys", ".ocx", ".cpl", ".msi"}:
            return SignatureStatus.NOT_APPLICABLE
        cache_key = identity or executable_identity(path)
        with self._lock:
            cached = self._signature_cache.get(cache_key)
        if cached is not None:
            return cached
        status = self._verify_trust(path)
        with self._lock:
            self._signature_cache[cache_key] = status
        return status

    def _verify_trust(self, path: str) -> SignatureStatus:
        action = GUID(
            0x00AAC56B,
            0xCD44,
            0x11D0,
            (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
        )
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(file_info)
        file_info.pcwszFilePath = path
        file_info.hFile = None
        file_info.pgKnownSubject = None

        data = WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(data)
        data.dwUIChoice = 2  # WTD_UI_NONE
        data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
        data.dwUnionChoice = 1  # WTD_CHOICE_FILE
        data.pFile = ctypes.pointer(file_info)
        data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
        # Do not force cache-only chain building. On clean Windows installs that
        # can classify a valid Microsoft signature as untrusted simply because
        # an intermediate certificate has not been cached yet. Revocation is
        # still explicitly disabled above for a deterministic UI check.
        data.dwProvFlags = 0
        try:
            result = int(
                self.wintrust.WinVerifyTrust(
                    wintypes.HWND(INVALID_HANDLE_VALUE), ctypes.byref(action), ctypes.byref(data)
                )
            )
            if result == 0:
                return SignatureStatus.TRUSTED
            unsigned_or_unsupported = {
                0x800B0001,  # TRUST_E_PROVIDER_UNKNOWN
                0x800B0003,  # TRUST_E_SUBJECT_FORM_UNKNOWN
                0x800B0100,  # TRUST_E_NOSIGNATURE (may still be catalog-signed)
            }
            if ctypes.c_ulong(result).value in unsigned_or_unsupported:
                # A file without an embedded signature can still be trusted by
                # a Windows catalog. This lightweight v0.1 check must not turn
                # "no embedded signature" into a false claim of invalid trust.
                return SignatureStatus.UNKNOWN
            return SignatureStatus.UNTRUSTED
        except OSError:
            return SignatureStatus.UNKNOWN
        finally:
            data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
            try:
                self.wintrust.WinVerifyTrust(
                    wintypes.HWND(INVALID_HANDLE_VALUE), ctypes.byref(action), ctypes.byref(data)
                )
            except OSError:
                pass

    def endpoints(self, process_map: dict[int, ProcessRecord] | None = None) -> list[NetworkEndpoint]:
        process_map = process_map or {}
        endpoints: list[NetworkEndpoint] = []
        endpoints.extend(self._tcp_table(AF_INET, MIB_TCPROW_OWNER_PID, process_map))
        endpoints.extend(self._tcp_table(AF_INET6, MIB_TCP6ROW_OWNER_PID, process_map))
        endpoints.extend(self._udp_table(AF_INET, MIB_UDPROW_OWNER_PID, process_map))
        endpoints.extend(self._udp_table(AF_INET6, MIB_UDP6ROW_OWNER_PID, process_map))
        return sorted(endpoints, key=lambda item: (item.process_name.casefold(), item.pid, item.protocol))

    def _table_buffer(self, function: object, family: int, table_class: int) -> ctypes.Array[ctypes.c_char] | None:
        size = wintypes.ULONG(0)
        result = function(None, ctypes.byref(size), False, family, table_class, 0)
        if result not in (0, ERROR_INSUFFICIENT_BUFFER) or size.value < 4:
            return None
        buffer = ctypes.create_string_buffer(size.value)
        result = function(buffer, ctypes.byref(size), False, family, table_class, 0)
        return buffer if result == 0 else None

    def _tcp_table(
        self,
        family: int,
        row_type: type[ctypes.Structure],
        process_map: dict[int, ProcessRecord],
    ) -> list[NetworkEndpoint]:
        buffer = self._table_buffer(self.iphlpapi.GetExtendedTcpTable, family, TCP_TABLE_OWNER_PID_ALL)
        if buffer is None:
            return []
        rows = _rows_from_buffer(buffer, row_type)
        results: list[NetworkEndpoint] = []
        for row in rows:
            if family == AF_INET:
                local_address = _ipv4(row.dwLocalAddr)
                remote_address = _ipv4(row.dwRemoteAddr)
            else:
                local_address = _ipv6(row.ucLocalAddr, int(row.dwLocalScopeId))
                remote_address = _ipv6(row.ucRemoteAddr, int(row.dwRemoteScopeId))
            pid = int(row.dwOwningPid)
            owner = process_map.get(pid)
            results.append(
                NetworkEndpoint(
                    protocol="TCP6" if family == AF_INET6 else "TCP4",
                    local_address=local_address,
                    local_port=_port(row.dwLocalPort),
                    remote_address=remote_address,
                    remote_port=_port(row.dwRemotePort),
                    state=TCP_STATES.get(int(row.dwState), f"STATE_{int(row.dwState)}"),
                    pid=pid,
                    process_name=owner.name if owner else "",
                    process_path=owner.path if owner else "",
                )
            )
        return results

    def _udp_table(
        self,
        family: int,
        row_type: type[ctypes.Structure],
        process_map: dict[int, ProcessRecord],
    ) -> list[NetworkEndpoint]:
        buffer = self._table_buffer(self.iphlpapi.GetExtendedUdpTable, family, UDP_TABLE_OWNER_PID)
        if buffer is None:
            return []
        rows = _rows_from_buffer(buffer, row_type)
        results: list[NetworkEndpoint] = []
        for row in rows:
            local_address = (
                _ipv4(row.dwLocalAddr)
                if family == AF_INET
                else _ipv6(row.ucLocalAddr, int(row.dwLocalScopeId))
            )
            pid = int(row.dwOwningPid)
            owner = process_map.get(pid)
            results.append(
                NetworkEndpoint(
                    protocol="UDP6" if family == AF_INET6 else "UDP4",
                    local_address=local_address,
                    local_port=_port(row.dwLocalPort),
                    remote_address="*",
                    remote_port=0,
                    state="BOUND",
                    pid=pid,
                    process_name=owner.name if owner else "",
                    process_path=owner.path if owner else "",
                )
            )
        return results


class AmsiScanner:
    """Optional consumer of the antivirus provider already installed in Windows."""

    def __init__(self, application_name: str = "OpenGuard/0.2") -> None:
        self.available = False
        self._context = ctypes.c_void_p()
        self._lock = threading.Lock()
        self._amsi: ctypes.WinDLL | None = None
        if not IS_WINDOWS:
            return
        try:
            amsi = ctypes.WinDLL("amsi", use_last_error=True)
            amsi.AmsiInitialize.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
            amsi.AmsiInitialize.restype = ctypes.c_long
            amsi.AmsiScanBuffer.argtypes = [
                ctypes.c_void_p,
                wintypes.LPVOID,
                wintypes.ULONG,
                wintypes.LPCWSTR,
                ctypes.c_void_p,
                ctypes.POINTER(wintypes.ULONG),
            ]
            amsi.AmsiScanBuffer.restype = ctypes.c_long
            amsi.AmsiUninitialize.argtypes = [ctypes.c_void_p]
            amsi.AmsiUninitialize.restype = None
            result = int(amsi.AmsiInitialize(application_name, ctypes.byref(self._context)))
            if result >= 0 and self._context.value:
                self._amsi = amsi
                self.available = True
        except OSError:
            self.available = False

    def scan(self, data: bytes, content_name: str) -> AmsiOutcome:
        if not self.available or self._amsi is None:
            return AmsiOutcome("unavailable")
        if not data:
            return AmsiOutcome("clean", 0)
        buffer = ctypes.create_string_buffer(data)
        result = wintypes.ULONG(0)
        with self._lock:
            hresult = int(
                self._amsi.AmsiScanBuffer(
                    self._context,
                    buffer,
                    len(data),
                    content_name,
                    None,
                    ctypes.byref(result),
                )
            )
        if hresult < 0:
            return AmsiOutcome("error", hresult)
        value = int(result.value)
        if value >= 32768:
            return AmsiOutcome("detected", value)
        if 16384 <= value < 20480:
            return AmsiOutcome("blocked_by_admin", value)
        return AmsiOutcome("clean", value)

    def close(self) -> None:
        if self.available and self._amsi is not None and self._context.value:
            with self._lock:
                self._amsi.AmsiUninitialize(self._context)
            self._context = ctypes.c_void_p()
            self.available = False

    def __enter__(self) -> "AmsiScanner":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _filetime_value(value: wintypes.FILETIME) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def _rows_from_buffer(
    buffer: ctypes.Array[ctypes.c_char], row_type: type[ctypes.Structure]
) -> list[ctypes.Structure]:
    raw_size = ctypes.sizeof(buffer)
    if raw_size < 4:
        return []
    count = int.from_bytes(buffer.raw[:4], "little")
    row_size = ctypes.sizeof(row_type)
    available = max((raw_size - 4) // row_size, 0)
    safe_count = min(count, available)
    return [row_type.from_buffer_copy(buffer, 4 + (index * row_size)) for index in range(safe_count)]


def _port(value: int) -> int:
    return socket.ntohs(int(value) & 0xFFFF)


def _ipv4(value: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", int(value)))


def _ipv6(value: ctypes.Array[ctypes.c_ubyte], scope_id: int) -> str:
    address = socket.inet_ntop(socket.AF_INET6, bytes(value))
    if scope_id and address.startswith("fe80:"):
        return f"{address}%{scope_id}"
    return address
