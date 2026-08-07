from __future__ import annotations

import ctypes
import threading
import unittest

from support import add_src_to_path

add_src_to_path()

from openguard.windows_api import (
    AF_INET,
    MIB_TCPROW_OWNER_PID,
    TCP_ESTATS_DATA_ROD_v0,
    TCP_ESTATS_DATA_RW_v0,
    WindowsNative,
    _counter_rate,
)


class _FakeEStatsApi:
    def __init__(self, enabled: bool, sent: int = 0, received: int = 0) -> None:
        self.enabled = enabled
        self.sent = sent
        self.received = received
        self.enable_calls = 0

    def GetPerTcpConnectionEStats(self, *arguments: object) -> int:
        rw = ctypes.cast(arguments[2], ctypes.POINTER(TCP_ESTATS_DATA_RW_v0)).contents
        rod = ctypes.cast(arguments[8], ctypes.POINTER(TCP_ESTATS_DATA_ROD_v0)).contents
        rw.EnableCollection = int(self.enabled)
        # Windows documents ROD values as invalid while collection is disabled.
        # Deliberately provide nonsense here to ensure OpenGuard never displays it.
        rod.DataBytesOut = self.sent if self.enabled else 0xDEADBEEFDEADBEEF
        rod.DataBytesIn = self.received if self.enabled else 0xFEEDFACEFEEDFACE
        return 0

    GetPerTcp6ConnectionEStats = GetPerTcpConnectionEStats

    def SetPerTcpConnectionEStats(self, *arguments: object) -> int:
        self.enable_calls += 1
        self.enabled = True
        return 0

    SetPerTcp6ConnectionEStats = SetPerTcpConnectionEStats


def _native(api: _FakeEStatsApi, elevated: bool) -> WindowsNative:
    native = WindowsNative.__new__(WindowsNative)
    native.iphlpapi = api
    native._elevated = elevated
    native._tcp_previous = {}
    native._tcp_enable_attempted = set()
    native._lock = threading.RLock()
    return native


def _row() -> MIB_TCPROW_OWNER_PID:
    row = MIB_TCPROW_OWNER_PID()
    row.dwState = 5
    row.dwOwningPid = 42
    return row


class TcpUsageTests(unittest.TestCase):
    def test_disabled_collection_never_exposes_invalid_rod_values(self) -> None:
        api = _FakeEStatsApi(enabled=False)
        usage = _native(api, elevated=False)._tcp_usage(_row(), AF_INET, ("connection",), 10.0)
        self.assertEqual(usage, (None, None, None, None, "service-required"))
        self.assertEqual(api.enable_calls, 0)

    def test_elevated_collector_enables_once_then_reports_deltas(self) -> None:
        api = _FakeEStatsApi(enabled=False)
        native = _native(api, elevated=True)
        key = ("connection",)
        self.assertEqual(native._tcp_usage(_row(), AF_INET, key, 10.0)[4], "warming")
        self.assertEqual(api.enable_calls, 1)

        api.sent, api.received = 1_000, 2_000
        first = native._tcp_usage(_row(), AF_INET, key, 11.0)
        self.assertEqual(first, (1_000, 2_000, None, None, "active"))

        api.sent, api.received = 1_600, 3_200
        second = native._tcp_usage(_row(), AF_INET, key, 13.0)
        self.assertEqual(second, (1_600, 3_200, 300.0, 600.0, "active"))
        self.assertEqual(api.enable_calls, 1)

    def test_counter_reset_never_produces_negative_rate(self) -> None:
        self.assertEqual(_counter_rate(10, 50, 2.0), 0.0)
        self.assertEqual(_counter_rate(150, 50, 2.0), 50.0)


if __name__ == "__main__":
    unittest.main()
