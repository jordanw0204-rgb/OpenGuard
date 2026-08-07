from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from support import add_src_to_path

add_src_to_path()

from openguard.models import (
    NetworkEndpoint,
    ProcessRecord,
    RiskAssessment,
    Severity,
    SignatureStatus,
)
from openguard.monitor import SystemMonitor
from openguard.storage import Database


def process(pid: int, identity: str, score: int = 0) -> ProcessRecord:
    severity = Severity.HIGH if score >= 65 else Severity.INFO
    return ProcessRecord(
        pid=pid,
        parent_pid=1,
        name=f"process-{pid}.exe",
        path=fr"C:\Apps\process-{pid}.exe",
        signature=SignatureStatus.TRUSTED if score == 0 else SignatureStatus.UNTRUSTED,
        identity=identity,
        risk=RiskAssessment(score, severity, ("test evidence",) if score else ()),
    )


class FakeNative:
    def __init__(self) -> None:
        self.records = [process(10, "first")]

    def processes(self, verify_signatures: bool = True) -> list[ProcessRecord]:
        return list(self.records)

    def endpoints(self, process_map: dict[int, ProcessRecord]) -> list[NetworkEndpoint]:
        owner = process_map[10]
        return [NetworkEndpoint("TCP4", "127.0.0.1", 1000, "127.0.0.1", 2000, "ESTABLISHED", 10, owner.name, owner.path)]

    def is_elevated(self) -> bool:
        return False


class MonitorTests(unittest.TestCase):
    def test_first_run_baselines_then_new_identity_alerts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "monitor.db")
            native = FakeNative()
            events = []
            monitor = SystemMonitor(native, database, on_event=events.append)
            first = monitor.collect_snapshot()
            self.assertEqual(sum(item.is_new for item in first.processes), 0)
            self.assertTrue(database.baseline_initialized())

            second = monitor.collect_snapshot()
            self.assertEqual(sum(item.is_new for item in second.processes), 0)

            native.records.append(process(11, "second", score=70))
            third = monitor.collect_snapshot()
            self.assertEqual(sum(item.is_new for item in third.processes), 1)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].severity, Severity.HIGH)
            self.assertEqual(database.unresolved_high_count(), 1)

    def test_non_persisting_snapshot_does_not_create_baseline_or_false_new(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "monitor.db")
            snapshot = SystemMonitor(FakeNative(), database).collect_snapshot(persist=False)
            self.assertEqual(sum(item.is_new for item in snapshot.processes), 0)
            self.assertFalse(database.baseline_initialized())


if __name__ == "__main__":
    unittest.main()
