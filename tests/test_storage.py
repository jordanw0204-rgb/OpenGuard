from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from support import add_src_to_path

add_src_to_path()

from openguard.models import ScanFinding, ScanVerdict, SecurityEvent, Severity
from openguard.storage import Database


class StorageTests(unittest.TestCase):
    def test_baseline_events_and_scans_persist_without_locking_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            database = Database(path)
            self.assertFalse(database.baseline_initialized())
            database.record_executables(
                [("identity", r"C:\tool.exe", "tool.exe", "trusted", 0, "2026-01-01T00:00:00+00:00")]
            )
            self.assertEqual(database.known_executable_identities(["identity", "missing"]), {"identity"})
            database.complete_baseline()
            self.assertTrue(database.baseline_initialized())

            event_id = database.record_event(
                SecurityEvent("test", Severity.HIGH, "Test event", "Evidence")
            )
            self.assertGreater(event_id, 0)
            self.assertEqual(database.unresolved_high_count(), 1)
            database.resolve_events([event_id])
            self.assertEqual(database.unresolved_high_count(), 0)

            database.record_scan(
                ScanFinding("clean.txt", ScanVerdict.CLEAN, 0, ("clean",), sha256="abc")
            )
            self.assertEqual(database.recent_scans(1)[0]["sha256"], "abc")
            database.reset_baseline()
            self.assertFalse(database.baseline_initialized())
        self.assertFalse(path.exists(), "Temporary database directory should be removable after connections close")


if __name__ == "__main__":
    unittest.main()
