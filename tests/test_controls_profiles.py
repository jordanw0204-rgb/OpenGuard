from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from support import add_src_to_path

add_src_to_path()

from openguard.models import ScanFinding, ScanProfile, ScanVerdict, utc_now
from openguard.profiles import profile_targets
from openguard.scanner import Scanner
from openguard.storage import Database


class SecurityControlsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.previous_data_dir = os.environ.get("OPENGUARD_DATA_DIR")
        os.environ["OPENGUARD_DATA_DIR"] = str(self.root / "data")
        self.database = Database(self.root / "controls.db")
        self.scanner = Scanner(self.database, amsi_enabled=False)

    def tearDown(self) -> None:
        self.scanner.close()
        if self.previous_data_dir is None:
            os.environ.pop("OPENGUARD_DATA_DIR", None)
        else:
            os.environ["OPENGUARD_DATA_DIR"] = self.previous_data_dir
        self.temporary.cleanup()

    def test_recursive_exclusion_skips_descendants(self) -> None:
        excluded = self.root / "excluded"
        excluded.mkdir()
        target = excluded / "file.txt"
        target.write_text("content", encoding="utf-8")
        self.database.add_exclusion(excluded, True, utc_now())
        finding = self.scanner.scan_file(target)
        self.assertEqual(finding.verdict, ScanVerdict.SKIPPED)
        self.assertIn("excluded", finding.reasons[0].casefold())

    def test_allowed_hash_skips_detection(self) -> None:
        target = self.root / "allowed.txt"
        target.write_bytes(b"OPENGUARD_INERT_YARA_TEST_MARKER_2026")
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        self.database.allow_hash(digest, "known lab fixture", utc_now())
        finding = self.scanner.scan_file(target)
        self.assertEqual(finding.verdict, ScanVerdict.SKIPPED)
        self.assertEqual(finding.sha256, digest)

    def test_quarantine_restore_round_trip_and_collision_refusal(self) -> None:
        target = self.root / "restore.bin"
        target.write_bytes(b"inert")
        finding = ScanFinding(
            str(target), ScanVerdict.SUSPICIOUS, 60, ("test",), hashlib.sha256(b"inert").hexdigest()
        )
        quarantined = self.scanner.quarantine(finding)
        record = self.database.quarantines(active_only=True)[0]
        target.write_bytes(b"collision")
        with self.assertRaises(FileExistsError):
            self.scanner.restore_quarantine(str(record["id"]))
        target.unlink()
        restored = self.scanner.restore_quarantine(str(record["id"]))
        self.assertEqual(restored.read_bytes(), b"inert")
        self.assertFalse(quarantined.exists())
        self.assertFalse(self.database.quarantines(active_only=True))


class ScanProfileTests(unittest.TestCase):
    def test_downloads_and_quick_profiles_resolve_existing_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            user = Path(directory)
            downloads = user / "Downloads"
            desktop = user / "Desktop"
            downloads.mkdir()
            desktop.mkdir()
            environment = {"USERPROFILE": str(user)}
            self.assertEqual(profile_targets(ScanProfile.DOWNLOADS, environ=environment), (downloads,))
            self.assertEqual(set(profile_targets(ScanProfile.QUICK, environ=environment)), {downloads, desktop})


if __name__ == "__main__":
    unittest.main()
