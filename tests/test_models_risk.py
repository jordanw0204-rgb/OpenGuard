from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from support import add_src_to_path

add_src_to_path()

from openguard.models import SignatureStatus, executable_identity
from openguard.risk import assess_process


class ModelsAndRiskTests(unittest.TestCase):
    def test_executable_identity_changes_when_file_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "tool.exe"
            target.write_bytes(b"one")
            first = executable_identity(str(target))
            target.write_bytes(b"a longer replacement")
            second = executable_identity(str(target))
            self.assertNotEqual(first, second)

    def test_trusted_windows_binary_has_no_risk_signal(self) -> None:
        assessment = assess_process(
            "tool.exe", r"C:\Windows\System32\tool.exe", SignatureStatus.TRUSTED
        )
        self.assertEqual(assessment.score, 0)
        self.assertEqual(assessment.reasons, ())

    def test_unsigned_temp_executable_is_high_risk_and_explained(self) -> None:
        with patch.dict(os.environ, {"TEMP": r"C:\Users\Test\Temp", "TMP": r"C:\Users\Test\Temp"}):
            assessment = assess_process(
                "payload.exe",
                r"C:\Users\Test\Temp\payload.exe",
                SignatureStatus.UNTRUSTED,
            )
        self.assertGreaterEqual(assessment.score, 65)
        self.assertTrue(any("temporary" in item.casefold() for item in assessment.reasons))
        self.assertTrue(any("authenticode" in item.casefold() for item in assessment.reasons))

    def test_protected_process_is_not_claimed_malicious(self) -> None:
        assessment = assess_process("System", "", SignatureStatus.UNKNOWN, accessible=False)
        self.assertLess(assessment.score, 15)
        self.assertIn("limited access", assessment.reasons[0].casefold())


if __name__ == "__main__":
    unittest.main()
