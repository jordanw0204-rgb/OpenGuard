from __future__ import annotations

import os
import unittest

from support import add_src_to_path

add_src_to_path()

from openguard.models import SignatureStatus
from openguard.windows_api import AmsiScanner, IS_WINDOWS, WindowsNative


@unittest.skipUnless(IS_WINDOWS, "Windows integration test")
class WindowsIntegrationTests(unittest.TestCase):
    def test_process_and_endpoint_apis(self) -> None:
        native = WindowsNative()
        processes = native.processes(verify_signatures=False)
        self.assertGreater(len(processes), 0)
        self.assertIn(os.getpid(), {item.pid for item in processes})
        endpoints = native.endpoints({item.pid: item for item in processes})
        self.assertIsInstance(endpoints, list)

    def test_python_executable_trust_and_amsi_clean_buffer(self) -> None:
        native = WindowsNative()
        status = native.signature_status(os.path.realpath(os.sys.executable))
        self.assertEqual(status, SignatureStatus.TRUSTED)
        amsi = AmsiScanner()
        if amsi.available:
            # GitHub's Windows images expose amsi.dll but do not always have an
            # active provider. Either a clean result or an explicit provider
            # error is correct; silently claiming detection would not be.
            self.assertIn(
                amsi.scan(b"OpenGuard clean integration test", "unit-test.txt").status,
                {"clean", "error"},
            )
        amsi.close()


if __name__ == "__main__":
    unittest.main()
