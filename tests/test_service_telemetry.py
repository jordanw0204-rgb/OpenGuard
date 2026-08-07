from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from support import add_src_to_path

add_src_to_path()

from openguard.service_control import service_action
from openguard.telemetry import EtwProcessEventSource


class ServiceControlTests(unittest.TestCase):
    def test_install_quotes_binary_and_data_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "folder with spaces" / "OpenGuardService.exe"
            binary.parent.mkdir()
            binary.write_bytes(b"fixture")
            completed = subprocess.CompletedProcess(["sc.exe"], 0, "created", "")
            with (
                patch("openguard.service_control._require_elevation"),
                patch("openguard.service_control.data_root", return_value=root / "data folder"),
                patch("openguard.service_control._sc", return_value=completed) as command,
            ):
                result = service_action("install", binary)
            self.assertTrue(result["success"])
            create_arguments = command.call_args_list[0].args
            image_path = create_arguments[3]
            self.assertIn(f'"{binary.resolve()}"', image_path)
            self.assertIn(f'"{(root / "data folder").resolve()}"', image_path)


class TelemetryFallbackTests(unittest.TestCase):
    def test_missing_etw_helper_is_explicitly_unavailable(self) -> None:
        source = EtwProcessEventSource(Path("Z:/definitely-missing/OpenGuardETW.exe"))
        self.assertFalse(source.start(lambda _event: None))
        self.assertEqual(source.status, "unavailable")
        self.assertIn("missing", source.detail.casefold())


if __name__ == "__main__":
    unittest.main()
