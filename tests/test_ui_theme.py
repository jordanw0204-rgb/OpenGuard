from __future__ import annotations

import os
import struct
import tkinter as tk
import unittest
from pathlib import Path
from tkinter import ttk
from unittest.mock import patch

from support import add_src_to_path

add_src_to_path()

from openguard.ui import COLORS, NAV_ITEMS, OpenGuardUI, _asset_path, _colorref


class _FakeText:
    def __init__(self) -> None:
        self.value = ""

    def configure(self, **_options: object) -> None:
        pass

    def delete(self, *_arguments: object) -> None:
        self.value = ""

    def insert(self, _position: str, value: str) -> None:
        self.value = value


class UIThemeTests(unittest.TestCase):
    def test_graphite_palette_and_navigation_icons_are_complete(self) -> None:
        self.assertEqual(COLORS["bg"], "#090a0c")
        self.assertEqual(COLORS["sidebar"], "#0d0f12")
        self.assertEqual(COLORS["accent"], "#35e6c0")
        self.assertEqual(
            [page for page, _icon in NAV_ITEMS],
            ["Overview", "Processes", "Network", "Scanner", "Security", "Alerts", "About"],
        )
        self.assertEqual(len({icon for _page, icon in NAV_ITEMS}), len(NAV_ITEMS))
        self.assertTrue(all(len(icon) == 1 for _page, icon in NAV_ITEMS))

    def test_brand_assets_have_expected_windows_formats(self) -> None:
        png = _asset_path("openguard-logo.png")
        self.assertTrue(png.is_file())
        png_bytes = png.read_bytes()
        self.assertEqual(png_bytes[:8], b"\x89PNG\r\n\x1a\n")
        width, height = struct.unpack(">II", png_bytes[16:24])
        self.assertEqual((width, height), (256, 256))

        ico = Path(__file__).resolve().parents[1] / "packaging" / "openguard.ico"
        self.assertTrue(ico.is_file())
        reserved, image_type, image_count = struct.unpack("<HHH", ico.read_bytes()[:6])
        self.assertEqual((reserved, image_type), (0, 1))
        self.assertGreaterEqual(image_count, 8)

    def test_colorref_uses_windows_bgr_layout(self) -> None:
        self.assertEqual(_colorref("#123456"), 0x563412)

    def test_security_refresh_starts_background_worker_without_blocking(self) -> None:
        ui = OpenGuardUI.__new__(OpenGuardUI)
        ui.security_status_text = _FakeText()
        ui.security_refresh_running = False
        ui.security_refresh_pending = False
        with patch("openguard.ui.threading.Thread") as thread:
            ui._refresh_security()
            self.assertTrue(ui.security_refresh_running)
            thread.assert_called_once()
            self.assertEqual(thread.call_args.kwargs["target"], ui._security_refresh_worker)
            thread.return_value.start.assert_called_once()

            ui._refresh_security()
            self.assertTrue(ui.security_refresh_pending)
            thread.assert_called_once()

    @unittest.skipUnless(os.name == "nt", "Tk visual styles are verified on Windows")
    def test_custom_scrollbar_styles_remove_native_arrow_buttons(self) -> None:
        root = tk.Tk()
        root.withdraw()
        try:
            ui = OpenGuardUI.__new__(OpenGuardUI)
            ui.root = root
            ui._configure_styles()
            style = ttk.Style(root)
            vertical_layout = str(style.layout("OpenGuard.Vertical.TScrollbar"))
            horizontal_layout = str(style.layout("OpenGuard.Horizontal.TScrollbar"))
            self.assertIn("thumb", vertical_layout.casefold())
            self.assertIn("thumb", horizontal_layout.casefold())
            self.assertNotIn("uparrow", vertical_layout.casefold())
            self.assertNotIn("rightarrow", horizontal_layout.casefold())
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
