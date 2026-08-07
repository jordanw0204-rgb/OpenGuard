"""Responsive tkinter desktop dashboard for OpenGuard."""

from __future__ import annotations

import ctypes
import os
import queue
import threading
import tkinter as tk
from dataclasses import dataclass, replace
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any

from .config import APP_NAME, DEFAULT_UPDATE_MANIFEST_URL, VERSION, data_root
from .models import NetworkEndpoint, ScanFinding, ScanProfile, ScanVerdict, SecurityEvent, Severity, SystemSnapshot, utc_now
from .monitor import SystemMonitor
from .scanner import Scanner
from .storage import Database
from .service_control import service_action
from .updates import SecurityContentUpdater
from .windows_api import WindowsNative
from .yara_engine import YaraEngine

COLORS = {
    "bg": "#090a0c",
    "sidebar": "#0d0f12",
    "surface": "#121418",
    "surface_alt": "#191c21",
    "surface_hover": "#20242a",
    "border": "#292d34",
    "border_strong": "#373d46",
    "text": "#f4f6f8",
    "muted": "#8e96a1",
    "muted_strong": "#bac1c9",
    "accent": "#35e6c0",
    "accent_hover": "#67efd4",
    "accent_dark": "#102d29",
    "selection": "#173d37",
    "blue": "#79a9ff",
    "yellow": "#e7c35d",
    "orange": "#ee9562",
    "red": "#ff6b7e",
    "scrollbar_track": "#0e1013",
    "scrollbar_thumb": "#3a4048",
    "scrollbar_hover": "#555d68",
}

NAV_ITEMS = (
    ("Overview", "\ue80f"),
    ("Processes", "\ue7c4"),
    ("Network", "\ue968"),
    ("Scanner", "\ue721"),
    ("Security", "\ue83d"),
    ("Alerts", "\ue7ba"),
    ("About", "\ue946"),
)


@dataclass(frozen=True, slots=True)
class SecurityPageSnapshot:
    content: dict[str, Any]
    service: dict[str, Any]
    yara_status: str
    yara_error: str
    etw_status: str
    etw_detail: str
    wfp_status: str
    wfp_detail: str
    quarantines: tuple[dict[str, Any], ...]
    exclusions: tuple[dict[str, Any], ...]
    allowed_hashes: tuple[dict[str, Any], ...]
    error: str = ""


def _asset_path(name: str) -> Path:
    return Path(__file__).resolve().parent / "assets" / name


def _colorref(value: str) -> int:
    value = value.lstrip("#")
    red, green, blue = (int(value[index : index + 2], 16) for index in (0, 2, 4))
    return red | (green << 8) | (blue << 16)


def _enable_windows_dark_chrome(root: tk.Tk) -> bool:
    """Apply supported Windows dark caption attributes without changing window behavior."""
    if os.name != "nt":
        return False
    try:
        root.update_idletasks()
        client_hwnd = int(root.winfo_id())
        parent_hwnd = int(ctypes.windll.user32.GetParent(client_hwnd))
        handles = tuple(dict.fromkeys(handle for handle in (parent_hwnd, client_hwnd) if handle))
        dwm = ctypes.windll.dwmapi
        applied = False
        for hwnd in handles:
            enabled = ctypes.c_int(1)
            result = dwm.DwmSetWindowAttribute(
                ctypes.c_void_p(hwnd), 20, ctypes.byref(enabled), ctypes.sizeof(enabled)
            )
            applied = applied or result == 0
            for attribute, color in (
                (34, COLORS["border"]),
                (35, COLORS["sidebar"]),
                (36, COLORS["text"]),
            ):
                color_value = ctypes.c_uint(_colorref(color))
                dwm.DwmSetWindowAttribute(
                    ctypes.c_void_p(hwnd),
                    attribute,
                    ctypes.byref(color_value),
                    ctypes.sizeof(color_value),
                )
        return applied
    except (AttributeError, OSError, tk.TclError, ValueError):
        return False


class OpenGuardUI:
    def __init__(self, root: tk.Tk, database: Database, native: WindowsNative) -> None:
        self.root = root
        self.database = database
        self.native = native
        self.scanner = Scanner(database, native, amsi_enabled=True)
        self.messages: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=64)
        self.latest_snapshot: SystemSnapshot | None = None
        self.scan_cancel = threading.Event()
        self.scan_running = False
        self.scan_findings: list[ScanFinding] = []
        self.security_refresh_running = False
        self.security_refresh_pending = False
        self.current_page = "Overview"
        self.pages: dict[str, tk.Frame] = {}
        self.nav_widgets: dict[str, tuple[tk.Frame, tk.Frame, tk.Label, tk.Label, tk.Frame]] = {}
        self.metric_values: dict[str, tk.Label] = {}
        self._configure_window()
        self._configure_styles()
        self._build_shell()
        self.monitor = SystemMonitor(
            native,
            database,
            on_snapshot=lambda item: self._post("snapshot", item),
            on_event=lambda item: self._post("event", item),
            on_error=lambda item: self._post("error", item),
        )
        self.monitor.start()
        self.root.after(100, self._drain_messages)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _configure_window(self) -> None:
        self.root.title(f"{APP_NAME} — Windows Security Monitor")
        self.root.geometry("1380x860")
        self.root.minsize(1080, 680)
        self.root.configure(bg=COLORS["bg"])
        self.logo_image: tk.PhotoImage | None = None
        self.brand_logo: tk.PhotoImage | None = None
        try:
            self.logo_image = tk.PhotoImage(file=str(_asset_path("openguard-logo.png")))
            self.brand_logo = self.logo_image.subsample(4, 4)
            self.root.iconphoto(True, self.logo_image)
        except tk.TclError:
            pass
        self.root.after(150, lambda: _enable_windows_dark_chrome(self.root))
        self.root.after(800, lambda: _enable_windows_dark_chrome(self.root))

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=COLORS["surface"],
            fieldbackground=COLORS["surface"],
            foreground=COLORS["text"],
            rowheight=32,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        style.map(
            "Treeview",
            background=[("selected", COLORS["selection"])],
            foreground=[("selected", COLORS["text"])],
        )
        style.configure(
            "Treeview.Heading",
            background=COLORS["surface_alt"],
            foreground=COLORS["muted"],
            relief="flat",
            padding=(8, 8),
            font=("Segoe UI Semibold", 9),
        )
        style.map("Treeview.Heading", background=[("active", COLORS["border"])])
        style.configure(
            "OpenGuard.Vertical.TScrollbar",
            gripcount=0,
            background=COLORS["scrollbar_thumb"],
            darkcolor=COLORS["scrollbar_thumb"],
            lightcolor=COLORS["scrollbar_thumb"],
            troughcolor=COLORS["scrollbar_track"],
            bordercolor=COLORS["scrollbar_track"],
            arrowcolor=COLORS["muted"],
            relief="flat",
            borderwidth=0,
            width=12,
        )
        style.layout(
            "OpenGuard.Vertical.TScrollbar",
            [("Vertical.Scrollbar.trough", {"sticky": "ns", "children": [
                ("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})
            ]})],
        )
        style.map(
            "OpenGuard.Vertical.TScrollbar",
            background=[("pressed", COLORS["accent"]), ("active", COLORS["scrollbar_hover"])],
        )
        style.configure(
            "OpenGuard.Horizontal.TScrollbar",
            gripcount=0,
            background=COLORS["scrollbar_thumb"],
            darkcolor=COLORS["scrollbar_thumb"],
            lightcolor=COLORS["scrollbar_thumb"],
            troughcolor=COLORS["scrollbar_track"],
            bordercolor=COLORS["scrollbar_track"],
            arrowcolor=COLORS["muted"],
            relief="flat",
            borderwidth=0,
            width=12,
        )
        style.layout(
            "OpenGuard.Horizontal.TScrollbar",
            [("Horizontal.Scrollbar.trough", {"sticky": "ew", "children": [
                ("Horizontal.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})
            ]})],
        )
        style.map(
            "OpenGuard.Horizontal.TScrollbar",
            background=[("pressed", COLORS["accent"]), ("active", COLORS["scrollbar_hover"])],
        )
        style.configure(
            "OpenGuard.Horizontal.TProgressbar",
            background=COLORS["accent"],
            troughcolor=COLORS["surface_alt"],
            borderwidth=0,
        )
        style.configure(
            "TCombobox",
            fieldbackground=COLORS["surface_alt"],
            background=COLORS["surface_alt"],
            foreground=COLORS["text"],
            arrowcolor=COLORS["text"],
            bordercolor=COLORS["border"],
            lightcolor=COLORS["border"],
            darkcolor=COLORS["border"],
            selectbackground=COLORS["selection"],
            selectforeground=COLORS["text"],
            padding=(8, 5),
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", COLORS["surface_alt"])],
            foreground=[("readonly", COLORS["text"])],
            background=[("active", COLORS["surface_hover"]), ("readonly", COLORS["surface_alt"])],
        )
        style.configure("TNotebook", background=COLORS["bg"], borderwidth=0, tabmargins=(0, 0, 0, 10))
        style.configure(
            "TNotebook.Tab",
            background=COLORS["surface"],
            foreground=COLORS["muted"],
            borderwidth=0,
            padding=(18, 10),
            font=("Segoe UI Semibold", 9),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", COLORS["accent_dark"]), ("active", COLORS["surface_hover"])],
            foreground=[("selected", COLORS["accent"]), ("active", COLORS["text"])],
        )
        self.root.option_add("*TCombobox*Listbox.background", COLORS["surface_alt"])
        self.root.option_add("*TCombobox*Listbox.foreground", COLORS["text"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", COLORS["selection"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", COLORS["text"])

    def _build_shell(self) -> None:
        sidebar = tk.Frame(
            self.root,
            bg=COLORS["sidebar"],
            width=252,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        main = tk.Frame(self.root, bg=COLORS["bg"])
        main.pack(side="left", fill="both", expand=True)

        brand = tk.Frame(sidebar, bg=COLORS["sidebar"])
        brand.pack(fill="x", padx=18, pady=(22, 24))
        if self.brand_logo is not None:
            tk.Label(
                brand,
                image=self.brand_logo,
                bg=COLORS["sidebar"],
                bd=0,
            ).pack(side="left")
        else:
            tk.Label(
                brand,
                text="◈",
                bg=COLORS["accent_dark"],
                fg=COLORS["accent"],
                font=("Segoe UI Symbol", 22, "bold"),
                width=2,
                height=1,
            ).pack(side="left")
        brand_text = tk.Frame(brand, bg=COLORS["sidebar"])
        brand_text.pack(side="left", padx=(10, 0))
        tk.Label(
            brand_text,
            text=APP_NAME,
            bg=COLORS["sidebar"],
            fg=COLORS["text"],
            font=("Segoe UI Semibold", 17),
        ).pack(anchor="w")
        tk.Label(
            brand_text,
            text=f"OPEN SOURCE  •  v{VERSION}",
            bg=COLORS["sidebar"],
            fg=COLORS["muted"],
            font=("Segoe UI", 7),
        ).pack(anchor="w")

        for page, symbol in NAV_ITEMS:
            self._build_nav_item(sidebar, page, symbol)

        status_box = tk.Frame(sidebar, bg=COLORS["surface"], highlightbackground=COLORS["border"], highlightthickness=1)
        status_box.pack(side="bottom", fill="x", padx=16, pady=18)
        self.sidebar_status = tk.Label(
            status_box,
            text="●  Starting monitor…",
            bg=COLORS["surface"],
            fg=COLORS["yellow"],
            font=("Segoe UI Semibold", 9),
            anchor="w",
        )
        self.sidebar_status.pack(fill="x", padx=12, pady=(11, 2))
        self.sidebar_scope = tk.Label(
            status_box,
            text="User-mode coverage",
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            font=("Segoe UI", 8),
            anchor="w",
        )
        self.sidebar_scope.pack(fill="x", padx=12, pady=(0, 11))

        header = tk.Frame(main, bg=COLORS["bg"], height=88)
        header.pack(fill="x", padx=28, pady=(20, 0))
        header.pack_propagate(False)
        header_left = tk.Frame(header, bg=COLORS["bg"])
        header_left.pack(side="left", anchor="w")
        self.page_title = tk.Label(
            header_left,
            text="Overview",
            bg=COLORS["bg"],
            fg=COLORS["text"],
            font=("Segoe UI Semibold", 23),
        )
        self.page_title.pack(anchor="w")
        self.page_subtitle = tk.Label(
            header_left,
            text="A readable view of security-relevant activity on this PC",
            bg=COLORS["bg"],
            fg=COLORS["muted"],
            font=("Segoe UI", 10),
        )
        self.page_subtitle.pack(anchor="w", pady=(3, 0))
        self.header_status = tk.Label(
            header,
            text="COLLECTING INITIAL SNAPSHOT",
            bg=COLORS["accent_dark"],
            fg=COLORS["accent"],
            padx=13,
            pady=8,
            font=("Segoe UI Semibold", 8),
        )
        self.header_status.pack(side="right", anchor="n", pady=4)

        self.content = tk.Frame(main, bg=COLORS["bg"])
        self.content.pack(fill="both", expand=True, padx=28, pady=(0, 24))
        self._build_overview()
        self._build_processes()
        self._build_network()
        self._build_scanner()
        self._build_security()
        self._build_alerts()
        self._build_about()
        self.show_page("Overview")

    def _build_nav_item(self, sidebar: tk.Frame, page: str, symbol: str) -> None:
        row = tk.Frame(sidebar, bg=COLORS["sidebar"], height=54, cursor="hand2")
        row.pack(fill="x", padx=10, pady=2)
        row.pack_propagate(False)
        indicator = tk.Frame(row, bg=COLORS["sidebar"], width=3)
        indicator.pack(side="left", fill="y", pady=9)
        icon_tile = tk.Frame(row, bg=COLORS["surface_alt"], width=38, height=38, cursor="hand2")
        icon_tile.pack(side="left", padx=(9, 12), pady=8)
        icon_tile.pack_propagate(False)
        icon = tk.Label(
            icon_tile,
            text=symbol,
            bg=COLORS["surface_alt"],
            fg=COLORS["muted_strong"],
            font=("Segoe Fluent Icons", 17),
            cursor="hand2",
        )
        icon.pack(fill="both", expand=True)
        label = tk.Label(
            row,
            text=page,
            bg=COLORS["sidebar"],
            fg=COLORS["muted_strong"],
            font=("Segoe UI Semibold", 10),
            anchor="w",
            cursor="hand2",
        )
        label.pack(side="left", fill="both", expand=True)
        self.nav_widgets[page] = (row, icon_tile, icon, label, indicator)
        for widget in (row, icon_tile, icon, label, indicator):
            widget.bind("<Button-1>", lambda _event, selected=page: self.show_page(selected))
            widget.bind("<Enter>", lambda _event, selected=page: self._set_nav_hover(selected, True))
            widget.bind("<Leave>", lambda _event, selected=page: self._set_nav_hover(selected, False))

    def _set_nav_hover(self, page: str, hovering: bool) -> None:
        if page == self.current_page:
            return
        row, icon_tile, icon, label, indicator = self.nav_widgets[page]
        row_color = COLORS["surface_alt"] if hovering else COLORS["sidebar"]
        tile_color = COLORS["surface_hover"] if hovering else COLORS["surface_alt"]
        row.configure(bg=row_color)
        label.configure(bg=row_color, fg=COLORS["text"] if hovering else COLORS["muted_strong"])
        indicator.configure(bg=row_color)
        icon_tile.configure(bg=tile_color)
        icon.configure(bg=tile_color, fg=COLORS["text"] if hovering else COLORS["muted_strong"])

    def _set_nav_selected(self, page: str, selected: bool) -> None:
        row, icon_tile, icon, label, indicator = self.nav_widgets[page]
        row_color = COLORS["surface_alt"] if selected else COLORS["sidebar"]
        tile_color = COLORS["accent_dark"] if selected else COLORS["surface_alt"]
        row.configure(bg=row_color)
        label.configure(bg=row_color, fg=COLORS["text"] if selected else COLORS["muted_strong"])
        indicator.configure(bg=COLORS["accent"] if selected else row_color)
        icon_tile.configure(bg=tile_color)
        icon.configure(bg=tile_color, fg=COLORS["accent"] if selected else COLORS["muted_strong"])

    def _new_page(self, name: str) -> tk.Frame:
        frame = tk.Frame(self.content, bg=COLORS["bg"])
        frame.grid(row=0, column=0, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)
        self.pages[name] = frame
        return frame

    def _build_overview(self) -> None:
        page = self._new_page("Overview")
        cards = tk.Frame(page, bg=COLORS["bg"])
        cards.pack(fill="x")
        for column in range(4):
            cards.grid_columnconfigure(column, weight=1, uniform="metric")
        for index, (key, label, accent) in enumerate(
            (
                ("processes", "Running processes", COLORS["blue"]),
                ("endpoints", "Network endpoints", COLORS["accent"]),
                ("new", "New executables", COLORS["yellow"]),
                ("alerts", "High alerts", COLORS["red"]),
            )
        ):
            card = tk.Frame(cards, bg=COLORS["surface"], highlightbackground=COLORS["border"], highlightthickness=1)
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 7, 0 if index == 3 else 7))
            tk.Frame(card, bg=accent, width=4).pack(side="left", fill="y")
            inside = tk.Frame(card, bg=COLORS["surface"])
            inside.pack(fill="both", expand=True, padx=16, pady=14)
            value = tk.Label(inside, text="—", bg=COLORS["surface"], fg=COLORS["text"], font=("Segoe UI Semibold", 24))
            value.pack(anchor="w")
            tk.Label(inside, text=label, bg=COLORS["surface"], fg=COLORS["muted"], font=("Segoe UI", 9)).pack(anchor="w")
            self.metric_values[key] = value

        lower = tk.Frame(page, bg=COLORS["bg"])
        lower.pack(fill="both", expand=True, pady=(18, 0))
        lower.grid_columnconfigure(0, weight=3)
        lower.grid_columnconfigure(1, weight=2)
        lower.grid_rowconfigure(0, weight=1)

        activity = self._panel(lower, "Recent security activity", "Newest local alerts and findings")
        activity.grid(row=0, column=0, sticky="nsew", padx=(0, 9))
        self.overview_alerts = self._tree(
            activity,
            ("time", "severity", "event", "detail"),
            {"time": 120, "severity": 80, "event": 190, "detail": 420},
        )
        self.overview_alerts.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        coverage = self._panel(lower, "Coverage status", "What this build can currently observe")
        coverage.grid(row=0, column=1, sticky="nsew", padx=(9, 0))
        self.coverage_text = tk.Text(
            coverage,
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            relief="flat",
            bd=0,
            wrap="word",
            font=("Segoe UI", 10),
            padx=14,
            pady=4,
            cursor="arrow",
        )
        self.coverage_text.pack(fill="both", expand=True)
        self._set_text(
            self.coverage_text,
            "• Process and endpoint monitor is starting.\n\n"
            "• Files remain on this PC. AMSI requests follow the installed provider's policy.\n\n"
            "• No packet capture, driver, automatic deletion, or Defender changes.",
        )

    def _build_processes(self) -> None:
        page = self._new_page("Processes")
        tools = self._toolbar(page)
        tk.Label(tools, text="Search", bg=COLORS["surface"], fg=COLORS["muted"], font=("Segoe UI", 9)).pack(side="left", padx=(12, 6))
        self.process_search = tk.StringVar()
        entry = self._entry(tools, self.process_search, 28)
        entry.pack(side="left", pady=10)
        self.process_search.trace_add("write", lambda *_: self._refresh_processes())
        tk.Label(tools, text="Risk", bg=COLORS["surface"], fg=COLORS["muted"], font=("Segoe UI", 9)).pack(side="left", padx=(18, 6))
        self.process_risk_filter = tk.StringVar(value="All")
        combo = ttk.Combobox(tools, textvariable=self.process_risk_filter, values=("All", "New", "Medium+", "High+"), state="readonly", width=11)
        combo.pack(side="left")
        combo.bind("<<ComboboxSelected>>", lambda _: self._refresh_processes())
        self.process_count_label = tk.Label(tools, text="Waiting for snapshot", bg=COLORS["surface"], fg=COLORS["muted"], font=("Segoe UI", 9))
        self.process_count_label.pack(side="right", padx=14)

        panel = self._panel(page, "Process inventory", "Double-click a row to inspect risk evidence and path")
        panel.pack(fill="both", expand=True, pady=(14, 0))
        self.process_tree = self._tree(
            panel,
            ("pid", "name", "risk", "new", "trust", "cpu", "memory", "threads", "path"),
            {"pid": 68, "name": 180, "risk": 78, "new": 58, "trust": 94, "cpu": 68, "memory": 85, "threads": 70, "path": 460},
        )
        self.process_tree.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.process_tree.bind("<Double-1>", self._show_process_details)

    def _build_network(self) -> None:
        page = self._new_page("Network")
        tools = self._toolbar(page)
        tk.Label(tools, text="Search app / address", bg=COLORS["surface"], fg=COLORS["muted"], font=("Segoe UI", 9)).pack(side="left", padx=(12, 6))
        self.network_search = tk.StringVar()
        entry = self._entry(tools, self.network_search, 34)
        entry.pack(side="left", pady=10)
        self.network_search.trace_add("write", lambda *_: self._refresh_network())
        self.network_count_label = tk.Label(tools, text="Waiting for snapshot", bg=COLORS["surface"], fg=COLORS["muted"], font=("Segoe UI", 9))
        self.network_count_label.pack(side="right", padx=14)
        panel = self._panel(
            page,
            "Live application network activity",
            "Actual TCP bytes and rates since tracking began, plus the destination behind each connection",
        )
        panel.pack(fill="both", expand=True, pady=(14, 0))
        self.network_tree = self._tree(
            panel,
            (
                "app",
                "pid",
                "download",
                "upload",
                "received",
                "sent",
                "destination",
                "reputation",
                "protocol",
                "state",
                "local",
                "path",
            ),
            {
                "app": 155,
                "pid": 62,
                "download": 90,
                "upload": 90,
                "received": 92,
                "sent": 92,
                "destination": 310,
                "reputation": 100,
                "protocol": 72,
                "state": 95,
                "local": 180,
                "path": 330,
            },
        )
        self.network_tree.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.network_tree.bind("<Double-1>", self._show_network_details)

    def _build_scanner(self) -> None:
        page = self._new_page("Scanner")
        selector = self._panel(page, "Scan a file or folder", "Local rules plus the installed Windows AMSI provider; no OpenGuard uploads")
        selector.pack(fill="x")
        row = tk.Frame(selector, bg=COLORS["surface"])
        row.pack(fill="x", padx=14, pady=(0, 10))
        self.scan_target = tk.StringVar()
        self.scan_entry = self._entry(row, self.scan_target, 60)
        self.scan_entry.pack(side="left", fill="x", expand=True, ipady=3)
        self._button(row, "Choose file", self._choose_file).pack(side="left", padx=(8, 0))
        self._button(row, "Choose folder", self._choose_folder).pack(side="left", padx=(8, 0))
        self.scan_button = self._button(row, "Start scan", self._start_scan, accent=True)
        self.scan_button.pack(side="left", padx=(8, 0))
        self.cancel_button = self._button(row, "Cancel", self._cancel_scan)
        self.cancel_button.configure(state="disabled")
        self.cancel_button.pack(side="left", padx=(8, 0))
        profiles = tk.Frame(selector, bg=COLORS["surface"])
        profiles.pack(fill="x", padx=14, pady=(0, 10))
        tk.Label(profiles, text="Profiles", bg=COLORS["surface"], fg=COLORS["muted"], font=("Segoe UI", 9)).pack(side="left", padx=(0, 7))
        for profile in ScanProfile:
            self._button(
                profiles,
                profile.value.title(),
                lambda selected=profile: self._start_profile(selected),
            ).pack(side="left", padx=(0, 6))
        status = tk.Frame(selector, bg=COLORS["surface"])
        status.pack(fill="x", padx=14, pady=(0, 14))
        self.scan_progress = ttk.Progressbar(status, style="OpenGuard.Horizontal.TProgressbar", mode="determinate")
        self.scan_progress.pack(side="left", fill="x", expand=True)
        self.scan_status = tk.Label(status, text="Ready", bg=COLORS["surface"], fg=COLORS["muted"], width=42, anchor="e", font=("Segoe UI", 9))
        self.scan_status.pack(side="right", padx=(12, 0))

        results = self._panel(page, "Scan results", "Select a suspicious or malicious result to enable quarantine")
        results.pack(fill="both", expand=True, pady=(14, 0))
        action_row = tk.Frame(results, bg=COLORS["surface"])
        action_row.pack(fill="x", padx=14, pady=(0, 9))
        self.quarantine_button = self._button(action_row, "Quarantine selected", self._quarantine_selected)
        self.quarantine_button.configure(state="disabled")
        self.quarantine_button.pack(side="right")
        self.allow_button = self._button(action_row, "Allow selected hash", self._allow_selected)
        self.allow_button.configure(state="disabled")
        self.allow_button.pack(side="right", padx=(0, 8))
        self.scan_tree = self._tree(
            results,
            ("verdict", "score", "yara_x", "amsi", "signature", "size", "file"),
            {"verdict": 100, "score": 62, "yara_x": 110, "amsi": 110, "signature": 100, "size": 80, "file": 560},
        )
        self.scan_tree.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.scan_tree.bind("<<TreeviewSelect>>", lambda _: self._update_quarantine_state())
        self.scan_tree.bind("<Double-1>", self._show_scan_details)

    def _build_security(self) -> None:
        page = self._new_page("Security")
        notebook = ttk.Notebook(page)
        notebook.pack(fill="both", expand=True)

        status_tab = tk.Frame(notebook, bg=COLORS["bg"])
        quarantine_tab = tk.Frame(notebook, bg=COLORS["bg"])
        controls_tab = tk.Frame(notebook, bg=COLORS["bg"])
        notebook.add(status_tab, text="  Status & updates  ")
        notebook.add(quarantine_tab, text="  Quarantine  ")
        notebook.add(controls_tab, text="  Allow-list & exclusions  ")

        status_panel = self._panel(status_tab, "Protection components", "YARA-X, signed content, service, ETW, and WFP health")
        status_panel.pack(fill="both", expand=True, padx=4, pady=4)
        status_actions = tk.Frame(status_panel, bg=COLORS["surface"])
        status_actions.pack(fill="x", padx=14, pady=(0, 8))
        self._button(status_actions, "Refresh", self._refresh_security).pack(side="left")
        self._button(status_actions, "Install signed update", self._install_security_update).pack(side="left", padx=8)
        self._button(status_actions, "Roll back content", self._rollback_security_update).pack(side="left")
        self.security_status_text = tk.Text(
            status_panel, bg=COLORS["surface_alt"], fg=COLORS["text"], relief="flat",
            wrap="word", font=("Consolas", 10), padx=14, pady=12, height=18,
        )
        self.security_status_text.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        quarantine_panel = self._panel(quarantine_tab, "Recoverable quarantine", "Restore verifies the stored SHA-256 and refuses destination collisions")
        quarantine_panel.pack(fill="both", expand=True, padx=4, pady=4)
        quarantine_actions = tk.Frame(quarantine_panel, bg=COLORS["surface"])
        quarantine_actions.pack(fill="x", padx=14, pady=(0, 8))
        self._button(quarantine_actions, "Refresh", self._refresh_security).pack(side="left")
        self._button(quarantine_actions, "Restore selected", self._restore_selected_quarantine, accent=True).pack(side="left", padx=8)
        self.security_quarantine_tree = self._tree(
            quarantine_panel,
            ("id", "created", "original_path", "reason"),
            {"id": 160, "created": 145, "original_path": 440, "reason": 430},
        )
        self.security_quarantine_tree.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        exclusion_panel = self._panel(controls_tab, "Path exclusions", "User-created exclusions are visible, local, and removable")
        exclusion_panel.pack(fill="both", expand=True, padx=4, pady=(4, 7))
        exclusion_actions = tk.Frame(exclusion_panel, bg=COLORS["surface"])
        exclusion_actions.pack(fill="x", padx=14, pady=(0, 8))
        self._button(exclusion_actions, "Add folder", self._add_exclusion).pack(side="left")
        self._button(exclusion_actions, "Remove selected", self._remove_selected_exclusion).pack(side="left", padx=8)
        self.exclusion_tree = self._tree(exclusion_panel, ("path", "recursive", "created"), {"path": 650, "recursive": 100, "created": 180})
        self.exclusion_tree.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        allow_panel = self._panel(controls_tab, "SHA-256 allow-list", "Allow-list entries skip detection only for the exact file hash")
        allow_panel.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        allow_actions = tk.Frame(allow_panel, bg=COLORS["surface"])
        allow_actions.pack(fill="x", padx=14, pady=(0, 8))
        self._button(allow_actions, "Remove selected", self._remove_selected_allowed_hash).pack(side="left")
        self.allow_tree = self._tree(allow_panel, ("sha256", "label", "created"), {"sha256": 520, "label": 260, "created": 180})
        self.allow_tree.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        self._refresh_security()

    def _build_alerts(self) -> None:
        page = self._new_page("Alerts")
        tools = self._toolbar(page)
        self._button(tools, "Refresh", self._refresh_alerts).pack(side="right", padx=10, pady=8)
        self._button(tools, "Mark selected resolved", self._resolve_selected_alerts).pack(side="right", pady=8)
        panel = self._panel(page, "Local alert history", "Findings remain on this PC in the OpenGuard SQLite database")
        panel.pack(fill="both", expand=True, pady=(14, 0))
        self.alert_tree = self._tree(
            panel,
            ("time", "severity", "type", "title", "detail", "status"),
            {"time": 145, "severity": 78, "type": 120, "title": 260, "detail": 470, "status": 78},
        )
        self.alert_tree.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    def _build_about(self) -> None:
        page = self._new_page("About")
        panel = self._panel(page, f"{APP_NAME} {VERSION}", "Transparent Windows activity monitoring and local security scanning")
        panel.pack(fill="both", expand=True)
        body = tk.Text(
            panel,
            bg=COLORS["surface"],
            fg=COLORS["text"],
            relief="flat",
            bd=0,
            wrap="word",
            font=("Segoe UI", 11),
            padx=22,
            pady=10,
            cursor="arrow",
        )
        body.pack(fill="both", expand=True)
        self._set_text(
            body,
            "OpenGuard 0.2 is an open-source alpha security companion. It is useful today for "
            "process inventory, unseen executable alerts, app-owned TCP/UDP endpoint visibility, "
            "YARA-X and AMSI scanning, signed security-content updates, recovery quarantine, "
            "scan profiles, ETW-triggered refreshes, local reputation context, and audit history.\n\n"
            "What it does not claim\n\n"
            "• It does not replace Microsoft Defender or a mature endpoint antivirus.\n"
            "• It does not inspect packet contents, decrypt TLS, or provide UDP byte totals. TCP counters begin when the service enables tracking.\n"
            "• ETW requires administrator/service access; polling remains the safe fallback.\n"
            "• It cannot inspect protected process memory or defend against a local administrator/kernel attacker.\n"
            "• It never disables Defender, adds exclusions, auto-deletes files, or installs a driver.\n\n"
            "Privacy\n\n"
            "OpenGuard contains no telemetry or file-upload client. AMSI checks are handled by the "
            "antimalware provider installed on Windows and follow that provider's cloud settings.\n\n"
            f"Local data: {data_root()}\n\n"
            "Architecture\n\n"
            "The background service, ETW helper, and read-only WFP subscription use documented Windows APIs. "
            "No network filter or kernel driver is installed. Signed rule/reputation updates are verified "
            "before atomic activation and preserve a last-known-good rollback.\n\n"
            "License: MIT",
        )

    def _panel(self, parent: tk.Misc, title: str, subtitle: str) -> tk.Frame:
        frame = tk.Frame(parent, bg=COLORS["surface"], highlightbackground=COLORS["border"], highlightthickness=1)
        heading = tk.Frame(frame, bg=COLORS["surface"])
        heading.pack(fill="x", padx=14, pady=(13, 10))
        tk.Label(heading, text=title, bg=COLORS["surface"], fg=COLORS["text"], font=("Segoe UI Semibold", 12)).pack(anchor="w")
        tk.Label(heading, text=subtitle, bg=COLORS["surface"], fg=COLORS["muted"], font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))
        return frame

    def _toolbar(self, parent: tk.Misc) -> tk.Frame:
        frame = tk.Frame(parent, bg=COLORS["surface"], highlightbackground=COLORS["border"], highlightthickness=1)
        frame.pack(fill="x")
        return frame

    def _entry(self, parent: tk.Misc, variable: tk.StringVar, width: int) -> tk.Entry:
        return tk.Entry(
            parent,
            textvariable=variable,
            width=width,
            bg=COLORS["surface_alt"],
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="flat",
            bd=0,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            font=("Segoe UI", 10),
        )

    def _button(self, parent: tk.Misc, text: str, command: object, accent: bool = False) -> tk.Button:
        background = COLORS["accent"] if accent else COLORS["surface_alt"]
        foreground = COLORS["bg"] if accent else COLORS["text"]
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=background,
            fg=foreground,
            activebackground=COLORS["blue"] if accent else COLORS["border"],
            activeforeground=COLORS["bg"] if accent else COLORS["text"],
            disabledforeground=COLORS["muted"],
            relief="flat",
            bd=0,
            padx=13,
            pady=7,
            cursor="hand2",
            font=("Segoe UI Semibold", 9),
        )

    def _tree(self, parent: tk.Misc, columns: tuple[str, ...], widths: dict[str, int]) -> ttk.Treeview:
        wrapper = tk.Frame(parent, bg=COLORS["surface"])
        tree = ttk.Treeview(wrapper, columns=columns, show="headings", selectmode="extended")
        scrollbar = ttk.Scrollbar(
            wrapper,
            orient="vertical",
            style="OpenGuard.Vertical.TScrollbar",
            command=tree.yview,
        )
        horizontal = ttk.Scrollbar(
            wrapper,
            orient="horizontal",
            style="OpenGuard.Horizontal.TScrollbar",
            command=tree.xview,
        )
        tree.configure(yscrollcommand=scrollbar.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        wrapper.grid_rowconfigure(0, weight=1)
        wrapper.grid_columnconfigure(0, weight=1)
        for column in columns:
            tree.heading(column, text=column.replace("_", " ").title())
            tree.column(column, width=widths.get(column, 120), minwidth=45, stretch=column in {"path", "file", "detail", "title"})
        tree.tag_configure("info", foreground=COLORS["text"])
        tree.tag_configure("low", foreground=COLORS["yellow"])
        tree.tag_configure("medium", foreground=COLORS["orange"])
        tree.tag_configure("high", foreground=COLORS["red"])
        tree.tag_configure("critical", foreground=COLORS["red"])
        tree.tag_configure("clean", foreground=COLORS["accent"])
        tree._wrapper = wrapper  # type: ignore[attr-defined]
        original_pack = tree.pack

        def pack_proxy(*args: object, **kwargs: object) -> object:
            return wrapper.pack(*args, **kwargs)

        tree.pack = pack_proxy  # type: ignore[method-assign]
        tree._original_pack = original_pack  # type: ignore[attr-defined]
        return tree

    def show_page(self, name: str) -> None:
        self.current_page = name
        self.pages[name].tkraise()
        self.page_title.configure(text=name)
        subtitles = {
            "Overview": "A readable view of security-relevant activity on this PC",
            "Processes": "Running apps, trust checks, resource use, and explainable risk",
            "Network": "Live TCP usage, owning processes, and remote destinations",
            "Scanner": "Inspect local files and folders without OpenGuard uploads",
            "Security": "Manage signed content, quarantine recovery, allow-listing, and exclusions",
            "Alerts": "Review and resolve the local security event history",
            "About": "Coverage, privacy, limitations, and the production roadmap",
        }
        self.page_subtitle.configure(text=subtitles[name])
        for page in self.nav_widgets:
            self._set_nav_selected(page, page == name)
        if name == "Processes":
            self._refresh_processes()
        elif name == "Network":
            self._refresh_network()
        elif name == "Security":
            self._refresh_security()
        elif name == "Alerts":
            self._refresh_alerts()

    def _post(self, kind: str, payload: object) -> None:
        try:
            self.messages.put_nowait((kind, payload))
        except queue.Full:
            if kind == "snapshot":
                try:
                    self.messages.get_nowait()
                    self.messages.put_nowait((kind, payload))
                except (queue.Empty, queue.Full):
                    pass

    def _drain_messages(self) -> None:
        try:
            while True:
                kind, payload = self.messages.get_nowait()
                if kind == "snapshot" and isinstance(payload, SystemSnapshot):
                    self._apply_snapshot(payload)
                elif kind == "event" and isinstance(payload, SecurityEvent):
                    self._apply_event(payload)
                elif kind == "error" and isinstance(payload, Exception):
                    self._apply_error(payload)
                elif kind == "scan_progress" and isinstance(payload, tuple):
                    self._apply_scan_progress(*payload)
                elif kind == "scan_result" and isinstance(payload, ScanFinding):
                    self._append_scan_result(payload)
                elif kind == "scan_done" and isinstance(payload, tuple):
                    self._finish_scan(*payload)
                elif kind == "security_done" and isinstance(payload, tuple):
                    self._finish_security_action(*payload)
                elif kind == "security_refresh" and isinstance(payload, SecurityPageSnapshot):
                    self._apply_security_snapshot(payload)
        except queue.Empty:
            pass
        if self.root.winfo_exists():
            self.root.after(120, self._drain_messages)

    def _apply_snapshot(self, snapshot: SystemSnapshot) -> None:
        self.latest_snapshot = snapshot
        new_count = sum(1 for process in snapshot.processes if process.is_new)
        self.metric_values["processes"].configure(text=f"{len(snapshot.processes):,}")
        self.metric_values["endpoints"].configure(text=f"{len(snapshot.endpoints):,}")
        self.metric_values["new"].configure(text=f"{new_count:,}")
        self.metric_values["alerts"].configure(text=f"{self.database.unresolved_high_count():,}")
        self.header_status.configure(text=f"MONITOR ACTIVE  •  {snapshot.captured_at[11:19]}")
        self.sidebar_status.configure(text="●  Monitor active", fg=COLORS["accent"])
        self.sidebar_scope.configure(text="Elevated coverage" if snapshot.elevated else "User-mode coverage")
        notes = "\n\n".join(f"• {note}" for note in snapshot.coverage_notes)
        self._set_text(self.coverage_text, notes)
        self._refresh_overview_alerts()
        if self.current_page == "Processes":
            self._refresh_processes()
        if self.current_page == "Network":
            self._refresh_network()

    def _apply_event(self, event: SecurityEvent) -> None:
        if event.severity in {Severity.HIGH, Severity.CRITICAL}:
            self.root.bell()
            self.header_status.configure(text=f"ALERT  •  {event.title}", bg="#4b2030", fg=COLORS["red"])
        self._refresh_overview_alerts()
        if self.current_page == "Alerts":
            self._refresh_alerts()

    def _apply_error(self, error: Exception) -> None:
        self.sidebar_status.configure(text="●  Monitor degraded", fg=COLORS["red"])
        self.header_status.configure(text="MONITOR ERROR", bg="#4b2030", fg=COLORS["red"])
        self.sidebar_scope.configure(text=f"{type(error).__name__}: {error}")

    def _refresh_processes(self) -> None:
        if not hasattr(self, "process_tree"):
            return
        self.process_tree.delete(*self.process_tree.get_children())
        if self.latest_snapshot is None:
            return
        needle = self.process_search.get().strip().casefold()
        filter_value = self.process_risk_filter.get()
        shown = 0
        for process in self.latest_snapshot.processes:
            searchable = f"{process.name} {process.path} {process.pid}".casefold()
            if needle and needle not in searchable:
                continue
            if filter_value == "New" and not process.is_new:
                continue
            if filter_value == "Medium+" and process.risk.score < 35:
                continue
            if filter_value == "High+" and process.risk.score < 65:
                continue
            memory = f"{process.working_set_bytes / (1024**2):.1f} MB" if process.working_set_bytes else "—"
            self.process_tree.insert(
                "",
                "end",
                iid=str(process.pid),
                values=(
                    process.pid,
                    process.name,
                    process.risk.score,
                    "NEW" if process.is_new else "",
                    str(process.signature).replace("_", " ").title(),
                    f"{process.cpu_percent:.1f}%",
                    memory,
                    process.thread_count,
                    process.path or "Access limited",
                ),
                tags=(str(process.risk.severity),),
            )
            shown += 1
        self.process_count_label.configure(text=f"Showing {shown:,} of {len(self.latest_snapshot.processes):,}")

    def _refresh_network(self) -> None:
        if not hasattr(self, "network_tree"):
            return
        self.network_tree.delete(*self.network_tree.get_children())
        if self.latest_snapshot is None:
            return
        needle = self.network_search.get().strip().casefold()
        shown = 0
        active_usage = 0
        self._network_rows: dict[str, NetworkEndpoint] = {}
        endpoints = sorted(
            self.latest_snapshot.endpoints,
            key=lambda item: (
                -((item.receive_rate_bps or 0.0) + (item.send_rate_bps or 0.0)),
                item.process_name.casefold(),
                item.pid,
            ),
        )
        for index, endpoint in enumerate(endpoints):
            local = _endpoint_text(endpoint.local_address, endpoint.local_port)
            remote = _endpoint_text(endpoint.remote_address, endpoint.remote_port)
            destination = _destination_text(endpoint)
            searchable = f"{endpoint.process_name} {endpoint.process_path} {local} {remote} {destination} {endpoint.remote_hostname} {endpoint.reputation} {endpoint.pid}".casefold()
            if needle and needle not in searchable:
                continue
            if endpoint.usage_status == "active":
                active_usage += 1
            self.network_tree.insert(
                "",
                "end",
                iid=f"net-{index}",
                values=(
                    endpoint.process_name or "Unknown / exited",
                    endpoint.pid,
                    _format_rate(endpoint.receive_rate_bps, endpoint.usage_status),
                    _format_rate(endpoint.send_rate_bps, endpoint.usage_status),
                    _format_optional_bytes(endpoint.bytes_received),
                    _format_optional_bytes(endpoint.bytes_sent),
                    destination,
                    endpoint.reputation.title(),
                    endpoint.protocol,
                    endpoint.state,
                    local,
                    endpoint.process_path,
                ),
                tags=("critical" if endpoint.reputation == "malicious" else "high" if endpoint.reputation == "suspicious" else "info",),
            )
            self._network_rows[f"net-{index}"] = endpoint
            shown += 1
        usage_note = f" • {active_usage:,} TCP connections metered" if active_usage else " • TCP usage warming / service required"
        self.network_count_label.configure(
            text=f"Showing {shown:,} of {len(self.latest_snapshot.endpoints):,}{usage_note}"
        )

    def _show_network_details(self, _: object) -> None:
        selected = self.network_tree.selection()
        if not selected:
            return
        endpoint = getattr(self, "_network_rows", {}).get(selected[0])
        if endpoint is None:
            return
        messagebox.showinfo(
            "Network connection details",
            f"Application: {endpoint.process_name or 'Unknown / exited'} (PID {endpoint.pid})\n"
            f"Executable: {endpoint.process_path or 'Access limited'}\n\n"
            f"Destination: {_destination_text(endpoint)}\n"
            f"Local endpoint: {_endpoint_text(endpoint.local_address, endpoint.local_port)}\n"
            f"Protocol / state: {endpoint.protocol} / {endpoint.state}\n"
            f"Reputation: {endpoint.reputation.title()}"
            f"{(' — ' + endpoint.reputation_reason) if endpoint.reputation_reason else ''}\n\n"
            f"Download: {_format_rate(endpoint.receive_rate_bps, endpoint.usage_status)} "
            f"({_format_optional_bytes(endpoint.bytes_received)} observed)\n"
            f"Upload: {_format_rate(endpoint.send_rate_bps, endpoint.usage_status)} "
            f"({_format_optional_bytes(endpoint.bytes_sent)} observed)\n\n"
            "These are connection metadata and TCP byte counters. HTTPS content is encrypted, so this view can "
            "highlight an unfamiliar destination or upload spike but cannot prove that a session cookie was stolen.",
            parent=self.root,
        )

    def _refresh_overview_alerts(self) -> None:
        self.overview_alerts.delete(*self.overview_alerts.get_children())
        for event in self.database.recent_events(8):
            self.overview_alerts.insert(
                "",
                "end",
                values=(event["created_at"].replace("T", " ")[:19], event["severity"].title(), event["title"], event["detail"]),
                tags=(event["severity"],),
            )

    def _refresh_alerts(self) -> None:
        self.alert_tree.delete(*self.alert_tree.get_children())
        for event in self.database.recent_events(500):
            self.alert_tree.insert(
                "",
                "end",
                iid=str(event["id"]),
                values=(
                    event["created_at"].replace("T", " ")[:19],
                    event["severity"].title(),
                    event["event_type"].replace("_", " ").title(),
                    event["title"],
                    event["detail"],
                    "Resolved" if event["resolved"] else "Open",
                ),
                tags=(event["severity"],),
            )

    def _resolve_selected_alerts(self) -> None:
        selected = [int(item) for item in self.alert_tree.selection()]
        if not selected:
            return
        self.database.resolve_events(selected)
        self._refresh_alerts()
        self._refresh_overview_alerts()

    def _show_process_details(self, _: object) -> None:
        selected = self.process_tree.selection()
        if not selected or self.latest_snapshot is None:
            return
        pid = int(selected[0])
        process = next((item for item in self.latest_snapshot.processes if item.pid == pid), None)
        if process is None:
            return
        evidence = "\n".join(f"• {reason}" for reason in process.risk.reasons) or "• No elevated risk signal matched"
        messagebox.showinfo(
            f"{process.name} — PID {process.pid}",
            f"Risk: {process.risk.score}/100 ({process.risk.severity})\n"
            f"Signature: {process.signature}\n"
            f"Parent PID: {process.parent_pid}\n"
            f"Path: {process.path or 'Windows denied access'}\n\nEvidence\n{evidence}",
            parent=self.root,
        )

    def _choose_file(self) -> None:
        selected = filedialog.askopenfilename(parent=self.root, title="Choose a file to scan")
        if selected:
            self.scan_target.set(selected)

    def _choose_folder(self) -> None:
        selected = filedialog.askdirectory(parent=self.root, title="Choose a folder to scan")
        if selected:
            self.scan_target.set(selected)

    def _start_scan(self) -> None:
        if self.scan_running:
            return
        target = self.scan_target.get().strip().strip('"')
        if not target:
            messagebox.showwarning("Choose a target", "Select a file or folder first.", parent=self.root)
            return
        if not Path(target).exists():
            messagebox.showerror("Target not found", f"The selected path does not exist:\n{target}", parent=self.root)
            return
        self.scan_running = True
        self.scan_cancel.clear()
        self.scan_findings.clear()
        self.scan_tree.delete(*self.scan_tree.get_children())
        self.scan_progress.configure(value=0, maximum=100)
        self.scan_status.configure(text="Preparing scan…")
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        thread = threading.Thread(target=self._scan_worker, args=(target,), name="OpenGuardScanner", daemon=True)
        thread.start()

    def _start_profile(self, profile: ScanProfile) -> None:
        if self.scan_running:
            return
        self.scan_running = True
        self.scan_cancel.clear()
        self.scan_findings.clear()
        self.scan_tree.delete(*self.scan_tree.get_children())
        self.scan_progress.configure(value=0, maximum=100)
        self.scan_status.configure(text=f"Preparing {profile.value} scan…")
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        thread = threading.Thread(
            target=self._scan_profile_worker,
            args=(profile,),
            name=f"OpenGuard-{profile.value}-scan",
            daemon=True,
        )
        thread.start()

    def _scan_worker(self, target: str) -> None:
        try:
            results = self.scanner.scan_path(
                target,
                cancel=self.scan_cancel,
                progress=lambda current, total, path: self._post("scan_progress", (current, total, path)),
                on_result=lambda finding: self._post("scan_result", finding),
            )
            self._post("scan_done", (results, self.scan_cancel.is_set(), None))
        except Exception as error:
            self._post("scan_done", ([], False, error))

    def _scan_profile_worker(self, profile: ScanProfile) -> None:
        try:
            results = self.scanner.scan_profile(
                profile,
                cancel=self.scan_cancel,
                progress=lambda current, total, path: self._post("scan_progress", (current, total, path)),
                on_result=lambda finding: self._post("scan_result", finding),
            )
            self._post("scan_done", (results, self.scan_cancel.is_set(), None))
        except Exception as error:
            self._post("scan_done", ([], False, error))

    def _cancel_scan(self) -> None:
        self.scan_cancel.set()
        self.scan_status.configure(text="Cancelling safely…")

    def _apply_scan_progress(self, current: int, total: int, path: str) -> None:
        percent = (current / total * 100) if total else 0
        self.scan_progress.configure(value=percent)
        name = Path(path).name if path else "Finishing"
        self.scan_status.configure(text=f"{current:,}/{total:,}  •  {name}")

    def _append_scan_result(self, finding: ScanFinding) -> None:
        index = len(self.scan_findings)
        self.scan_findings.append(finding)
        tag = {
            ScanVerdict.CLEAN: "clean",
            ScanVerdict.LOW_RISK: "low",
            ScanVerdict.SUSPICIOUS: "high",
            ScanVerdict.MALICIOUS: "critical",
            ScanVerdict.ERROR: "medium",
        }.get(finding.verdict, "info")
        self.scan_tree.insert(
            "",
            "end",
            iid=f"scan-{index}",
            values=(
                str(finding.verdict).replace("_", " ").title(),
                finding.score,
                ", ".join(finding.yara_matches) if finding.yara_matches else finding.yara_status.title(),
                finding.amsi_result.replace("_", " ").title(),
                str(finding.signature).replace("_", " ").title(),
                _format_bytes(finding.size_bytes),
                finding.path,
            ),
            tags=(tag,),
        )

    def _finish_scan(self, results: list[ScanFinding], cancelled: bool, error: Exception | None) -> None:
        self.scan_running = False
        self.scan_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        if error:
            self.scan_status.configure(text=f"Scan failed: {error}")
            messagebox.showerror("Scan failed", str(error), parent=self.root)
            return
        detections = sum(item.verdict in {ScanVerdict.SUSPICIOUS, ScanVerdict.MALICIOUS} for item in results)
        self.scan_status.configure(text=f"{'Cancelled' if cancelled else 'Complete'}  •  {len(results):,} files  •  {detections} detections")
        self.scan_progress.configure(value=100 if not cancelled else self.scan_progress["value"])
        self._refresh_overview_alerts()

    def _update_quarantine_state(self) -> None:
        finding = self._selected_finding()
        enabled = finding is not None and finding.verdict in {ScanVerdict.SUSPICIOUS, ScanVerdict.MALICIOUS} and Path(finding.path).is_file()
        self.quarantine_button.configure(state="normal" if enabled else "disabled")
        allow_enabled = finding is not None and bool(finding.sha256)
        self.allow_button.configure(state="normal" if allow_enabled else "disabled")

    def _selected_finding(self) -> ScanFinding | None:
        selected = self.scan_tree.selection()
        if not selected:
            return None
        try:
            index = int(selected[0].split("-", 1)[1])
            return self.scan_findings[index]
        except (IndexError, ValueError):
            return None

    def _show_scan_details(self, _: object) -> None:
        finding = self._selected_finding()
        if finding is None:
            return
        evidence = "\n".join(f"• {reason}" for reason in finding.reasons)
        messagebox.showinfo(
            f"Scan result — {Path(finding.path).name}",
            f"Verdict: {finding.verdict}\nScore: {finding.score}/100\n"
            f"SHA-256: {finding.sha256 or 'Unavailable'}\nSignature: {finding.signature}\n"
            f"AMSI: {finding.amsi_result}\nYARA-X: {finding.yara_status}"
            f" ({', '.join(finding.yara_matches) or 'no match'})\n\nEvidence\n{evidence}",
            parent=self.root,
        )

    def _quarantine_selected(self) -> None:
        finding = self._selected_finding()
        if finding is None:
            return
        confirmed = messagebox.askyesno(
            "Quarantine file?",
            "OpenGuard will move this file into your per-user quarantine and record its original path. "
            "The file will no longer be available at its current location. Continue?",
            icon="warning",
            parent=self.root,
        )
        if not confirmed:
            return
        try:
            destination = self.scanner.quarantine(finding)
            messagebox.showinfo("File quarantined", f"Stored at:\n{destination}", parent=self.root)
            self._update_quarantine_state()
        except Exception as error:
            messagebox.showerror("Quarantine failed", str(error), parent=self.root)

    def _allow_selected(self) -> None:
        finding = self._selected_finding()
        if finding is None or not finding.sha256:
            return
        confirmed = messagebox.askyesno(
            "Allow exact file hash?",
            "Future scans will skip detections only when the SHA-256 is exactly the same. "
            "Changed files will not be allowed. Continue?",
            parent=self.root,
        )
        if not confirmed:
            return
        try:
            self.scanner.allow_finding(finding)
            self._refresh_security()
            messagebox.showinfo("Hash allowed", finding.sha256, parent=self.root)
        except Exception as error:
            messagebox.showerror("Allow-list failed", str(error), parent=self.root)

    def _refresh_security(self) -> None:
        if not hasattr(self, "security_status_text"):
            return
        if self.security_refresh_running:
            self.security_refresh_pending = True
            return
        self.security_refresh_running = True
        if not getattr(self, "_security_snapshot_loaded", False):
            self._set_text(
                self.security_status_text,
                "Refreshing protection status…\n\nYou can keep using OpenGuard while this loads.",
            )
        threading.Thread(
            target=self._security_refresh_worker,
            name="OpenGuardSecurityRefresh",
            daemon=True,
        ).start()

    def _security_refresh_worker(self) -> None:
        try:
            content = SecurityContentUpdater().state()
            service = service_action("status")
            monitor = getattr(self, "monitor", None)
            etw_status = monitor.process_events.status if monitor else "starting"
            etw_detail = monitor.process_events.detail if monitor else ""
            wfp_status = monitor.wfp_monitor.status if monitor else "starting"
            wfp_detail = monitor.wfp_monitor.detail if monitor else ""
            if service["success"]:
                etw_status = self.database.get_metadata("service_etw_status", etw_status) or etw_status
                etw_detail = self.database.get_metadata("service_etw_detail", etw_detail) or etw_detail
                wfp_status = self.database.get_metadata("service_wfp_status", wfp_status) or wfp_status
                wfp_detail = self.database.get_metadata("service_wfp_detail", wfp_detail) or wfp_detail
            snapshot = SecurityPageSnapshot(
                content=dict(content),
                service=dict(service),
                yara_status=self.scanner.yara.status,
                yara_error=self.scanner.yara.error,
                etw_status=str(etw_status),
                etw_detail=str(etw_detail),
                wfp_status=str(wfp_status),
                wfp_detail=str(wfp_detail),
                quarantines=tuple(dict(item) for item in self.database.quarantines(active_only=True)),
                exclusions=tuple(dict(item) for item in self.database.exclusions()),
                allowed_hashes=tuple(dict(item) for item in self.database.allowed_hashes()),
            )
        except Exception as error:
            snapshot = SecurityPageSnapshot(
                content={},
                service={},
                yara_status="unknown",
                yara_error="",
                etw_status="unknown",
                etw_detail="",
                wfp_status="unknown",
                wfp_detail="",
                quarantines=(),
                exclusions=(),
                allowed_hashes=(),
                error=f"{type(error).__name__}: {error}",
            )
        self._post("security_refresh", snapshot)

    def _apply_security_snapshot(self, snapshot: SecurityPageSnapshot) -> None:
        self.security_refresh_running = False
        if snapshot.error:
            self._set_text(
                self.security_status_text,
                f"Protection status refresh failed\n\n{snapshot.error}",
            )
        else:
            self._security_snapshot_loaded = True
            content = snapshot.content
            service = snapshot.service
            status = (
                f"OpenGuard: {VERSION}\n"
                f"YARA-X: {snapshot.yara_status}"
                f"{(' — ' + snapshot.yara_error) if snapshot.yara_error else ''}\n"
                f"Security content: {content.get('active_version', 'built-in')}"
                f" (rollback: {content.get('previous_version') or 'none'})\n"
                f"Background service: {'installed' if service.get('success') else 'not installed'}\n"
                f"ETW process events: {snapshot.etw_status} {snapshot.etw_detail}\n"
                f"WFP net events: {snapshot.wfp_status} {snapshot.wfp_detail}\n\n"
                "OpenGuard never installs WFP filters or a kernel driver in this release. "
                "When ETW/WFP access is unavailable, the monitor keeps the documented polling/IP Helper fallback."
            )
            self._set_text(self.security_status_text, status)

            self.security_quarantine_tree.delete(*self.security_quarantine_tree.get_children())
            for item in snapshot.quarantines:
                self.security_quarantine_tree.insert(
                    "", "end", iid=str(item["id"]),
                    values=(item["id"], str(item["created_at"])[:19], item["original_path"], item["reason"]),
                )
            self._exclusions = list(snapshot.exclusions)
            self.exclusion_tree.delete(*self.exclusion_tree.get_children())
            for index, item in enumerate(self._exclusions):
                self.exclusion_tree.insert(
                    "", "end", iid=f"exclusion-{index}",
                    values=(item["path"], "Yes" if item["recursive"] else "No", str(item["created_at"])[:19]),
                )
            self._allowed_hashes = list(snapshot.allowed_hashes)
            self.allow_tree.delete(*self.allow_tree.get_children())
            for index, item in enumerate(self._allowed_hashes):
                self.allow_tree.insert(
                    "", "end", iid=f"allowed-{index}",
                    values=(item["sha256"], item["label"], str(item["created_at"])[:19]),
                )

        if self.security_refresh_pending:
            self.security_refresh_pending = False
            self.root.after_idle(self._refresh_security)

    def _install_security_update(self) -> None:
        url = simpledialog.askstring(
            "Install signed security content",
            "HTTPS URL of the OpenGuard signed manifest:",
            parent=self.root,
            initialvalue=DEFAULT_UPDATE_MANIFEST_URL,
        )
        if not url:
            return
        threading.Thread(
            target=self._security_update_worker,
            args=("install", url.strip()),
            name="OpenGuardContentUpdate",
            daemon=True,
        ).start()

    def _rollback_security_update(self) -> None:
        if not messagebox.askyesno("Roll back content?", "Activate the previous verified content version?", parent=self.root):
            return
        threading.Thread(
            target=self._security_update_worker,
            args=("rollback", ""),
            name="OpenGuardContentRollback",
            daemon=True,
        ).start()

    def _security_update_worker(self, action: str, url: str) -> None:
        try:
            updater = SecurityContentUpdater()
            version = updater.fetch_and_install(url) if action == "install" else updater.rollback()
            self._post("security_done", (True, f"Security content {version} is active"))
        except Exception as error:
            self._post("security_done", (False, f"{type(error).__name__}: {error}"))

    def _finish_security_action(self, success: bool, detail: str) -> None:
        if success:
            self.scanner.yara = YaraEngine()
            self._refresh_security()
            messagebox.showinfo("Security content", detail, parent=self.root)
        else:
            messagebox.showerror("Security content failed", detail, parent=self.root)

    def _restore_selected_quarantine(self) -> None:
        selected = self.security_quarantine_tree.selection()
        if not selected:
            return
        quarantine_id = selected[0]
        if not messagebox.askyesno(
            "Restore quarantined file?",
            "The original path must be free. OpenGuard will verify the stored SHA-256 before restoring.",
            parent=self.root,
        ):
            return
        try:
            destination = self.scanner.restore_quarantine(quarantine_id)
            self._refresh_security()
            messagebox.showinfo("File restored", str(destination), parent=self.root)
        except Exception as error:
            messagebox.showerror("Restore failed", str(error), parent=self.root)

    def _add_exclusion(self) -> None:
        selected = filedialog.askdirectory(parent=self.root, title="Choose a folder to exclude")
        if not selected:
            return
        if not messagebox.askyesno(
            "Add recursive exclusion?",
            "Excluded files are not scanned. Add this folder and all descendants?",
            icon="warning",
            parent=self.root,
        ):
            return
        self.database.add_exclusion(selected, True, utc_now())
        self._refresh_security()

    def _remove_selected_exclusion(self) -> None:
        selected = self.exclusion_tree.selection()
        if not selected:
            return
        index = int(selected[0].split("-", 1)[1])
        self.database.remove_exclusion(self._exclusions[index]["path"])
        self._refresh_security()

    def _remove_selected_allowed_hash(self) -> None:
        selected = self.allow_tree.selection()
        if not selected:
            return
        index = int(selected[0].split("-", 1)[1])
        self.database.remove_allowed_hash(self._allowed_hashes[index]["sha256"])
        self._refresh_security()

    def close(self) -> None:
        self.scan_cancel.set()
        if hasattr(self, "monitor"):
            self.monitor.stop(timeout=3.0)
        self.scanner.close()
        self.root.destroy()

    @staticmethod
    def _set_text(widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")


def _endpoint_text(address: str, port: int) -> str:
    if ":" in address and address != "*":
        return f"[{address}]:{port}" if port else f"[{address}]"
    return f"{address}:{port}" if port else address


def _destination_text(endpoint: NetworkEndpoint) -> str:
    remote = _endpoint_text(endpoint.remote_address, endpoint.remote_port)
    if endpoint.remote_address == "*":
        return "Per-datagram destination (UDP)"
    if endpoint.remote_hostname and endpoint.remote_hostname.casefold() != endpoint.remote_address.casefold():
        return f"{endpoint.remote_hostname}  •  {remote}"
    return remote


def _format_optional_bytes(value: int | None) -> str:
    return _format_bytes(value) if value is not None else "—"


def _format_rate(value: float | None, status: str) -> str:
    if value is not None:
        return f"{_format_bytes(int(value))}/s"
    return "Warming" if status == "active" else "—"


def _format_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    if value < 1024**2:
        return f"{value / 1024:.1f} KB"
    if value < 1024**3:
        return f"{value / (1024**2):.1f} MB"
    return f"{value / (1024**3):.1f} GB"


def run_ui(database: Database, native: WindowsNative) -> int:
    root = tk.Tk()
    OpenGuardUI(root, database, native)
    root.mainloop()
    return 0
