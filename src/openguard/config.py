"""Application constants and per-user paths."""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "OpenGuard"
VERSION = "0.2.0"
DATABASE_SCHEMA_VERSION = 2
MONITOR_INTERVAL_SECONDS = 2.0
MAX_CONTENT_INSPECTION_BYTES = 16 * 1024 * 1024
MAX_HASH_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_UPDATE_MANIFEST_URL = (
    "https://raw.githubusercontent.com/jordanw0204-rgb/OpenGuard/main/"
    "security-content/manifest.json"
)


def data_root() -> Path:
    """Return the writable per-user data directory without creating it."""
    override = os.environ.get("OPENGUARD_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    local_app_data = os.environ.get("LOCALAPPDATA")
    base = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
    return base / APP_NAME


def database_path() -> Path:
    return data_root() / "openguard.db"


def quarantine_root() -> Path:
    return data_root() / "quarantine"


def log_root() -> Path:
    return data_root() / "logs"


def security_content_root() -> Path:
    return data_root() / "security-content"


def active_content_path() -> Path:
    return security_content_root() / "active.json"
