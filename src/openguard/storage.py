"""Thread-safe-by-construction SQLite persistence.

Every public operation opens its own short-lived connection. This avoids
sharing sqlite3 connection objects across the monitor, scanner, and UI threads.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Iterable

from .config import DATABASE_SCHEMA_VERSION, database_path
from .models import ScanFinding, SecurityEvent, Severity


class Database:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else database_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS seen_executables (
                    identity TEXT PRIMARY KEY,
                    path TEXT NOT NULL,
                    name TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    risk_score INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_seen_path ON seen_executables(path);
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    process_id INTEGER,
                    path TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    resolved INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_events_created ON security_events(created_at DESC);
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    reasons_json TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    signature TEXT NOT NULL,
                    amsi_result TEXT NOT NULL,
                    yara_status TEXT NOT NULL DEFAULT 'not_scanned',
                    yara_matches_json TEXT NOT NULL DEFAULT '[]',
                    scanned_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_scans_time ON scan_results(scanned_at DESC);
                CREATE TABLE IF NOT EXISTS quarantines (
                    id TEXT PRIMARY KEY,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    restored_at TEXT
                );
                CREATE TABLE IF NOT EXISTS exclusions (
                    path_key TEXT PRIMARY KEY,
                    path TEXT NOT NULL,
                    recursive INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS hash_allowlist (
                    sha256 TEXT PRIMARY KEY,
                    label TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                """
            )
            scan_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(scan_results)").fetchall()
            }
            if "yara_status" not in scan_columns:
                connection.execute(
                    "ALTER TABLE scan_results ADD COLUMN yara_status TEXT NOT NULL DEFAULT 'not_scanned'"
                )
            if "yara_matches_json" not in scan_columns:
                connection.execute(
                    "ALTER TABLE scan_results ADD COLUMN yara_matches_json TEXT NOT NULL DEFAULT '[]'"
                )
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(DATABASE_SCHEMA_VERSION),),
            )

    def get_metadata(self, key: str, default: str | None = None) -> str | None:
        with self._connection() as connection:
            row = connection.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default

    def set_metadata(self, key: str, value: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def baseline_initialized(self) -> bool:
        return self.get_metadata("baseline_initialized", "0") == "1"

    def complete_baseline(self) -> None:
        self.set_metadata("baseline_initialized", "1")

    def reset_baseline(self) -> None:
        with self._connection() as connection:
            connection.execute("DELETE FROM seen_executables")
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES('baseline_initialized', '0') "
                "ON CONFLICT(key) DO UPDATE SET value='0'"
            )

    def has_seen_executable(self, identity: str) -> bool:
        if not identity:
            return True
        with self._connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM seen_executables WHERE identity = ?", (identity,)
            ).fetchone()
        return row is not None

    def known_executable_identities(self, identities: Iterable[str]) -> set[str]:
        unique = tuple(dict.fromkeys(item for item in identities if item))
        if not unique:
            return set()
        known: set[str] = set()
        # Keep each query comfortably below SQLite's parameter limit.
        with self._connection() as connection:
            for offset in range(0, len(unique), 500):
                chunk = unique[offset : offset + 500]
                placeholders = ",".join("?" for _ in chunk)
                rows = connection.execute(
                    f"SELECT identity FROM seen_executables WHERE identity IN ({placeholders})",
                    chunk,
                ).fetchall()
                known.update(str(row["identity"]) for row in rows)
        return known

    def record_executable(
        self,
        identity: str,
        path: str,
        name: str,
        signature: str,
        risk_score: int,
        observed_at: str,
    ) -> None:
        if not identity:
            return
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO seen_executables(
                    identity, path, name, first_seen, last_seen, signature, risk_score
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(identity) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    signature=excluded.signature,
                    risk_score=excluded.risk_score
                """,
                (identity, path, name, observed_at, observed_at, signature, risk_score),
            )

    def record_executables(
        self, rows: Iterable[tuple[str, str, str, str, int, str]]
    ) -> None:
        values = [row for row in rows if row[0]]
        if not values:
            return
        with self._connection() as connection:
            connection.executemany(
                """
                INSERT INTO seen_executables(
                    identity, path, name, first_seen, last_seen, signature, risk_score
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(identity) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    signature=excluded.signature,
                    risk_score=excluded.risk_score
                """,
                (
                    (identity, path, name, observed_at, observed_at, signature, risk_score)
                    for identity, path, name, signature, risk_score, observed_at in values
                ),
            )

    def record_event(self, event: SecurityEvent) -> int:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO security_events(
                    event_type, severity, title, detail, process_id, path, created_at, resolved
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_type,
                    str(event.severity),
                    event.title,
                    event.detail,
                    event.process_id,
                    event.path,
                    event.created_at,
                    int(event.resolved),
                ),
            )
            return int(cursor.lastrowid)

    def recent_events(self, limit: int = 200) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 2000))
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM security_events ORDER BY created_at DESC, id DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def unresolved_high_count(self) -> int:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS total FROM security_events "
                "WHERE resolved = 0 AND severity IN (?, ?)",
                (str(Severity.HIGH), str(Severity.CRITICAL)),
            ).fetchone()
        return int(row["total"] if row else 0)

    def resolve_events(self, event_ids: Iterable[int]) -> None:
        ids = tuple(int(item) for item in event_ids)
        if not ids:
            return
        placeholders = ",".join("?" for _ in ids)
        with self._connection() as connection:
            connection.execute(
                f"UPDATE security_events SET resolved = 1 WHERE id IN ({placeholders})", ids
            )

    def record_scan(self, finding: ScanFinding) -> int:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scan_results(
                    path, verdict, score, reasons_json, sha256, size_bytes,
                    signature, amsi_result, yara_status, yara_matches_json, scanned_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.path,
                    str(finding.verdict),
                    finding.score,
                    json.dumps(finding.reasons),
                    finding.sha256,
                    finding.size_bytes,
                    str(finding.signature),
                    finding.amsi_result,
                    finding.yara_status,
                    json.dumps(finding.yara_matches),
                    finding.scanned_at,
                ),
            )
            return int(cursor.lastrowid)

    def recent_scans(self, limit: int = 200) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 2000))
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM scan_results ORDER BY scanned_at DESC, id DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["reasons"] = json.loads(item.pop("reasons_json"))
            item["yara_matches"] = json.loads(item.pop("yara_matches_json", "[]"))
            results.append(item)
        return results

    def record_quarantine(
        self,
        quarantine_id: str,
        original_path: str,
        quarantine_path: str,
        sha256: str,
        reason: str,
        created_at: str,
    ) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO quarantines(
                    id, original_path, quarantine_path, sha256, reason, created_at
                ) VALUES(?, ?, ?, ?, ?, ?)
                """,
                (quarantine_id, original_path, quarantine_path, sha256, reason, created_at),
            )

    def quarantines(self, *, active_only: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM quarantines"
        if active_only:
            query += " WHERE restored_at IS NULL"
        query += " ORDER BY created_at DESC"
        with self._connection() as connection:
            rows = connection.execute(query).fetchall()
        return [dict(row) for row in rows]

    def quarantine_by_id(self, quarantine_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM quarantines WHERE id = ?", (quarantine_id,)
            ).fetchone()
        return dict(row) if row else None

    def mark_quarantine_restored(self, quarantine_id: str, restored_at: str) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE quarantines SET restored_at = ? WHERE id = ? AND restored_at IS NULL",
                (restored_at, quarantine_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Quarantine record is missing or already restored")

    def add_exclusion(self, path: str | Path, recursive: bool, created_at: str) -> None:
        resolved = str(Path(path).expanduser().resolve())
        key = _path_key(resolved)
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO exclusions(path_key, path, recursive, created_at) VALUES(?, ?, ?, ?) "
                "ON CONFLICT(path_key) DO UPDATE SET path=excluded.path, recursive=excluded.recursive",
                (key, resolved, int(recursive), created_at),
            )

    def remove_exclusion(self, path: str | Path) -> bool:
        key = _path_key(str(Path(path).expanduser().resolve()))
        with self._connection() as connection:
            cursor = connection.execute("DELETE FROM exclusions WHERE path_key = ?", (key,))
        return cursor.rowcount > 0

    def exclusions(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM exclusions ORDER BY path").fetchall()
        return [dict(row) for row in rows]

    def path_excluded(self, path: str | Path) -> bool:
        candidate = _path_key(str(Path(path).expanduser().resolve()))
        for item in self.exclusions():
            excluded = str(item["path_key"])
            if candidate == excluded:
                return True
            if item["recursive"] and candidate.startswith(excluded.rstrip("\\") + "\\"):
                return True
        return False

    def allow_hash(self, sha256: str, label: str, created_at: str) -> None:
        digest = _valid_sha256(sha256)
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO hash_allowlist(sha256, label, created_at) VALUES(?, ?, ?) "
                "ON CONFLICT(sha256) DO UPDATE SET label=excluded.label",
                (digest, label, created_at),
            )

    def remove_allowed_hash(self, sha256: str) -> bool:
        digest = _valid_sha256(sha256)
        with self._connection() as connection:
            cursor = connection.execute("DELETE FROM hash_allowlist WHERE sha256 = ?", (digest,))
        return cursor.rowcount > 0

    def allowed_hash(self, sha256: str) -> dict[str, Any] | None:
        digest = _valid_sha256(sha256)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM hash_allowlist WHERE sha256 = ?", (digest,)
            ).fetchone()
        return dict(row) if row else None

    def allowed_hashes(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM hash_allowlist ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]


def _path_key(path: str) -> str:
    return path.replace("/", "\\").casefold().rstrip("\\")


def _valid_sha256(value: str) -> str:
    normalized = value.strip().casefold()
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise ValueError("A 64-character SHA-256 digest is required")
    return normalized
