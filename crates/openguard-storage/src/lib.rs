#![forbid(unsafe_code)]

use openguard_domain::{
    AllowedHashRecord, ExclusionRecord, QuarantineRecord, ScanFinding, SecurityEvent, Severity,
};
use rusqlite::{Connection, OpenFlags, Row, params};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;

pub const DATABASE_SCHEMA_VERSION: u32 = 4;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database contains invalid severity '{0}'")]
    InvalidSeverity(String),
}

#[derive(Debug, Clone)]
pub struct Database {
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredQuarantine {
    pub record: QuarantineRecord,
    pub quarantine_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SeenExecutable {
    pub identity: String,
    pub path: String,
    pub name: String,
    pub signature: String,
    pub risk_score: u8,
    pub observed_at: String,
}

impl Database {
    /// Opens or creates the service-owned database and applies native schema migrations.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the parent directory cannot be created,
    /// the database cannot be opened, or a migration cannot be committed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let database = Self { path };
        database.initialize()?;
        Ok(database)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn connect(&self) -> Result<Connection, StorageError> {
        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(10))?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;",
        )?;
        Ok(connection)
    }

    #[allow(clippy::too_many_lines)]
    fn initialize(&self) -> Result<(), StorageError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            r"
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS seen_executables (
                identity TEXT NOT NULL,
                owner_sid TEXT NOT NULL DEFAULT '',
                path TEXT NOT NULL,
                name TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                signature TEXT NOT NULL,
                risk_score INTEGER NOT NULL CHECK(risk_score BETWEEN 0 AND 100),
                PRIMARY KEY(owner_sid, identity)
            );
            CREATE INDEX IF NOT EXISTS idx_seen_path ON seen_executables(path);
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_sid TEXT NOT NULL DEFAULT '',
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT NOT NULL,
                process_id INTEGER,
                path TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                resolved INTEGER NOT NULL DEFAULT 0 CHECK(resolved IN (0, 1))
            );
            CREATE INDEX IF NOT EXISTS idx_events_created
                ON security_events(created_at DESC, id DESC);
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_sid TEXT NOT NULL DEFAULT '',
                path TEXT NOT NULL,
                verdict TEXT NOT NULL,
                score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100),
                reasons_json TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
                signature TEXT NOT NULL,
                amsi_result TEXT NOT NULL,
                yara_status TEXT NOT NULL DEFAULT 'not_scanned',
                yara_matches_json TEXT NOT NULL DEFAULT '[]',
                scanned_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scans_time
                ON scan_results(scanned_at DESC, id DESC);
            CREATE TABLE IF NOT EXISTS quarantines (
                id TEXT PRIMARY KEY,
                owner_sid TEXT NOT NULL,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL UNIQUE,
                sha256 TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                restored_at TEXT,
                restored_path TEXT
            );
            CREATE TABLE IF NOT EXISTS exclusions (
                owner_sid TEXT NOT NULL,
                path_key TEXT NOT NULL,
                path TEXT NOT NULL,
                recursive INTEGER NOT NULL DEFAULT 1 CHECK(recursive IN (0, 1)),
                created_at TEXT NOT NULL,
                PRIMARY KEY(owner_sid, path_key)
            );
            CREATE TABLE IF NOT EXISTS hash_allowlist (
                owner_sid TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                PRIMARY KEY(owner_sid, sha256)
            );
            CREATE TABLE IF NOT EXISTS network_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                observed_at TEXT NOT NULL,
                pid INTEGER NOT NULL,
                process_identity TEXT NOT NULL DEFAULT '',
                protocol TEXT NOT NULL,
                remote_address TEXT NOT NULL,
                remote_port INTEGER NOT NULL,
                bytes_sent INTEGER,
                bytes_received INTEGER,
                reputation TEXT NOT NULL DEFAULT 'unknown'
            );
            CREATE INDEX IF NOT EXISTS idx_network_observed
                ON network_observations(observed_at DESC, id DESC);
            ",
        )?;
        migrate_seen_executables(&transaction)?;
        transaction.execute(
            "INSERT INTO metadata(key, value) VALUES('schema_version', ?1) \
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [DATABASE_SCHEMA_VERSION.to_string()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Returns a metadata value when the key exists.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the database cannot execute the query.
    pub fn get_metadata(&self, key: &str) -> Result<Option<String>, StorageError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare("SELECT value FROM metadata WHERE key=?1")?;
        let mut rows = statement.query([key])?;
        Ok(rows.next()?.map(|row| row.get(0)).transpose()?)
    }

    /// Atomically inserts or replaces one metadata value.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the database cannot commit the value.
    pub fn set_metadata(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let connection = self.connect()?;
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES(?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Atomically activates one immutable content version and records rollback state.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the activation transaction cannot commit.
    pub fn activate_content_version(
        &self,
        active_version: &str,
        previous_version: Option<&str>,
    ) -> Result<(), StorageError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO metadata(key, value) VALUES('active_content_version', ?1) \
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [active_version],
        )?;
        transaction.execute(
            "INSERT INTO metadata(key, value) VALUES('previous_content_version', ?1) \
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [previous_version.unwrap_or("")],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Returns the subset of executable identities already observed for one user.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the query cannot be executed.
    pub fn known_executable_identities(
        &self,
        owner_sid: &str,
        identities: &[String],
    ) -> Result<HashSet<String>, StorageError> {
        let unique = identities
            .iter()
            .filter(|identity| !identity.is_empty())
            .collect::<HashSet<_>>();
        if unique.is_empty() {
            return Ok(HashSet::new());
        }
        let connection = self.connect()?;
        let mut known = HashSet::new();
        let identities = unique.into_iter().collect::<Vec<_>>();
        for chunk in identities.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT identity FROM seen_executables WHERE owner_sid=? AND identity IN ({placeholders})"
            );
            let mut values: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(chunk.len() + 1);
            values.push(&owner_sid);
            values.extend(
                chunk
                    .iter()
                    .map(|identity| *identity as &dyn rusqlite::ToSql),
            );
            let mut statement = connection.prepare(&sql)?;
            let rows = statement.query_map(values.as_slice(), |row| row.get::<_, String>(0))?;
            known.extend(rows.collect::<Result<Vec<_>, _>>()?);
        }
        Ok(known)
    }

    /// Upserts the current executable observations for one authenticated user.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the batch cannot be committed atomically.
    pub fn record_executables(
        &self,
        owner_sid: &str,
        observations: &[SeenExecutable],
    ) -> Result<(), StorageError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        {
            let mut statement = transaction.prepare(
                r"INSERT INTO seen_executables(
                    owner_sid, identity, path, name, first_seen, last_seen, signature, risk_score
                ) VALUES(?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7)
                ON CONFLICT(owner_sid, identity) DO UPDATE SET
                    path=excluded.path,
                    name=excluded.name,
                    last_seen=excluded.last_seen,
                    signature=excluded.signature,
                    risk_score=excluded.risk_score",
            )?;
            for observation in observations
                .iter()
                .filter(|observation| !observation.identity.is_empty())
            {
                statement.execute(params![
                    owner_sid,
                    observation.identity,
                    observation.path,
                    observation.name,
                    observation.observed_at,
                    observation.signature,
                    observation.risk_score,
                ])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Persists one explainable security event for its authenticated owner.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the database cannot commit the event.
    pub fn record_event(
        &self,
        owner_sid: &str,
        event: &SecurityEvent,
    ) -> Result<i64, StorageError> {
        let connection = self.connect()?;
        connection.execute(
            r"INSERT INTO security_events(
                owner_sid, event_type, severity, title, detail, process_id,
                path, created_at, resolved
            ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                owner_sid,
                event.event_type,
                event.severity.to_string(),
                event.title,
                event.detail,
                event.process_id,
                event.path,
                event.created_at,
                event.resolved,
            ],
        )?;
        Ok(connection.last_insert_rowid())
    }

    /// Returns recent events visible to an authenticated owner, newest first.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the database cannot execute the query or stored
    /// enum data is invalid.
    pub fn recent_events(
        &self,
        owner_sid: &str,
        limit: u32,
    ) -> Result<Vec<SecurityEvent>, StorageError> {
        let safe_limit = limit.clamp(1, 2_000);
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT id, event_type, severity, title, detail, process_id, path, created_at, resolved \
             FROM security_events WHERE owner_sid=?1 OR owner_sid='' \
             ORDER BY created_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![owner_sid, safe_limit], |row| {
            let severity_text: String = row.get(2)?;
            let severity = Severity::parse(&severity_text).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    severity_text.len(),
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid severity {severity_text}"),
                    )),
                )
            })?;
            let process_id = row
                .get::<_, Option<i64>>(5)?
                .and_then(|value| u32::try_from(value).ok());
            Ok(SecurityEvent {
                id: row.get(0)?,
                event_type: row.get(1)?,
                severity,
                title: row.get(3)?,
                detail: row.get(4)?,
                process_id,
                path: row.get(6)?,
                created_at: row.get(7)?,
                resolved: row.get(8)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    /// Persists one completed scanner finding for its authenticated owner.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the finding cannot be serialized or the
    /// database cannot commit it.
    pub fn record_scan(&self, owner_sid: &str, finding: &ScanFinding) -> Result<i64, StorageError> {
        let reasons = serde_json::to_string(&finding.reasons).map_err(|error| {
            StorageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })?;
        let yara_matches = serde_json::to_string(&finding.yara_matches).map_err(|error| {
            StorageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })?;
        let size_bytes = i64::try_from(finding.size_bytes).map_err(|error| {
            StorageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })?;
        let connection = self.connect()?;
        connection.execute(
            r"INSERT INTO scan_results(
                owner_sid, path, verdict, score, reasons_json, sha256,
                size_bytes, signature, amsi_result, yara_status,
                yara_matches_json, scanned_at
            ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                owner_sid,
                finding.path,
                finding.verdict.to_string(),
                finding.score,
                reasons,
                finding.sha256,
                size_bytes,
                finding.signature.to_string(),
                finding.amsi_result,
                finding.yara_status,
                yara_matches,
                finding.scanned_at,
            ],
        )?;
        Ok(connection.last_insert_rowid())
    }

    /// Adds or updates one visible path exclusion for an authenticated owner.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the record cannot be committed.
    pub fn add_exclusion(
        &self,
        owner_sid: &str,
        path_key: &str,
        record: &ExclusionRecord,
    ) -> Result<(), StorageError> {
        let connection = self.connect()?;
        connection.execute(
            r"INSERT INTO exclusions(owner_sid, path_key, path, recursive, created_at)
              VALUES(?1, ?2, ?3, ?4, ?5)
              ON CONFLICT(owner_sid, path_key) DO UPDATE SET
                path=excluded.path, recursive=excluded.recursive, created_at=excluded.created_at",
            params![
                owner_sid,
                path_key,
                record.path,
                record.recursive,
                record.created_at
            ],
        )?;
        Ok(())
    }

    /// Removes one exact normalized path exclusion for an authenticated owner.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the delete cannot be executed.
    pub fn remove_exclusion(&self, owner_sid: &str, path_key: &str) -> Result<bool, StorageError> {
        let connection = self.connect()?;
        Ok(connection.execute(
            "DELETE FROM exclusions WHERE owner_sid=?1 AND path_key=?2",
            params![owner_sid, path_key],
        )? == 1)
    }

    /// Returns visible exclusions for one authenticated owner.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the query cannot be executed.
    pub fn list_exclusions(&self, owner_sid: &str) -> Result<Vec<ExclusionRecord>, StorageError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT path, recursive, created_at FROM exclusions \
             WHERE owner_sid=?1 ORDER BY path COLLATE NOCASE",
        )?;
        let rows = statement.query_map([owner_sid], |row| {
            Ok(ExclusionRecord {
                path: row.get(0)?,
                recursive: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    /// Returns whether a normalized file path is excluded for one owner.
    ///
    /// # Errors
    ///
    /// Returns a storage error when exclusions cannot be queried.
    pub fn path_excluded(
        &self,
        owner_sid: &str,
        candidate_key: &str,
    ) -> Result<bool, StorageError> {
        let connection = self.connect()?;
        let mut statement =
            connection.prepare("SELECT path_key, recursive FROM exclusions WHERE owner_sid=?1")?;
        let rows = statement.query_map([owner_sid], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?))
        })?;
        for row in rows {
            let (key, recursive) = row?;
            if candidate_key == key
                || (recursive
                    && candidate_key
                        .strip_prefix(&key)
                        .is_some_and(|suffix| suffix.starts_with('\\')))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Adds or updates one exact SHA-256 allow-list entry.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the record cannot be committed.
    pub fn allow_hash(
        &self,
        owner_sid: &str,
        record: &AllowedHashRecord,
    ) -> Result<(), StorageError> {
        let connection = self.connect()?;
        connection.execute(
            r"INSERT INTO hash_allowlist(owner_sid, sha256, label, created_at)
              VALUES(?1, ?2, ?3, ?4)
              ON CONFLICT(owner_sid, sha256) DO UPDATE SET
                label=excluded.label, created_at=excluded.created_at",
            params![owner_sid, record.sha256, record.label, record.created_at],
        )?;
        Ok(())
    }

    /// Finds the user-visible label for one exact allowed SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the query cannot be executed.
    pub fn allowed_hash(
        &self,
        owner_sid: &str,
        sha256: &str,
    ) -> Result<Option<String>, StorageError> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare("SELECT label FROM hash_allowlist WHERE owner_sid=?1 AND sha256=?2")?;
        let mut rows = statement.query(params![owner_sid, sha256])?;
        Ok(rows.next()?.map(|row| row.get(0)).transpose()?)
    }

    /// Returns exact hash allow-list entries for one owner.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the query cannot be executed.
    pub fn list_allowed_hashes(
        &self,
        owner_sid: &str,
    ) -> Result<Vec<AllowedHashRecord>, StorageError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT sha256, label, created_at FROM hash_allowlist \
             WHERE owner_sid=?1 ORDER BY created_at DESC, sha256",
        )?;
        let rows = statement.query_map([owner_sid], |row| {
            Ok(AllowedHashRecord {
                sha256: row.get(0)?,
                label: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    /// Removes one exact SHA-256 allow-list entry.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the delete cannot be executed.
    pub fn remove_allowed_hash(&self, owner_sid: &str, sha256: &str) -> Result<bool, StorageError> {
        let connection = self.connect()?;
        Ok(connection.execute(
            "DELETE FROM hash_allowlist WHERE owner_sid=?1 AND sha256=?2",
            params![owner_sid, sha256],
        )? == 1)
    }

    /// Persists a defanged quarantine payload after it has been copied and hash-verified.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the record cannot be committed.
    pub fn record_quarantine(
        &self,
        owner_sid: &str,
        record: &QuarantineRecord,
        quarantine_path: &Path,
    ) -> Result<(), StorageError> {
        let connection = self.connect()?;
        connection.execute(
            r"INSERT INTO quarantines(
                id, owner_sid, original_path, quarantine_path, sha256, reason,
                created_at, restored_at, restored_path
            ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                record.id,
                owner_sid,
                record.original_path,
                quarantine_path.display().to_string(),
                record.sha256,
                record.reason,
                record.created_at,
                record.restored_at,
                record.restored_path,
            ],
        )?;
        Ok(())
    }

    /// Returns active and restored quarantine records owned by one authenticated user.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the query cannot be executed.
    pub fn list_quarantines(
        &self,
        owner_sid: &str,
        limit: u32,
    ) -> Result<Vec<QuarantineRecord>, StorageError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT id, original_path, quarantine_path, sha256, reason, created_at, \
             restored_at, restored_path FROM quarantines WHERE owner_sid=?1 \
             ORDER BY created_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![owner_sid, limit.clamp(1, 2_000)], |row| {
            quarantine_from_row(row).map(|stored| stored.record)
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    /// Finds one quarantine entry only when it belongs to the authenticated owner.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the query cannot be executed.
    pub fn quarantine(
        &self,
        owner_sid: &str,
        quarantine_id: &str,
    ) -> Result<Option<StoredQuarantine>, StorageError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT id, original_path, quarantine_path, sha256, reason, created_at, \
             restored_at, restored_path FROM quarantines WHERE owner_sid=?1 AND id=?2",
        )?;
        let mut rows = statement.query(params![owner_sid, quarantine_id])?;
        rows.next()?
            .map(quarantine_from_row)
            .transpose()
            .map_err(StorageError::from)
    }

    /// Marks a quarantine entry restored without deleting its audit metadata.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the update cannot be committed.
    pub fn mark_quarantine_restored(
        &self,
        owner_sid: &str,
        quarantine_id: &str,
        restored_at: &str,
        restored_path: &Path,
    ) -> Result<bool, StorageError> {
        let connection = self.connect()?;
        let changed = connection.execute(
            "UPDATE quarantines SET restored_at=?3, restored_path=?4 \
             WHERE owner_sid=?1 AND id=?2 AND restored_at IS NULL",
            params![
                owner_sid,
                quarantine_id,
                restored_at,
                restored_path.display().to_string()
            ],
        )?;
        Ok(changed == 1)
    }

    /// Removes a just-created quarantine record during an operation rollback.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the delete cannot be committed.
    pub fn delete_quarantine(
        &self,
        owner_sid: &str,
        quarantine_id: &str,
    ) -> Result<bool, StorageError> {
        let connection = self.connect()?;
        Ok(connection.execute(
            "DELETE FROM quarantines WHERE owner_sid=?1 AND id=?2",
            params![owner_sid, quarantine_id],
        )? == 1)
    }
}

fn migrate_seen_executables(transaction: &rusqlite::Transaction<'_>) -> Result<(), StorageError> {
    let primary_key_columns = {
        let mut statement = transaction.prepare("PRAGMA table_info(seen_executables)")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(5)?))
        })?;
        rows.filter_map(Result::ok)
            .filter(|(_, primary_key_order)| *primary_key_order > 0)
            .map(|(name, _)| name)
            .collect::<Vec<_>>()
    };
    if primary_key_columns != ["identity"] {
        return Ok(());
    }
    transaction.execute_batch(
        r"
        ALTER TABLE seen_executables RENAME TO seen_executables_v3;
        CREATE TABLE seen_executables (
            identity TEXT NOT NULL,
            owner_sid TEXT NOT NULL DEFAULT '',
            path TEXT NOT NULL,
            name TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            signature TEXT NOT NULL,
            risk_score INTEGER NOT NULL CHECK(risk_score BETWEEN 0 AND 100),
            PRIMARY KEY(owner_sid, identity)
        );
        INSERT OR IGNORE INTO seen_executables(
            identity, owner_sid, path, name, first_seen, last_seen, signature, risk_score
        ) SELECT identity, owner_sid, path, name, first_seen, last_seen, signature, risk_score
          FROM seen_executables_v3;
        DROP TABLE seen_executables_v3;
        DROP INDEX IF EXISTS idx_seen_path;
        CREATE INDEX idx_seen_path ON seen_executables(path);
        ",
    )?;
    Ok(())
}

fn quarantine_from_row(row: &Row<'_>) -> rusqlite::Result<StoredQuarantine> {
    Ok(StoredQuarantine {
        record: QuarantineRecord {
            id: row.get(0)?,
            original_path: row.get(1)?,
            sha256: row.get(3)?,
            reason: row.get(4)?,
            created_at: row.get(5)?,
            restored_at: row.get(6)?,
            restored_path: row.get(7)?,
        },
        quarantine_path: PathBuf::from(row.get::<_, String>(2)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn event() -> SecurityEvent {
        SecurityEvent {
            id: None,
            event_type: "new_executable".into(),
            severity: Severity::High,
            title: "New executable".into(),
            detail: "Unsigned program contacted a new destination".into(),
            process_id: Some(42),
            path: r"C:\Users\Test\Downloads\sample.exe".into(),
            created_at: "2026-08-07T10:00:00Z".into(),
            resolved: false,
        }
    }

    #[test]
    fn initializes_wal_schema_and_round_trips_events() {
        let directory = TempDir::new().expect("temporary directory");
        let database = Database::open(directory.path().join("openguard.db")).expect("database");
        assert_eq!(
            database
                .get_metadata("schema_version")
                .expect("metadata")
                .as_deref(),
            Some("4")
        );
        let id = database
            .record_event("S-1-5-21-test", &event())
            .expect("record event");
        let events = database
            .recent_events("S-1-5-21-test", 20)
            .expect("recent events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, Some(id));
        assert_eq!(events[0].severity, Severity::High);
    }

    #[test]
    fn event_queries_are_scoped_to_the_authenticated_owner() {
        let directory = TempDir::new().expect("temporary directory");
        let database = Database::open(directory.path().join("openguard.db")).expect("database");
        database
            .record_event("owner-a", &event())
            .expect("owner a event");
        database
            .record_event("owner-b", &event())
            .expect("owner b event");
        assert_eq!(database.recent_events("owner-a", 20).unwrap().len(), 1);
    }

    #[test]
    fn persists_native_scan_findings() {
        let directory = TempDir::new().expect("temporary directory");
        let database = Database::open(directory.path().join("openguard.db")).expect("database");
        let finding = ScanFinding {
            path: r"C:\Users\Test\sample.txt".into(),
            verdict: openguard_domain::ScanVerdict::Clean,
            score: 0,
            reasons: vec!["No configured local detection signal matched".into()],
            sha256: "abc123".into(),
            size_bytes: 12,
            signature: openguard_domain::SignatureStatus::NotApplicable,
            amsi_result: "not_scanned".into(),
            yara_status: "active".into(),
            yara_matches: Vec::new(),
            scanned_at: "unix:1".into(),
        };
        let id = database
            .record_scan("owner-a", &finding)
            .expect("record scan");
        assert!(id > 0);
    }

    #[test]
    fn quarantines_are_owner_scoped_and_retain_restore_audit() {
        let directory = TempDir::new().expect("temporary directory");
        let database = Database::open(directory.path().join("openguard.db")).expect("database");
        let record = QuarantineRecord {
            id: "q-1".into(),
            original_path: r"C:\Users\Test\bad.exe".into(),
            sha256: "abc123".into(),
            reason: "test detection".into(),
            created_at: "unix:1".into(),
            restored_at: None,
            restored_path: None,
        };
        database
            .record_quarantine("owner-a", &record, &directory.path().join("q-1.quarantine"))
            .expect("record quarantine");
        assert!(database.list_quarantines("owner-b", 10).unwrap().is_empty());
        assert_eq!(
            database.list_quarantines("owner-a", 10).unwrap(),
            vec![record]
        );
        assert!(
            database
                .mark_quarantine_restored(
                    "owner-a",
                    "q-1",
                    "unix:2",
                    Path::new(r"C:\Users\Test\restored.exe")
                )
                .unwrap()
        );
        let restored = database
            .quarantine("owner-a", "q-1")
            .unwrap()
            .expect("stored quarantine");
        assert_eq!(restored.record.restored_at.as_deref(), Some("unix:2"));
    }

    #[test]
    fn executable_baselines_are_owner_scoped_and_upserted() {
        let directory = TempDir::new().expect("temporary directory");
        let database = Database::open(directory.path().join("openguard.db")).expect("database");
        let observation = SeenExecutable {
            identity: "sample|1|2".into(),
            path: r"C:\sample.exe".into(),
            name: "sample.exe".into(),
            signature: "unknown".into(),
            risk_score: 20,
            observed_at: "unix:1".into(),
        };
        database
            .record_executables("owner-a", &[observation])
            .expect("record executable");
        let identities = vec!["sample|1|2".to_owned(), "unseen".to_owned()];
        assert_eq!(
            database
                .known_executable_identities("owner-a", &identities)
                .unwrap(),
            HashSet::from(["sample|1|2".to_owned()])
        );
        assert!(
            database
                .known_executable_identities("owner-b", &identities)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn exclusions_and_allowed_hashes_are_exact_and_owner_scoped() {
        let directory = TempDir::new().expect("temporary directory");
        let database = Database::open(directory.path().join("openguard.db")).expect("database");
        database
            .add_exclusion(
                "owner-a",
                r"c:\safe",
                &ExclusionRecord {
                    path: r"C:\Safe".into(),
                    recursive: true,
                    created_at: "unix:1".into(),
                },
            )
            .expect("add exclusion");
        assert!(
            database
                .path_excluded("owner-a", r"c:\safe\file.txt")
                .unwrap()
        );
        assert!(
            !database
                .path_excluded("owner-a", r"c:\safety\file.txt")
                .unwrap()
        );
        assert!(
            !database
                .path_excluded("owner-b", r"c:\safe\file.txt")
                .unwrap()
        );

        let allowed = AllowedHashRecord {
            sha256: "a".repeat(64),
            label: "reviewed sample".into(),
            created_at: "unix:2".into(),
        };
        database
            .allow_hash("owner-a", &allowed)
            .expect("allow hash");
        assert_eq!(
            database.allowed_hash("owner-a", &allowed.sha256).unwrap(),
            Some("reviewed sample".into())
        );
        assert!(
            database
                .allowed_hash("owner-b", &allowed.sha256)
                .unwrap()
                .is_none()
        );
    }
}
