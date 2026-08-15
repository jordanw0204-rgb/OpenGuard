#![forbid(unsafe_code)]

use openguard_domain::{
    AllowedHashRecord, ExclusionRecord, PersistenceItem, QuarantineRecord, ScanFinding,
    SecurityEvent, Severity, TimelineEvent, TimelinePage,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;

pub const DATABASE_SCHEMA_VERSION: u32 = 6;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("stored JSON error: {0}")]
    Json(#[from] serde_json::Error),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseRollback {
    pub id: String,
    pub action: String,
    pub target: String,
    pub payload: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub restored_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedResponseRollback {
    pub owner_sid: String,
    pub rollback: ResponseRollback,
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
                capabilities_json TEXT NOT NULL DEFAULT '[]',
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
            CREATE TABLE IF NOT EXISTS timeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_sid TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL,
                action TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT NOT NULL,
                process_id INTEGER,
                path TEXT NOT NULL DEFAULT '',
                remote_address TEXT NOT NULL DEFAULT '',
                correlation_id TEXT NOT NULL DEFAULT '',
                occurred_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_timeline_owner_cursor
                ON timeline_events(owner_sid, id DESC);
            CREATE INDEX IF NOT EXISTS idx_timeline_process
                ON timeline_events(process_id, id DESC);
            CREATE TABLE IF NOT EXISTS persistence_items (
                owner_sid TEXT NOT NULL,
                id TEXT NOT NULL,
                category TEXT NOT NULL,
                name TEXT NOT NULL,
                command TEXT NOT NULL,
                location TEXT NOT NULL,
                state TEXT NOT NULL,
                risk TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                response_capability TEXT NOT NULL DEFAULT 'none',
                PRIMARY KEY(owner_sid, id)
            );
            CREATE TABLE IF NOT EXISTS response_rollbacks (
                id TEXT PRIMARY KEY,
                owner_sid TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                restored_at TEXT
            );
            ",
        )?;
        migrate_seen_executables(&transaction)?;
        migrate_scan_capabilities(&transaction)?;
        transaction.execute(
            r"INSERT INTO timeline_events(
                owner_sid, category, action, severity, title, detail, process_id,
                path, remote_address, correlation_id, occurred_at
            )
            SELECT owner_sid, 'detection', event_type, severity, title, detail, process_id,
                   path, '', 'security-event-' || id, created_at
            FROM security_events
            WHERE NOT EXISTS (
                SELECT 1 FROM timeline_events
                WHERE correlation_id = 'security-event-' || security_events.id
            )",
            [],
        )?;
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
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        transaction.execute(
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
        let id = transaction.last_insert_rowid();
        insert_timeline(
            &transaction,
            owner_sid,
            &TimelineEvent {
                id: None,
                category: "detection".into(),
                action: event.event_type.clone(),
                severity: event.severity,
                title: event.title.clone(),
                detail: event.detail.clone(),
                process_id: event.process_id,
                path: event.path.clone(),
                remote_address: String::new(),
                correlation_id: format!("security-event-{id}"),
                occurred_at: event.created_at.clone(),
            },
        )?;
        transaction.commit()?;
        Ok(id)
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

    /// Persists one normalized investigation timeline event.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the event cannot be committed.
    pub fn record_timeline(
        &self,
        owner_sid: &str,
        event: &TimelineEvent,
    ) -> Result<i64, StorageError> {
        let connection = self.connect()?;
        insert_timeline(&connection, owner_sid, event)?;
        Ok(connection.last_insert_rowid())
    }

    /// Retains only the newest bounded security and timeline history rows.
    ///
    /// This is intentionally count-based so a noisy optional telemetry source cannot grow the
    /// service-owned database without bound. A minimum of one row is always retained.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the pruning transaction cannot be committed.
    pub fn prune_event_history(
        &self,
        maximum_security_events: u32,
        maximum_timeline_events: u32,
    ) -> Result<(usize, usize), StorageError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let security_deleted = transaction.execute(
            "DELETE FROM security_events WHERE id IN (SELECT id FROM security_events ORDER BY id DESC LIMIT -1 OFFSET ?1)",
            params![i64::from(maximum_security_events.max(1))],
        )?;
        let timeline_deleted = transaction.execute(
            "DELETE FROM timeline_events WHERE id IN (SELECT id FROM timeline_events ORDER BY id DESC LIMIT -1 OFFSET ?1)",
            params![i64::from(maximum_timeline_events.max(1))],
        )?;
        transaction.commit()?;
        Ok((security_deleted, timeline_deleted))
    }

    /// Returns one owner-scoped, filtered cursor page of historical evidence.
    ///
    /// # Errors
    ///
    /// Returns a storage error for query failures or invalid stored severity values.
    pub fn timeline(
        &self,
        owner_sid: &str,
        before_id: Option<i64>,
        limit: u32,
        category: Option<&str>,
        process_id: Option<u32>,
        search: Option<&str>,
    ) -> Result<TimelinePage, StorageError> {
        let safe_limit = limit.clamp(1, 500);
        let fetch_limit = i64::from(safe_limit) + 1;
        let search = search.map(str::trim).filter(|value| !value.is_empty());
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            r"SELECT id, category, action, severity, title, detail, process_id, path,
                     remote_address, correlation_id, occurred_at
              FROM timeline_events
              WHERE (owner_sid=?1 OR owner_sid='')
                AND (?2 IS NULL OR id < ?2)
                AND (?3 IS NULL OR category=?3)
                AND (?4 IS NULL OR process_id=?4)
                AND (?5 IS NULL OR title LIKE '%' || ?5 || '%' OR detail LIKE '%' || ?5 || '%'
                     OR path LIKE '%' || ?5 || '%' OR remote_address LIKE '%' || ?5 || '%')
              ORDER BY id DESC LIMIT ?6",
        )?;
        let rows = statement.query_map(
            params![
                owner_sid,
                before_id,
                category,
                process_id,
                search,
                fetch_limit
            ],
            timeline_from_row,
        )?;
        let mut events = rows.collect::<Result<Vec<_>, _>>()?;
        let has_more = events.len() > safe_limit as usize;
        if has_more {
            events.truncate(safe_limit as usize);
        }
        let next_before_id = if has_more {
            events.last().and_then(|event| event.id)
        } else {
            None
        };
        Ok(TimelinePage {
            events,
            next_before_id,
        })
    }

    /// Replaces the active persistence baseline and records added, changed, and removed items.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the transaction cannot be committed.
    pub fn sync_persistence_inventory(
        &self,
        owner_sid: &str,
        items: &[PersistenceItem],
        observed_at: &str,
    ) -> Result<Vec<TimelineEvent>, StorageError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let existing = {
            let mut statement = transaction.prepare(
                "SELECT id, command, state, active FROM persistence_items WHERE owner_sid=?1",
            )?;
            let rows = statement.query_map([owner_sid], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, bool>(3)?,
                    ),
                ))
            })?;
            rows.collect::<Result<HashMap<_, _>, _>>()?
        };
        let mut active = HashSet::new();
        let mut changes = Vec::new();
        for item in items {
            active.insert(item.id.clone());
            let change = match existing.get(&item.id) {
                None => Some(("added", Severity::Info, "Persistence entry discovered")),
                Some((command, state, was_active))
                    if !was_active || command != &item.command || state != &item.state =>
                {
                    Some(("changed", Severity::Medium, "Persistence entry changed"))
                }
                _ => None,
            };
            let evidence_json = serde_json::to_string(&item.evidence)?;
            transaction.execute(
                r"INSERT INTO persistence_items(
                    owner_sid, id, category, name, command, location, state, risk,
                    evidence_json, first_seen, last_seen, active, response_capability
                ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, 1, ?11)
                ON CONFLICT(owner_sid, id) DO UPDATE SET
                    category=excluded.category, name=excluded.name, command=excluded.command,
                    location=excluded.location, state=excluded.state, risk=excluded.risk,
                    evidence_json=excluded.evidence_json, last_seen=excluded.last_seen,
                    active=1, response_capability=excluded.response_capability",
                params![
                    owner_sid,
                    item.id,
                    item.category,
                    item.name,
                    item.command,
                    item.location,
                    item.state,
                    item.risk.to_string(),
                    evidence_json,
                    observed_at,
                    item.response_capability,
                ],
            )?;
            if let Some((action, severity, title)) = change {
                changes.push(TimelineEvent {
                    id: None,
                    category: "persistence".into(),
                    action: action.into(),
                    severity,
                    title: title.into(),
                    detail: format!("{}: {} ({})", item.category, item.name, item.state),
                    process_id: None,
                    path: item.command.clone(),
                    remote_address: String::new(),
                    correlation_id: format!("persistence:{}:{observed_at}", item.id),
                    occurred_at: observed_at.into(),
                });
            }
        }
        for (id, (_, _, was_active)) in &existing {
            if *was_active && !active.contains(id) {
                transaction.execute(
                    "UPDATE persistence_items SET active=0, last_seen=?3 WHERE owner_sid=?1 AND id=?2",
                    params![owner_sid, id, observed_at],
                )?;
                changes.push(TimelineEvent {
                    id: None,
                    category: "persistence".into(),
                    action: "removed".into(),
                    severity: Severity::Info,
                    title: "Persistence entry removed".into(),
                    detail: id.clone(),
                    process_id: None,
                    path: String::new(),
                    remote_address: String::new(),
                    correlation_id: format!("persistence:{id}:{observed_at}"),
                    occurred_at: observed_at.into(),
                });
            }
        }
        for event in &changes {
            insert_timeline(&transaction, owner_sid, event)?;
        }
        transaction.commit()?;
        Ok(changes)
    }

    /// Returns an active persistence item by its stable identifier.
    ///
    /// # Errors
    ///
    /// Returns a storage error for query or decode failures.
    pub fn persistence_item(
        &self,
        owner_sid: &str,
        id: &str,
    ) -> Result<Option<PersistenceItem>, StorageError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            r"SELECT id, category, name, command, location, state, risk, evidence_json,
                     last_seen, response_capability
              FROM persistence_items WHERE owner_sid=?1 AND id=?2 AND active=1",
        )?;
        statement
            .query_row(params![owner_sid, id], persistence_from_row)
            .optional()
            .map_err(StorageError::from)
    }

    /// Stores rollback material for a reversible response operation.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the record cannot be committed.
    pub fn record_response_rollback(
        &self,
        owner_sid: &str,
        rollback: &ResponseRollback,
    ) -> Result<(), StorageError> {
        let connection = self.connect()?;
        connection.execute(
            r"INSERT INTO response_rollbacks(
                id, owner_sid, action, target, payload, created_at, expires_at, restored_at
            ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                rollback.id,
                owner_sid,
                rollback.action,
                rollback.target,
                rollback.payload,
                rollback.created_at,
                rollback.expires_at,
                rollback.restored_at,
            ],
        )?;
        Ok(())
    }

    /// Loads an unrestored rollback record owned by the authenticated user.
    ///
    /// # Errors
    ///
    /// Returns a storage error for query failures.
    pub fn response_rollback(
        &self,
        owner_sid: &str,
        id: &str,
    ) -> Result<Option<ResponseRollback>, StorageError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            r"SELECT id, action, target, payload, created_at, expires_at, restored_at
              FROM response_rollbacks WHERE owner_sid=?1 AND id=?2 AND restored_at IS NULL",
        )?;
        statement
            .query_row(params![owner_sid, id], |row| {
                Ok(ResponseRollback {
                    id: row.get(0)?,
                    action: row.get(1)?,
                    target: row.get(2)?,
                    payload: row.get(3)?,
                    created_at: row.get(4)?,
                    expires_at: row.get(5)?,
                    restored_at: row.get(6)?,
                })
            })
            .optional()
            .map_err(StorageError::from)
    }

    /// Loads unrestored rollback records for one response action so the service
    /// can recover time-bound cleanup after a restart.
    ///
    /// # Errors
    ///
    /// Returns a storage error for query failures.
    pub fn active_response_rollbacks(
        &self,
        action: &str,
    ) -> Result<Vec<OwnedResponseRollback>, StorageError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            r"SELECT owner_sid, id, action, target, payload, created_at, expires_at, restored_at
              FROM response_rollbacks WHERE action=?1 AND restored_at IS NULL",
        )?;
        statement
            .query_map(params![action], |row| {
                Ok(OwnedResponseRollback {
                    owner_sid: row.get(0)?,
                    rollback: ResponseRollback {
                        id: row.get(1)?,
                        action: row.get(2)?,
                        target: row.get(3)?,
                        payload: row.get(4)?,
                        created_at: row.get(5)?,
                        expires_at: row.get(6)?,
                        restored_at: row.get(7)?,
                    },
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    /// Marks a rollback record restored exactly once.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the update cannot be committed.
    pub fn mark_response_restored(
        &self,
        owner_sid: &str,
        id: &str,
        restored_at: &str,
    ) -> Result<bool, StorageError> {
        let connection = self.connect()?;
        Ok(connection.execute(
            "UPDATE response_rollbacks SET restored_at=?3 WHERE owner_sid=?1 AND id=?2 AND restored_at IS NULL",
            params![owner_sid, id, restored_at],
        )? == 1)
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
        let capabilities = serde_json::to_string(&finding.capabilities)?;
        let size_bytes = i64::try_from(finding.size_bytes).map_err(|error| {
            StorageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })?;
        let connection = self.connect()?;
        connection.execute(
            r"INSERT INTO scan_results(
                owner_sid, path, verdict, score, reasons_json, sha256,
                size_bytes, signature, amsi_result, yara_status,
                yara_matches_json, capabilities_json, scanned_at
            ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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
                capabilities,
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

fn insert_timeline(
    connection: &Connection,
    owner_sid: &str,
    event: &TimelineEvent,
) -> rusqlite::Result<usize> {
    connection.execute(
        r"INSERT INTO timeline_events(
            owner_sid, category, action, severity, title, detail, process_id,
            path, remote_address, correlation_id, occurred_at
        ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            owner_sid,
            event.category,
            event.action,
            event.severity.to_string(),
            event.title,
            event.detail,
            event.process_id,
            event.path,
            event.remote_address,
            event.correlation_id,
            event.occurred_at,
        ],
    )
}

fn severity_from_row(row: &Row<'_>, index: usize) -> rusqlite::Result<Severity> {
    let value: String = row.get(index)?;
    Severity::parse(&value).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid severity {value}"),
            )),
        )
    })
}

fn timeline_from_row(row: &Row<'_>) -> rusqlite::Result<TimelineEvent> {
    Ok(TimelineEvent {
        id: row.get(0)?,
        category: row.get(1)?,
        action: row.get(2)?,
        severity: severity_from_row(row, 3)?,
        title: row.get(4)?,
        detail: row.get(5)?,
        process_id: row
            .get::<_, Option<i64>>(6)?
            .and_then(|value| u32::try_from(value).ok()),
        path: row.get(7)?,
        remote_address: row.get(8)?,
        correlation_id: row.get(9)?,
        occurred_at: row.get(10)?,
    })
}

fn persistence_from_row(row: &Row<'_>) -> rusqlite::Result<PersistenceItem> {
    let evidence_json: String = row.get(7)?;
    let evidence = serde_json::from_str(&evidence_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            evidence_json.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    Ok(PersistenceItem {
        id: row.get(0)?,
        category: row.get(1)?,
        name: row.get(2)?,
        command: row.get(3)?,
        location: row.get(4)?,
        state: row.get(5)?,
        risk: severity_from_row(row, 6)?,
        evidence,
        detected_at: row.get(8)?,
        response_capability: row.get(9)?,
    })
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

fn migrate_scan_capabilities(transaction: &rusqlite::Transaction<'_>) -> Result<(), StorageError> {
    let has_column = {
        let mut statement = transaction.prepare("PRAGMA table_info(scan_results)")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
        rows.filter_map(Result::ok)
            .any(|name| name == "capabilities_json")
    };
    if !has_column {
        transaction.execute(
            "ALTER TABLE scan_results ADD COLUMN capabilities_json TEXT NOT NULL DEFAULT '[]'",
            [],
        )?;
    }
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
            Some("6")
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
    fn prunes_event_history_to_bounded_newest_rows() {
        let directory = TempDir::new().expect("temporary directory");
        let database = Database::open(directory.path().join("openguard.db")).expect("database");
        for index in 0..5 {
            let mut item = event();
            item.title = format!("event-{index}");
            database
                .record_event("owner-a", &item)
                .expect("record event");
        }
        let deleted = database.prune_event_history(2, 3).expect("prune history");
        assert_eq!(deleted, (3, 2));
        let events = database.recent_events("owner-a", 20).expect("events");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].title, "event-4");
        let timeline = database
            .timeline("owner-a", None, 20, None, None, None)
            .expect("timeline");
        assert_eq!(timeline.events.len(), 3);
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
            capabilities: Vec::new(),
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

    fn timeline_event(title: &str, category: &str, process_id: Option<u32>) -> TimelineEvent {
        TimelineEvent {
            id: None,
            category: category.into(),
            action: "observed".into(),
            severity: Severity::Info,
            title: title.into(),
            detail: format!("detail for {title}"),
            process_id,
            path: format!(r"C:\Evidence\{title}.txt"),
            remote_address: String::new(),
            correlation_id: title.into(),
            occurred_at: "unix:10".into(),
        }
    }

    #[test]
    fn timeline_is_owner_scoped_filtered_and_cursor_paginated() {
        let directory = TempDir::new().expect("temporary directory");
        let database = Database::open(directory.path().join("timeline.db")).expect("database");
        database
            .record_timeline("owner-a", &timeline_event("first", "file", Some(42)))
            .unwrap();
        database
            .record_timeline("owner-a", &timeline_event("second", "response", None))
            .unwrap();
        database
            .record_timeline("owner-b", &timeline_event("private", "file", Some(42)))
            .unwrap();

        let first_page = database
            .timeline("owner-a", None, 1, None, None, None)
            .unwrap();
        assert_eq!(first_page.events.len(), 1);
        assert_eq!(first_page.events[0].title, "second");
        let second_page = database
            .timeline("owner-a", first_page.next_before_id, 1, None, None, None)
            .unwrap();
        assert_eq!(second_page.events[0].title, "first");
        assert!(second_page.next_before_id.is_none());
        assert_eq!(
            database
                .timeline("owner-a", None, 10, Some("file"), Some(42), Some("first"))
                .unwrap()
                .events
                .len(),
            1
        );
    }

    #[test]
    fn persistence_sync_reports_only_baseline_changes() {
        let directory = TempDir::new().expect("temporary directory");
        let database = Database::open(directory.path().join("persistence.db")).expect("database");
        let mut item = PersistenceItem {
            id: "service-example".into(),
            category: "service".into(),
            name: "Example".into(),
            command: r"C:\Example\service.exe".into(),
            location: r"HKLM\Services\Example".into(),
            state: "automatic".into(),
            risk: Severity::Info,
            evidence: vec!["test".into()],
            detected_at: "unix:1".into(),
            response_capability: "disable_restore".into(),
        };
        assert_eq!(
            database
                .sync_persistence_inventory("owner", &[item.clone()], "unix:1")
                .unwrap()
                .len(),
            1
        );
        assert!(
            database
                .sync_persistence_inventory("owner", &[item.clone()], "unix:2")
                .unwrap()
                .is_empty()
        );
        item.command.push_str(" --changed");
        assert_eq!(
            database
                .sync_persistence_inventory("owner", &[item], "unix:3")
                .unwrap()[0]
                .action,
            "changed"
        );
        assert_eq!(
            database
                .sync_persistence_inventory("owner", &[], "unix:4")
                .unwrap()[0]
                .action,
            "removed"
        );
        assert!(
            database
                .persistence_item("owner", "service-example")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn response_rollbacks_are_owner_scoped_and_single_use() {
        let directory = TempDir::new().expect("temporary directory");
        let database = Database::open(directory.path().join("response.db")).expect("database");
        let rollback = ResponseRollback {
            id: "rollback-1".into(),
            action: "block_remote_address".into(),
            target: "203.0.113.5".into(),
            payload: "OpenGuard Temporary Block rollback-1".into(),
            created_at: "unix:1".into(),
            expires_at: Some("unix:60".into()),
            restored_at: None,
        };
        database
            .record_response_rollback("owner-a", &rollback)
            .unwrap();
        database
            .record_response_rollback(
                "owner-b",
                &ResponseRollback {
                    id: "rollback-2".into(),
                    ..rollback.clone()
                },
            )
            .unwrap();
        let active = database
            .active_response_rollbacks("block_remote_address")
            .unwrap();
        assert_eq!(active.len(), 2);
        assert!(active.iter().any(|value| value.owner_sid == "owner-a"));
        assert!(active.iter().any(|value| value.owner_sid == "owner-b"));
        assert!(
            database
                .response_rollback("owner-b", "rollback-1")
                .unwrap()
                .is_none()
        );
        assert!(
            database
                .mark_response_restored("owner-a", "rollback-1", "unix:2")
                .unwrap()
        );
        assert!(
            !database
                .mark_response_restored("owner-a", "rollback-1", "unix:3")
                .unwrap()
        );
        assert!(
            database
                .response_rollback("owner-a", "rollback-1")
                .unwrap()
                .is_none()
        );
    }
}
