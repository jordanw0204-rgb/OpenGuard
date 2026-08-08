use crate::WindowsError;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    collections::{HashMap, HashSet},
    fs,
    mem::size_of,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::IO::DeviceIoControl,
    },
    core::PCWSTR,
};

const FILE_EVENT_CAPACITY: usize = 4_096;
const MAX_RECONCILE_FILES: usize = 50_000;
const FSCTL_QUERY_USN_JOURNAL: u32 = 0x0009_00f4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileActivity {
    pub action: String,
    pub path: PathBuf,
    pub source: String,
    pub observed_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsnCheckpoint {
    pub journal_id: u64,
    pub first_usn: i64,
    pub next_usn: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMonitorSnapshot {
    pub events: Vec<FileActivity>,
    pub dropped: u64,
    pub reconciled: bool,
    pub journal_changed: bool,
    pub checkpoint: Option<UsnCheckpoint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    length: u64,
    modified: u64,
}

/// Bounded Windows file watcher backed by notify's `ReadDirectoryChangesW` implementation.
/// A metadata baseline is retained so queue/Windows buffer gaps can be reconciled by enumeration.
pub struct FileMonitor {
    _watcher: RecommendedWatcher,
    receiver: Receiver<FileActivity>,
    dropped: Arc<AtomicU64>,
    roots: Vec<PathBuf>,
    baseline: HashMap<PathBuf, FileFingerprint>,
    baseline_receiver: Receiver<HashMap<PathBuf, FileFingerprint>>,
    baseline_ready: bool,
    prebaseline_events: Vec<FileActivity>,
    pending_reconcile: bool,
    previous_dropped: u64,
    checkpoint: Option<UsnCheckpoint>,
}

impl FileMonitor {
    /// Starts recursive monitoring for existing, distinct roots.
    ///
    /// # Errors
    ///
    /// Returns an error when no roots are available or Windows cannot create a watcher.
    pub fn start(roots: impl IntoIterator<Item = PathBuf>) -> Result<Self, WindowsError> {
        let mut unique = HashSet::new();
        let roots = roots
            .into_iter()
            .filter(|root| root.is_dir())
            .filter(|root| unique.insert(normalized(root)))
            .collect::<Vec<_>>();
        if roots.is_empty() {
            return Err(WindowsError::Api(
                "no file-monitor roots are available".into(),
            ));
        }
        let (sender, receiver) = sync_channel(FILE_EVENT_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let callback_dropped = Arc::clone(&dropped);
        let mut watcher =
            notify::recommended_watcher(move |result: notify::Result<Event>| match result {
                Ok(event) => enqueue_event(&sender, &callback_dropped, event),
                Err(_) => {
                    callback_dropped.fetch_add(1, Ordering::Relaxed);
                }
            })
            .map_err(|error| WindowsError::Api(format!("create file watcher: {error}")))?;
        for root in &roots {
            watcher
                .watch(root, RecursiveMode::Recursive)
                .map_err(|error| WindowsError::Api(format!("watch {}: {error}", root.display())))?;
        }
        let (baseline_sender, baseline_receiver) = sync_channel(1);
        let baseline_roots = roots.clone();
        let _ = std::thread::Builder::new()
            .name("OpenGuardFileBaseline".into())
            .spawn(move || {
                let _ = baseline_sender.send(enumerate(&baseline_roots));
            });
        let checkpoint = roots
            .first()
            .and_then(|root| query_usn_checkpoint(root).ok());
        Ok(Self {
            _watcher: watcher,
            receiver,
            dropped,
            roots,
            baseline: HashMap::new(),
            baseline_receiver,
            baseline_ready: false,
            prebaseline_events: Vec::new(),
            pending_reconcile: false,
            previous_dropped: 0,
            checkpoint,
        })
    }

    #[must_use]
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Drains at most `limit` records and reconciles any detected queue/journal gap.
    #[must_use]
    pub fn drain(&mut self, limit: usize) -> FileMonitorSnapshot {
        let mut events = self
            .receiver
            .try_iter()
            .take(limit.clamp(1, 4_096))
            .collect::<Vec<_>>();
        if !self.baseline_ready
            && let Ok(mut baseline) = self.baseline_receiver.try_recv()
        {
            update_baseline(&mut baseline, &self.prebaseline_events);
            self.prebaseline_events.clear();
            self.baseline = baseline;
            self.baseline_ready = true;
        }
        let dropped = self.dropped.load(Ordering::Relaxed);
        let current_checkpoint = self
            .roots
            .first()
            .and_then(|root| query_usn_checkpoint(root).ok());
        let journal_changed = matches!((self.checkpoint, current_checkpoint),
            (Some(previous), Some(current)) if previous.journal_id != current.journal_id
                || current.first_usn > previous.next_usn);
        if dropped > self.previous_dropped || journal_changed {
            self.pending_reconcile = true;
        }
        let needs_reconcile = self.pending_reconcile && self.baseline_ready;
        if needs_reconcile {
            events.extend(self.reconcile(limit.saturating_sub(events.len())));
            self.pending_reconcile = false;
        } else if self.baseline_ready {
            update_baseline(&mut self.baseline, &events);
        } else {
            let remaining = 4_096_usize.saturating_sub(self.prebaseline_events.len());
            self.prebaseline_events
                .extend(events.iter().take(remaining).cloned());
        }
        self.previous_dropped = dropped;
        self.checkpoint = current_checkpoint.or(self.checkpoint);
        FileMonitorSnapshot {
            events,
            dropped,
            reconciled: needs_reconcile,
            journal_changed,
            checkpoint: self.checkpoint,
        }
    }

    fn reconcile(&mut self, limit: usize) -> Vec<FileActivity> {
        let current = enumerate(&self.roots);
        let mut events = Vec::new();
        for (path, fingerprint) in &current {
            let action = match self.baseline.get(path) {
                None => Some("created"),
                Some(previous) if previous != fingerprint => Some("modified"),
                _ => None,
            };
            if let Some(action) = action {
                events.push(FileActivity {
                    action: action.into(),
                    path: path.clone(),
                    source: "reconciliation".into(),
                    observed_at: timestamp(),
                });
            }
            if events.len() >= limit {
                break;
            }
        }
        if events.len() < limit {
            for path in self
                .baseline
                .keys()
                .filter(|path| !current.contains_key(*path))
            {
                events.push(FileActivity {
                    action: "removed".into(),
                    path: path.clone(),
                    source: "reconciliation".into(),
                    observed_at: timestamp(),
                });
                if events.len() >= limit {
                    break;
                }
            }
        }
        self.baseline = current;
        events
    }
}

fn enqueue_event(sender: &SyncSender<FileActivity>, dropped: &AtomicU64, event: Event) {
    let action = match event.kind {
        EventKind::Create(_) => "created",
        EventKind::Modify(_) => "modified",
        EventKind::Remove(_) => "removed",
        EventKind::Access(_) => return,
        EventKind::Other | EventKind::Any => "changed",
    };
    for path in event.paths {
        let activity = FileActivity {
            action: action.into(),
            path,
            source: "read_directory_changes".into(),
            observed_at: timestamp(),
        };
        if sender.try_send(activity).is_err() {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn enumerate(roots: &[PathBuf]) -> HashMap<PathBuf, FileFingerprint> {
    let mut result = HashMap::new();
    let mut pending = roots.to_vec();
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            if result.len() >= MAX_RECONCILE_FILES {
                return result;
            }
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                if !metadata.file_type().is_symlink() {
                    pending.push(path);
                }
            } else if metadata.is_file() {
                result.insert(
                    normalized(&path),
                    FileFingerprint {
                        length: metadata.len(),
                        modified: metadata
                            .modified()
                            .ok()
                            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                            .map_or(0, |value| value.as_secs()),
                    },
                );
            }
        }
    }
    result
}

fn update_baseline(baseline: &mut HashMap<PathBuf, FileFingerprint>, events: &[FileActivity]) {
    for event in events {
        let path = normalized(&event.path);
        if event.action == "removed" {
            baseline.remove(&path);
        } else if let Ok(metadata) = fs::metadata(&path)
            && metadata.is_file()
        {
            baseline.insert(
                path,
                FileFingerprint {
                    length: metadata.len(),
                    modified: metadata
                        .modified()
                        .ok()
                        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                        .map_or(0, |value| value.as_secs()),
                },
            );
        }
    }
}

fn normalized(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Queries the NTFS journal identity/cursor for the volume containing `path`.
///
/// # Errors
///
/// Returns a Windows API error for non-drive paths, unsupported file systems, or access denial.
pub fn query_usn_checkpoint(path: &Path) -> Result<UsnCheckpoint, WindowsError> {
    let prefix = path
        .components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
        .filter(|value| value.len() >= 2 && value.as_bytes()[1] == b':')
        .ok_or_else(|| WindowsError::Api(format!("{} has no drive volume", path.display())))?;
    let volume = format!(r"\\.\{}", &prefix[..2]);
    let wide = std::ffi::OsStr::new(&volume)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|error| WindowsError::Api(format!("open USN volume {volume}: {error}")))?;
    if handle == INVALID_HANDLE_VALUE {
        return Err(WindowsError::Api(format!("open USN volume {volume}")));
    }
    let mut data = UsnJournalData::default();
    let journal_size = u32::try_from(size_of::<UsnJournalData>())
        .map_err(|_| WindowsError::Api("USN journal structure is too large".into()))?;
    let mut returned = 0_u32;
    let result = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            None,
            0,
            Some(std::ptr::from_mut(&mut data).cast()),
            journal_size,
            Some(&raw mut returned),
            None,
        )
    };
    let _ = unsafe { CloseHandle(handle) };
    result.map_err(|error| WindowsError::Api(format!("query USN volume {volume}: {error}")))?;
    if returned < journal_size {
        return Err(WindowsError::Api(
            "USN query returned a short buffer".into(),
        ));
    }
    Ok(UsnCheckpoint {
        journal_id: data.journal_id,
        first_usn: data.first_usn,
        next_usn: data.next_usn,
    })
}

#[repr(C)]
#[derive(Default)]
struct UsnJournalData {
    journal_id: u64,
    first_usn: i64,
    next_usn: i64,
    lowest_valid_usn: i64,
    max_usn: i64,
    maximum_size: u64,
    allocation_delta: u64,
}

fn timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    format!("unix:{seconds}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn watcher_reports_file_creation_without_unbounded_queueing() {
        let directory = TempDir::new().expect("temporary directory");
        let mut monitor = FileMonitor::start([directory.path().to_path_buf()]).expect("monitor");
        let target = directory.path().join("observed.txt");
        fs::write(&target, b"OpenGuard").expect("write observed file");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let snapshot = monitor.drain(32);
            if snapshot
                .events
                .iter()
                .any(|event| event.path.ends_with("observed.txt"))
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "watch event timed out"
            );
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    #[test]
    fn reconciliation_detects_changes_after_an_explicit_gap() {
        let directory = TempDir::new().expect("temporary directory");
        let mut monitor = FileMonitor::start([directory.path().to_path_buf()]).expect("monitor");
        let ready_deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !monitor.baseline_ready {
            let _ = monitor.drain(32);
            assert!(
                std::time::Instant::now() < ready_deadline,
                "baseline timed out"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let target = directory.path().join("reconciled.txt");
        fs::write(&target, b"evidence").expect("write evidence");
        monitor.dropped.fetch_add(1, Ordering::Relaxed);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let snapshot = monitor.drain(32);
            if snapshot.reconciled {
                assert!(
                    snapshot
                        .events
                        .iter()
                        .any(|event| event.path.ends_with("reconciled.txt"))
                );
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "reconciliation timed out"
            );
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
}
