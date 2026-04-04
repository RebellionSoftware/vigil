use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use chrono::{DateTime, Utc};
use fd_lock::RwLock as FdRwLock;
use serde::{Deserialize, Serialize};

const AUDIT_LOG_FILENAME: &str = "vigil-audit.log";

/// A single entry in the vigil audit log.
///
/// Serialized as one JSON object per line (NDJSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// RFC 3339 timestamp of the event.
    pub ts: DateTime<Utc>,
    /// Event type: "install", "block", "update", "remove", "verify_pass", "verify_fail".
    pub event: String,
    /// Package name.
    pub package: String,
    /// Resolved exact version.
    pub version: String,
    /// Age of the package version at time of event, in days.
    pub age_days: u32,
    /// Names of checks that passed (e.g. ["age-gate", "postinstall"]).
    pub checks_passed: Vec<String>,
    /// System user who triggered the event.
    pub user: String,
    /// Human-readable reason (required for bypasses, optional otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Append-only audit log stored as NDJSON.
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// Open (or create) the audit log in `project_dir`.
    pub fn new(project_dir: &Path) -> Self {
        AuditLog {
            path: project_dir.join(AUDIT_LOG_FILENAME),
        }
    }

    /// Append one entry. Creates the file if it does not exist.
    ///
    /// Acquires an exclusive advisory file lock before writing so that
    /// concurrent vigil invocations do not interleave partial lines.
    pub fn append(&self, entry: &AuditEntry) -> std::io::Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(&self.path)?;

        let mut lock = FdRwLock::new(file);
        let mut guard = lock.write()?;

        // Seek to end after acquiring the lock so we always append even when
        // another process has written since we opened the file.
        guard.seek(SeekFrom::End(0))?;

        let line = serde_json::to_string(entry)
            .expect("AuditEntry is always serializable");
        writeln!(*guard, "{line}")?;
        // Flush kernel page cache to disk before releasing the lock so audit
        // entries are durable even if the process crashes immediately after.
        (*guard).sync_data()
    }

    /// Read all entries from the log. Returns an empty vec if the file does not exist.
    pub fn read_all(&self) -> std::io::Result<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let file = std::fs::File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(trimmed) {
                entries.push(entry);
            }
            // Silently skip malformed lines — the log is append-only and
            // a future version may add new fields that older readers ignore.
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(event: &str, pkg: &str) -> AuditEntry {
        AuditEntry {
            ts: Utc::now(),
            event: event.to_string(),
            package: pkg.to_string(),
            version: "1.0.0".to_string(),
            age_days: 30,
            checks_passed: vec!["age-gate".to_string()],
            user: "testuser".to_string(),
            reason: None,
        }
    }

    #[test]
    fn append_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());

        log.append(&sample_entry("install", "express")).unwrap();
        log.append(&sample_entry("install", "ms")).unwrap();

        let entries = log.read_all().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].package, "express");
        assert_eq!(entries[1].package, "ms");
    }

    #[test]
    fn read_all_returns_empty_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());
        assert!(log.read_all().unwrap().is_empty());
    }

    #[test]
    fn reason_omitted_when_none() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());
        log.append(&sample_entry("install", "pkg")).unwrap();

        let raw = std::fs::read_to_string(dir.path().join("vigil-audit.log")).unwrap();
        assert!(!raw.contains("reason"), "reason field should be omitted when None: {raw}");
    }

    #[test]
    fn reason_included_when_some() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());
        let mut e = sample_entry("install", "pkg");
        e.reason = Some("trusted internal package".to_string());
        log.append(&e).unwrap();

        let raw = std::fs::read_to_string(dir.path().join("vigil-audit.log")).unwrap();
        assert!(raw.contains("trusted internal package"), "reason should appear in log: {raw}");
    }

    #[test]
    fn skips_malformed_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());
        let path = dir.path().join("vigil-audit.log");
        // Write one good line and one bad line
        let good = serde_json::to_string(&sample_entry("install", "ms")).unwrap();
        std::fs::write(&path, format!("{good}\nnot-json\n")).unwrap();

        let entries = log.read_all().unwrap();
        assert_eq!(entries.len(), 1, "malformed line should be silently skipped");
    }
}
