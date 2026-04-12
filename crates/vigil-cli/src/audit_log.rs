use chrono::{DateTime, Utc};
use fd_lock::RwLock as FdRwLock;
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub const AUDIT_LOG_FILENAME: &str = "vigil-audit.log";

/// A single entry in the vigil audit log.
///
/// Serialized as one JSON object per line (NDJSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// RFC 3339 timestamp of the event.
    pub ts: DateTime<Utc>,
    /// Event type: "install", "import", "block", "update", "remove", "trust", "verify_pass", "verify_fail".
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
    /// True if installed as a dev dependency (devDependencies).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dev: bool,
    /// True if installed as an optional dependency (optionalDependencies).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub optional: bool,
    /// Human-readable reason (required for bypasses, optional otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// SHA-256 hex digest of the previous raw log line. `None` on the first entry.
    ///
    /// Forms a tamper-evident chain: deleting, inserting, or modifying any line
    /// breaks the hash linkage detectable by `vigil audit verify`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
}

/// Return the SHA-256 hex digest of the last non-empty line in `file`, or
/// `None` if the file is empty.
///
/// **Verification note:** The hash is computed from the raw bytes as written to
/// disk (trailing `\n` stripped by `BufReader::lines`, no other trimming). Any
/// verifier (`vigil audit verify`) must re-read the raw file line by line and
/// hash the same raw bytes — do NOT re-serialize from parsed `AuditEntry`
/// structs, as `serde_json` field ordering could differ from what was written.
fn last_line_hash(file: &mut std::fs::File) -> std::io::Result<Option<String>> {
    file.seek(SeekFrom::Start(0))?;
    let reader = BufReader::new(&*file);
    let mut last: Option<String> = None;
    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            last = Some(line);
        }
    }
    Ok(last.map(|l| hex::encode(Sha256::digest(l.as_bytes()))))
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
    ///
    /// Sets `prev_hash` on the entry to the SHA-256 hex digest of the last raw
    /// log line before appending, forming a tamper-evident chain. The first
    /// entry gets `prev_hash: None` — git history is the out-of-band anchor.
    pub fn append(&self, entry: &AuditEntry) -> std::io::Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(&self.path)?;

        let mut lock = FdRwLock::new(file);
        let mut guard = lock.write()?;

        // Read the last non-empty line while holding the lock so the hash
        // reflects the true tail of the file at write time.
        let prev_hash = last_line_hash(&mut *guard)?;

        // Seek to end after acquiring the lock so we always append even when
        // another process has written since we opened the file.
        guard.seek(SeekFrom::End(0))?;

        let mut entry = entry.clone();
        entry.prev_hash = prev_hash;

        let line = serde_json::to_string(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        writeln!(*guard, "{line}")?;
        // Flush kernel page cache to disk before releasing the lock so audit
        // entries are durable even if the process crashes immediately after.
        (*guard).sync_data()
    }

    /// Read all entries from the log. Returns an empty vec if the file does not exist.
    ///
    /// Lines that cannot be parsed as `AuditEntry` are skipped with a warning printed
    /// to stderr. Parsing continues for all remaining lines after a malformed line.
    pub fn read_all(&self) -> std::io::Result<Vec<AuditEntry>> {
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e),
        };
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
            } else {
                // Strip control characters before printing to stderr to prevent
                // ANSI escape injection from a crafted log file.
                const MAX_DISPLAY: usize = 120;
                let safe: String = trimmed
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(MAX_DISPLAY)
                    .collect();
                let ellipsis = if trimmed.len() > MAX_DISPLAY {
                    "…"
                } else {
                    ""
                };
                eprintln!(
                    "  {} warning: skipped malformed line in {}: {}{ellipsis}",
                    "!".yellow(),
                    AUDIT_LOG_FILENAME,
                    safe,
                );
            }
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
            dev: false,
            optional: false,
            reason: None,
            prev_hash: None,
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
        assert!(
            !raw.contains("reason"),
            "reason field should be omitted when None: {raw}"
        );
    }

    #[test]
    fn reason_included_when_some() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());
        let mut e = sample_entry("install", "pkg");
        e.reason = Some("trusted internal package".to_string());
        log.append(&e).unwrap();

        let raw = std::fs::read_to_string(dir.path().join("vigil-audit.log")).unwrap();
        assert!(
            raw.contains("trusted internal package"),
            "reason should appear in log: {raw}"
        );
    }

    #[test]
    // The warning is emitted to stderr but not captured here; the test verifies
    // the entry is skipped and parsing does not abort.
    fn skips_malformed_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());
        let path = dir.path().join("vigil-audit.log");
        let good = serde_json::to_string(&sample_entry("install", "ms")).unwrap();
        std::fs::write(&path, format!("{good}\nnot-json\n")).unwrap();

        let entries = log.read_all().unwrap();
        assert_eq!(entries.len(), 1, "malformed line should be skipped");
    }

    #[test]
    fn append_overwrites_caller_prev_hash() {
        // append() must always compute prev_hash itself — a caller-supplied value
        // must be ignored so callers cannot inject a fabricated chain link.
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());
        let mut e = sample_entry("install", "a");
        e.prev_hash = Some("caller-should-not-control-this".to_string());
        log.append(&e).unwrap();

        let raw = std::fs::read_to_string(dir.path().join("vigil-audit.log")).unwrap();
        let v: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert!(
            v.get("prev_hash").is_none(),
            "first entry must have no prev_hash regardless of caller input: {v}"
        );
    }

    #[test]
    fn prev_hash_chain_is_correct() {
        use sha2::{Digest, Sha256};

        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());

        log.append(&sample_entry("install", "a")).unwrap();
        log.append(&sample_entry("install", "b")).unwrap();
        log.append(&sample_entry("install", "c")).unwrap();

        let raw = std::fs::read_to_string(dir.path().join("vigil-audit.log")).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 3);

        // First entry: no prev_hash
        let e0: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert!(
            e0.get("prev_hash").is_none(),
            "first entry must have no prev_hash"
        );

        // Second entry: prev_hash == SHA-256 of first raw line
        let e1: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        let expected1 = format!("{:x}", Sha256::digest(lines[0].as_bytes()));
        assert_eq!(e1["prev_hash"].as_str().unwrap(), expected1);

        // Third entry: prev_hash == SHA-256 of second raw line
        let e2: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        let expected2 = format!("{:x}", Sha256::digest(lines[1].as_bytes()));
        assert_eq!(e2["prev_hash"].as_str().unwrap(), expected2);
    }

    #[test]
    fn continues_parsing_after_malformed_line() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());
        let path = dir.path().join("vigil-audit.log");
        let good1 = serde_json::to_string(&sample_entry("install", "ms")).unwrap();
        let good2 = serde_json::to_string(&sample_entry("install", "express")).unwrap();
        std::fs::write(&path, format!("{good1}\nnot-json\n{good2}\n")).unwrap();

        let entries = log.read_all().unwrap();
        assert_eq!(
            entries.len(),
            2,
            "valid entries after a malformed line must be parsed"
        );
        assert_eq!(entries[0].package, "ms");
        assert_eq!(entries[1].package, "express");
    }
}
