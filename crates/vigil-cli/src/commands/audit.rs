use clap::{Args, Subcommand};
use std::env;
use std::io::{BufRead, BufReader};
use std::path::Path;
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};

use crate::audit_log::{AuditEntry, AuditLog, AUDIT_LOG_FILENAME};

#[derive(Debug, Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommand,
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Display the audit log.
    Log(AuditLogArgs),

    /// Verify the audit log chain integrity.
    Verify,
}

#[derive(Debug, Args)]
pub struct AuditLogArgs {
    /// Filter by package name.
    #[arg(long)]
    pub package: Option<String>,

    /// Filter by event type (install, update, remove, block, import, trust).
    #[arg(long)]
    pub event: Option<String>,

    /// Show only the last N entries.
    #[arg(long, value_name = "N")]
    pub last: Option<usize>,
}

pub async fn run(args: AuditArgs) -> miette::Result<()> {
    match args.command {
        AuditCommand::Log(log_args) => show_log(log_args),
        AuditCommand::Verify => verify_chain(),
    }
}

fn show_log(args: AuditLogArgs) -> miette::Result<()> {
    let project_dir = env::current_dir()
        .map_err(|e| miette::miette!("cannot determine current directory: {e}"))?;

    let log = AuditLog::new(&project_dir);
    let mut entries = log
        .read_all()
        .map_err(|e| miette::miette!("failed to read audit log: {e}"))?;

    // Apply filters
    if let Some(ref pkg) = args.package {
        entries.retain(|e| &e.package == pkg);
    }
    if let Some(ref event) = args.event {
        entries.retain(|e| &e.event == event);
    }
    if let Some(n) = args.last {
        let len = entries.len();
        if len > n {
            entries = entries.into_iter().skip(len - n).collect();
        }
    }

    if entries.is_empty() {
        eprintln!("  No audit log entries found.");
        return Ok(());
    }

    // Header
    eprintln!(
        "\n  {:<26} {:<12} {:<30} {:<10} {}",
        "TIMESTAMP".bold(),
        "EVENT".bold(),
        "PACKAGE".bold(),
        "AGE (days)".bold(),
        "USER".bold(),
    );
    eprintln!("  {}", "─".repeat(90));

    for entry in &entries {
        let ts = entry.ts.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let event_colored = match entry.event.as_str() {
            "install" => entry.event.green().to_string(),
            "update"  => entry.event.cyan().to_string(),
            "remove"  => entry.event.red().to_string(),
            "block"   => entry.event.red().bold().to_string(),
            "import"  => entry.event.yellow().to_string(),
            "trust"   => entry.event.magenta().to_string(),
            _         => entry.event.clone(),
        };

        let pkg_ver = format!("{}@{}", entry.package, entry.version);
        eprintln!(
            "  {:<26} {:<12} {:<30} {:<10} {}",
            ts,
            event_colored,
            pkg_ver,
            entry.age_days,
            entry.user,
        );

        if let Some(ref reason) = entry.reason {
            eprintln!("    {} reason: {reason}", "→".dimmed());
        }
    }

    eprintln!("\n  {} entries", entries.len());
    Ok(())
}

fn verify_chain() -> miette::Result<()> {
    let project_dir = env::current_dir()
        .map_err(|e| miette::miette!("cannot determine current directory: {e}"))?;

    verify_chain_at(&project_dir.join(AUDIT_LOG_FILENAME))
}

/// Core chain verification logic. Accepts a path so it can be called from tests.
pub fn verify_chain_at(log_path: &Path) -> miette::Result<()> {
    let file = match std::fs::File::open(log_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("  {} no audit log found at {}", "✓".green(), AUDIT_LOG_FILENAME);
            return Ok(());
        }
        Err(e) => return Err(miette::miette!("failed to open {}: {e}", AUDIT_LOG_FILENAME)),
    };

    let reader = BufReader::new(file);

    // Collect raw lines exactly as BufReader yields them (trailing \n stripped,
    // no further trimming). The hash in each entry's prev_hash was computed from
    // these same bytes — trimming here would produce a mismatch.
    let mut lines: Vec<String> = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| miette::miette!("failed to read line: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        lines.push(line); // store raw, not trimmed
    }

    if lines.is_empty() {
        eprintln!("  {} audit log is empty", "✓".green());
        return Ok(());
    }

    let mut has_unverified_legacy = false;
    let mut chain_broken = false;

    for (i, line) in lines.iter().enumerate() {
        let entry: AuditEntry = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(e) => {
                // A line that cannot be parsed has an unverifiable prev_hash — treat as broken.
                eprintln!(
                    "  {} chain broken at entry {}: failed to parse: {e}",
                    "✗".red().bold(),
                    i + 1,
                );
                chain_broken = true;
                // Continue to surface any further breaks rather than aborting.
                continue;
            }
        };

        if i == 0 {
            if entry.prev_hash.is_some() {
                // A prev_hash on the first entry is unexpected: it claims a
                // predecessor but there is no entry at index -1 to verify
                // against. Could be prepend tampering or a migrated log.
                // Warn but do not fail — the remaining chain may be intact.
                eprintln!(
                    "  {} {}: first entry has an unexpected prev_hash — possible prepend or migration",
                    "!".yellow(),
                    AUDIT_LOG_FILENAME,
                );
            }
        } else {
            let prev_line = &lines[i - 1];
            let computed = hex::encode(Sha256::digest(prev_line.as_bytes()));

            if let Some(ref expected_hash) = entry.prev_hash {
                if &computed != expected_hash {
                    eprintln!(
                        "  {} chain broken at entry {}: hash mismatch",
                        "✗".red().bold(),
                        i + 1,
                    );
                    chain_broken = true;
                }
            } else {
                eprintln!(
                    "  {} entry {} has no prev_hash (legacy/unverified)",
                    "!".yellow(),
                    i + 1,
                );
                has_unverified_legacy = true;
            }
        }
    }

    if chain_broken {
        eprintln!("\n  {} audit log chain verification FAILED", "✗".red().bold());
        return Err(miette::miette!("audit log chain verification failed"));
    }

    if has_unverified_legacy {
        eprintln!(
            "\n  {} audit log contains legacy entries without chain hashes",
            "!".yellow(),
        );
        eprintln!("  Run `git log {}` to review full history", AUDIT_LOG_FILENAME);
        eprintln!(
            "  {} audit log chain verification PASSED (with unverified legacy entries)",
            "!".yellow(),
        );
    } else {
        eprintln!("  {} audit log chain verification PASSED", "✓".green());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_log::AuditLog;
    use chrono::Utc;

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
    fn verify_clean_chain_passes() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());
        log.append(&sample_entry("install", "a")).unwrap();
        log.append(&sample_entry("install", "b")).unwrap();
        log.append(&sample_entry("install", "c")).unwrap();

        let path = dir.path().join(AUDIT_LOG_FILENAME);
        assert!(verify_chain_at(&path).is_ok());
    }

    #[test]
    fn verify_absent_log_passes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILENAME);
        assert!(verify_chain_at(&path).is_ok());
    }

    #[test]
    fn verify_empty_log_passes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILENAME);
        std::fs::write(&path, "").unwrap();
        assert!(verify_chain_at(&path).is_ok());
    }

    #[test]
    fn verify_tampered_middle_entry_fails() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());
        log.append(&sample_entry("install", "a")).unwrap();
        log.append(&sample_entry("install", "b")).unwrap();
        log.append(&sample_entry("install", "c")).unwrap();

        let path = dir.path().join(AUDIT_LOG_FILENAME);
        let raw = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = raw.lines().collect();

        // Corrupt the second line by replacing the package name
        let corrupted = lines[1].replace("\"b\"", "\"TAMPERED\"");
        let tampered = format!("{}\n{}\n{}\n", lines[0], corrupted, lines[2]);
        std::fs::write(&path, tampered).unwrap();

        assert!(verify_chain_at(&path).is_err());
    }

    #[test]
    fn verify_deleted_middle_entry_fails() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());
        log.append(&sample_entry("install", "a")).unwrap();
        log.append(&sample_entry("install", "b")).unwrap();
        log.append(&sample_entry("install", "c")).unwrap();

        let path = dir.path().join(AUDIT_LOG_FILENAME);
        let raw = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = raw.lines().collect();

        // Remove the middle entry
        let without_middle = format!("{}\n{}\n", lines[0], lines[2]);
        std::fs::write(&path, without_middle).unwrap();

        assert!(verify_chain_at(&path).is_err());
    }

    #[test]
    fn verify_legacy_entries_pass_with_warning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILENAME);

        // Write two entries manually with no prev_hash (legacy format)
        let e1 = serde_json::to_string(&sample_entry("install", "a")).unwrap();
        let e2 = serde_json::to_string(&sample_entry("install", "b")).unwrap();
        std::fs::write(&path, format!("{e1}\n{e2}\n")).unwrap();

        // Legacy log (no prev_hash on non-first entries) should warn but not error
        assert!(verify_chain_at(&path).is_ok());
    }
}
