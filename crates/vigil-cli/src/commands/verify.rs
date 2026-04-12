use clap::Args;
use std::env;
use vigil_core::{
    config::VigilConfig,
    hash::hash_package_dir,
    lockfile::VigilLockfile,
    overrides::{DriftIssue, OverridesManager},
};
use owo_colors::OwoColorize;

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Exit 1 if vigil.lock is missing (useful in CI).
    #[arg(long)]
    pub ci: bool,

    /// Check for uncommitted local changes to vigil.lock using git status.
    /// Warns if the lockfile has been modified but not committed — such changes
    /// may indicate tampering in a shared or CI environment.
    ///
    /// Combined with --ci, an uncommitted vigil.lock is treated as a hard failure.
    /// Has no effect if vigil.lock is listed in .gitignore.
    #[arg(long)]
    pub git: bool,
}

pub async fn run(args: VerifyArgs) -> miette::Result<()> {
    let project_dir = env::current_dir()
        .map_err(|e| miette::miette!("cannot determine current directory: {e}"))?;

    // ── Load lockfile ─────────────────────────────────────────────────────────
    let lockfile = match VigilLockfile::read_optional(&project_dir)
        .map_err(|e| miette::miette!("failed to read vigil.lock: {e}"))?
    {
        Some(lf) => lf,
        None => {
            if args.ci {
                return Err(miette::miette!(
                    "vigil.lock not found — run `vigil install` before CI verify"
                ));
            }
            eprintln!("  {} vigil.lock not found — nothing to verify", "!".yellow());
            return Ok(());
        }
    };

    let mut failures: Vec<String> = Vec::new();

    // ── Hash verification ─────────────────────────────────────────────────────
    let node_modules = project_dir.join("node_modules");

    for (key, entry) in &lockfile.packages {
        let (pkg_name, _) = key.rsplit_once('@').unwrap_or((key.as_str(), ""));

        match hash_package_dir(&node_modules, pkg_name) {
            Ok(actual_hash) => {
                if actual_hash != entry.content_hash {
                    // Disk hashes use "sha512-" + 128 hex chars (135 total).
                    // Registry dist.integrity uses base64 (~95 chars) and is stored
                    // for packages installed before vigil computed a disk hash.
                    let is_disk_hash = entry.content_hash.starts_with("sha512-")
                        && entry.content_hash.len() == 135;

                    if is_disk_hash {
                        failures.push(format!(
                            "hash mismatch for {key}\n    expected: {}\n    actual:   {actual_hash}",
                            entry.content_hash,
                        ));
                    } else if args.ci {
                        // In CI, a missing disk hash is a failure: every package must
                        // have been hashed by a prior `vigil install` run.
                        failures.push(format!(
                            "{key}: disk hash not yet recorded — run `vigil install` and commit vigil.lock"
                        ));
                    } else {
                        eprintln!(
                            "  {} {key}: disk hash not yet recorded — run `vigil install` to compute it",
                            "!".yellow(),
                        );
                    }
                }
            }
            Err(_) => {
                failures.push(format!(
                    "{key}: not found in node_modules — run `vigil install` to restore it"
                ));
            }
        }
    }

    // ── Overrides drift detection ─────────────────────────────────────────────
    match OverridesManager::detect_drift(&project_dir, &lockfile) {
        Ok(drift) => {
            for d in &drift {
                let msg = match &d.issue {
                    DriftIssue::MissingFromOverrides { expected_version } => {
                        format!("overrides drift: '{}' missing (expected {})", d.package, expected_version)
                    }
                    DriftIssue::ExtraInOverrides { actual_version } => {
                        format!("overrides drift: '{}@{}' in overrides but not in lockfile", d.package, actual_version)
                    }
                    DriftIssue::VersionMismatch { expected, actual } => {
                        format!("overrides drift: '{}' pinned to {} but lockfile says {}", d.package, actual, expected)
                    }
                    DriftIssue::SentinelMissing => {
                        "overrides block is missing the _vigil sentinel — may not be managed by vigil".to_string()
                    }
                };
                failures.push(msg);
            }
        }
        Err(e) => {
            failures.push(format!("could not read package.json overrides: {e}"));
        }
    }

    // ── vigil.toml integrity ──────────────────────────────────────────────────
    // If the lockfile records a config hash, verify vigil.toml hasn't changed.
    if let Some(stored_hash) = &lockfile.meta.config_hash {
        match VigilConfig::load_with_hash(&project_dir) {
            Ok((_, Some(actual_hash))) => {
                if &actual_hash != stored_hash {
                    failures.push(
                        "vigil.toml has been modified since last install — \
                         re-run `vigil install` to update the lockfile".to_string(),
                    );
                }
            }
            Ok((_, None)) => {
                failures.push(
                    "vigil.toml is missing — policy configuration may have been removed".to_string(),
                );
            }
            Err(e) => {
                failures.push(format!("could not read vigil.toml: {e}"));
            }
        }
    }

    // ── Git-backed integrity check ─────────────────────────────────────────────
    if args.git {
        if let Some(msg) = check_git_status(&project_dir) {
            eprintln!("  {} {msg}", "!".yellow());
            eprintln!(
                "    Run `git diff vigil.lock` to see changes, or `git checkout vigil.lock` to restore"
            );
            if args.ci {
                failures.push(msg);
            }
        }
    }

    // ── Report ────────────────────────────────────────────────────────────────
    if failures.is_empty() {
        let n = lockfile.packages.len();
        eprintln!(
            "\n  {} {} package{} verified — all hashes match",
            "✓".green().bold(),
            n,
            if n == 1 { "" } else { "s" },
        );
        Ok(())
    } else {
        eprintln!("\n  {} Verification failed:\n", "✗".red().bold());
        for f in &failures {
            eprintln!("    {} {f}", "✗".red());
        }
        eprintln!();
        Err(miette::miette!("{} verification failure{}", failures.len(), if failures.len() == 1 { "" } else { "s" }))
    }
}

/// Run `git status --porcelain vigil.lock` and return a warning message if the
/// file has uncommitted local changes, or `None` if it is clean.
///
/// Returns `None` (with a warning to stderr) if git is not available or fails,
/// so callers can treat the check as non-fatal degradation.
fn check_git_status(project_dir: &std::path::Path) -> Option<String> {
    let output = match std::process::Command::new("git")
        .args(["status", "--porcelain", "vigil.lock"])
        .current_dir(project_dir)
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("  {} git not found — skipping --git check", "!".yellow());
            return None;
        }
        Err(e) => {
            eprintln!("  {} could not run git status: {e}", "!".yellow());
            return None;
        }
    };

    if !output.status.success() {
        // git failed (e.g. not a git repository, safe.directory rejection).
        // Warn and skip rather than panic or produce a false positive.
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!(
            "  {} git status failed (exit {}): {} — skipping --git check",
            "!".yellow(),
            output.status.code().unwrap_or(-1),
            stderr.trim(),
        );
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.trim().is_empty() {
        return Some(
            "vigil.lock has uncommitted local changes — lockfile may have been tampered with"
                .to_string(),
        );
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_git_dir_returns_none() {
        // A directory with no .git ancestor causes git to exit 128.
        // check_git_status should warn to stderr and return None (not panic).
        let dir = tempfile::tempdir().unwrap();
        let result = check_git_status(dir.path());
        assert!(result.is_none(), "non-git directory should return None, got: {result:?}");
    }

    #[test]
    fn clean_committed_lockfile_returns_none() {
        let dir = tempfile::tempdir().unwrap();

        // Skip if git is not available on this machine.
        if std::process::Command::new("git").arg("--version").output().is_err() {
            return;
        }

        // Initialise a repo, commit vigil.lock, then verify it is clean.
        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@test.com")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@test.com")
                .output()
                .unwrap()
        };

        run(&["init"]);
        run(&["config", "user.email", "test@test.com"]);
        run(&["config", "user.name", "test"]);
        std::fs::write(dir.path().join("vigil.lock"), "{}").unwrap();
        run(&["add", "vigil.lock"]);
        run(&["commit", "-m", "init"]);

        let result = check_git_status(dir.path());
        assert!(result.is_none(), "clean committed lockfile should return None");
    }

    #[test]
    fn dirty_lockfile_returns_some() {
        let dir = tempfile::tempdir().unwrap();

        // Skip if git is not available on this machine.
        if std::process::Command::new("git").arg("--version").output().is_err() {
            return;
        }

        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@test.com")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@test.com")
                .output()
                .unwrap()
        };

        run(&["init"]);
        run(&["config", "user.email", "test@test.com"]);
        run(&["config", "user.name", "test"]);
        std::fs::write(dir.path().join("vigil.lock"), "{}").unwrap();
        run(&["add", "vigil.lock"]);
        run(&["commit", "-m", "init"]);

        // Modify the lockfile without committing.
        std::fs::write(dir.path().join("vigil.lock"), "{\"modified\": true}").unwrap();

        let result = check_git_status(dir.path());
        assert!(result.is_some(), "dirty lockfile should return a warning message");
    }
}
