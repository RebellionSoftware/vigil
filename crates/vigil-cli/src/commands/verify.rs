use clap::Args;
use std::env;
use vigil_core::{
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
