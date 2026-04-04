use clap::Args;
use std::{env, path::Path};
use vigil_core::{config::VigilConfig, lockfile::VigilLockfile, types::PackageName};
use owo_colors::OwoColorize;

use crate::audit_log::{AuditEntry, AuditLog};

const PERMISSION_POSTINSTALL: &str = "postinstall";
const PERMISSION_INACTIVITY: &str = "inactivity";

/// Write `vigil.toml` atomically: serialize to a temp file then rename over the
/// original. Matches the pattern used by `VigilLockfile::write` so a crash
/// during the write cannot leave a zero-byte or partially-written config.
fn write_vigil_toml(project_dir: &Path, config: &VigilConfig) -> miette::Result<()> {
    let path = project_dir.join("vigil.toml");
    let tmp_path = project_dir.join("vigil.toml.tmp");
    let contents = toml::to_string_pretty(config)
        .map_err(|e| miette::miette!("failed to serialize vigil.toml: {e}"))?;
    std::fs::write(&tmp_path, &contents)
        .map_err(|e| miette::miette!("failed to write vigil.toml.tmp: {e}"))?;
    std::fs::rename(&tmp_path, &path)
        .map_err(|e| miette::miette!("failed to replace vigil.toml: {e}"))
}

#[derive(Debug, Args)]
pub struct TrustArgs {
    /// Package to configure trust for.
    pub package: String,

    /// Grant permission (currently only "postinstall" is supported).
    #[arg(long = "allow", value_name = "PERMISSION")]
    pub allow: Vec<String>,
}

pub async fn run(args: TrustArgs) -> miette::Result<()> {
    // Validate the package name up front so we never write an invalid name into
    // vigil.toml. An unvalidated name stored in allow_inactivity or allow_postinstall
    // would silently fail to match at check time (the check compares against validated
    // PackageName strings), making the bypass ineffective without any error.
    PackageName::new(&args.package)
        .map_err(|_| miette::miette!("invalid package name: '{}'", args.package))?;

    if args.allow.is_empty() {
        return Err(miette::miette!(
            "specify a permission to grant, e.g. --allow postinstall"
        ));
    }

    for perm in &args.allow {
        if perm != PERMISSION_POSTINSTALL && perm != PERMISSION_INACTIVITY {
            return Err(miette::miette!(
                "unknown permission '{perm}' — supported permissions: postinstall, inactivity"
            ));
        }
    }

    let project_dir = env::current_dir()
        .map_err(|e| miette::miette!("cannot determine current directory: {e}"))?;

    // If the package is not yet installed (common when block_postinstall blocks the first
    // install), store the approval in vigil.toml [bypass] allow_postinstall so the next
    // `vigil install` can proceed.
    let lockfile_opt = VigilLockfile::read_optional(&project_dir)
        .map_err(|e| miette::miette!("failed to read vigil.lock: {e}"))?;

    let matched_keys: Vec<String> = lockfile_opt.as_ref().map(|lf| {
        lf.packages
            .keys()
            .filter(|k| k.rsplit_once('@').map(|(n, _)| n) == Some(args.package.as_str()))
            .cloned()
            .collect()
    }).unwrap_or_default();

    // Package not yet installed — write a pre-approval to vigil.toml instead.
    if matched_keys.is_empty() {
        let has_postinstall = args.allow.contains(&PERMISSION_POSTINSTALL.to_string());
        let has_inactivity = args.allow.contains(&PERMISSION_INACTIVITY.to_string());

        if has_postinstall || has_inactivity {
            let mut config = VigilConfig::load(&project_dir)
                .map_err(|e| miette::miette!("failed to load vigil.toml: {e}"))?;

            if has_postinstall && !config.bypass.allow_postinstall.contains(&args.package) {
                config.bypass.allow_postinstall.push(args.package.clone());
            }

            if has_inactivity && !config.bypass.allow_inactivity.contains(&args.package) {
                config.bypass.allow_inactivity.push(args.package.clone());
            }

            write_vigil_toml(&project_dir, &config)?;

            if has_postinstall {
                eprintln!(
                    "  {} Pre-approved postinstall scripts for {}",
                    "✓".green().bold(),
                    args.package.bold(),
                );
            }

            if has_inactivity {
                eprintln!(
                    "  {} Pre-approved inactivity bypass for {}",
                    "✓".green().bold(),
                    args.package.bold(),
                );
            }

            let run_msg = if has_postinstall {
                format!("Run `vigil install {}` to install with scripts enabled.", args.package)
            } else {
                format!("Run `vigil install {}` to complete installation.", args.package)
            };
            eprintln!("\n  {run_msg}");
            return Ok(());
        }
        return Err(miette::miette!(
            "'{}' not found in vigil.lock — install it first, or use `vigil trust` before installing",
            args.package
        ));
    }

    // SAFETY: matched_keys is populated from lockfile_opt.as_ref(), so if
    // lockfile_opt were None, matched_keys would be empty and we'd have returned above.
    let mut lockfile = lockfile_opt.expect("lockfile must be Some when matched_keys is non-empty");

    let username = whoami::username();
    let audit = AuditLog::new(&project_dir);

    // Write inactivity approval to vigil.toml once, before iterating lockfile entries.
    // Doing this inside the loop would re-read and re-write the file on every matched key,
    // meaning the last write wins and concurrent invocations could silently drop each other's changes.
    if args.allow.contains(&PERMISSION_INACTIVITY.to_string()) {
        let mut config = VigilConfig::load(&project_dir)
            .map_err(|e| miette::miette!("failed to load vigil.toml: {e}"))?;
        if !config.bypass.allow_inactivity.contains(&args.package) {
            config.bypass.allow_inactivity.push(args.package.clone());
            write_vigil_toml(&project_dir, &config)?;
        }
        eprintln!(
            "  {} Approved inactivity bypass for {}",
            "✓".green().bold(),
            args.package.bold(),
        );
    }

    for key in &matched_keys {
        // SAFETY: matched_keys was collected from lockfile.packages.keys() and
        // no code between collection and this loop modifies lockfile.packages.
        let entry = lockfile.packages.get_mut(key)
            .expect("key collected from lockfile.packages must still be present");

        if args.allow.contains(&PERMISSION_POSTINSTALL.to_string()) {
            entry.postinstall_approved = true;
            eprintln!(
                "  {} Approved postinstall scripts for {}",
                "✓".green().bold(),
                key.bold(),
            );
        }

        let (name, version) = key.rsplit_once('@').unwrap_or((key.as_str(), ""));
        if let Err(e) = audit.append(&AuditEntry {
            ts: chrono::Utc::now(),
            event: "trust".to_string(),
            package: name.to_string(),
            version: version.to_string(),
            age_days: entry.age_at_install_days,
            checks_passed: vec![],
            user: username.clone(),
            reason: Some(format!("approved: {}", args.allow.join(", "))),
        }) {
            // Trust decisions MUST be audited — fail loudly if the log write fails.
            return Err(miette::miette!("failed to write trust decision to audit log: {e}"));
        }
    }

    lockfile
        .write(&project_dir)
        .map_err(|e| miette::miette!("failed to write vigil.lock: {e}"))?;

    let run_msg = if args.allow.contains(&PERMISSION_POSTINSTALL.to_string()) {
        "Run `vigil install` again to execute the approved scripts."
    } else {
        "Run `vigil install` again to complete installation."
    };
    eprintln!("\n  {run_msg}");
    Ok(())
}
