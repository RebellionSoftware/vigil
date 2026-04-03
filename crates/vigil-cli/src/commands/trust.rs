use clap::Args;
use std::env;
use vigil_core::{config::VigilConfig, lockfile::VigilLockfile};
use owo_colors::OwoColorize;

use crate::audit_log::{AuditEntry, AuditLog};

const PERMISSION_POSTINSTALL: &str = "postinstall";

#[derive(Debug, Args)]
pub struct TrustArgs {
    /// Package to configure trust for.
    pub package: String,

    /// Grant permission (currently only "postinstall" is supported).
    #[arg(long = "allow", value_name = "PERMISSION")]
    pub allow: Vec<String>,
}

pub async fn run(args: TrustArgs) -> miette::Result<()> {
    if args.allow.is_empty() {
        return Err(miette::miette!(
            "specify a permission to grant, e.g. --allow postinstall"
        ));
    }

    for perm in &args.allow {
        if perm != PERMISSION_POSTINSTALL {
            return Err(miette::miette!(
                "unknown permission '{perm}' — only 'postinstall' is supported in this version"
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
        if args.allow.contains(&PERMISSION_POSTINSTALL.to_string()) {
            let mut config = VigilConfig::load(&project_dir)
                .map_err(|e| miette::miette!("failed to load vigil.toml: {e}"))?;

            if !config.bypass.allow_postinstall.contains(&args.package) {
                config.bypass.allow_postinstall.push(args.package.clone());
                let contents = toml::to_string_pretty(&config)
                    .map_err(|e| miette::miette!("failed to serialize vigil.toml: {e}"))?;
                std::fs::write(project_dir.join("vigil.toml"), contents)
                    .map_err(|e| miette::miette!("failed to write vigil.toml: {e}"))?;
            }

            eprintln!(
                "  {} Pre-approved postinstall scripts for {}",
                "✓".green().bold(),
                args.package.bold(),
            );
            eprintln!(
                "\n  Run `vigil install {}` to install with scripts enabled.",
                args.package,
            );
            return Ok(());
        }
        return Err(miette::miette!(
            "'{}' not found in vigil.lock — install it first, or use `vigil trust` before installing",
            args.package
        ));
    }

    let mut lockfile = lockfile_opt.unwrap();

    let username = whoami::username();
    let audit = AuditLog::new(&project_dir);

    for key in &matched_keys {
        let entry = lockfile.packages.get_mut(key).unwrap();

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

    eprintln!(
        "\n  Run `vigil install` again to execute the approved scripts."
    );
    Ok(())
}
