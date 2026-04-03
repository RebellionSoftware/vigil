use clap::Args;
use std::env;
use vigil_core::lockfile::VigilLockfile;
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

    let mut lockfile = VigilLockfile::read(&project_dir)
        .map_err(|e| miette::miette!(
            "vigil.lock not found — run `vigil install` first: {e}"
        ))?;

    // Find the entry for this package (direct or transitive).
    let matched_keys: Vec<String> = lockfile
        .packages
        .keys()
        .filter(|k| {
            k.rsplit_once('@').map(|(name, _)| name) == Some(args.package.as_str())
        })
        .cloned()
        .collect();

    if matched_keys.is_empty() {
        return Err(miette::miette!(
            "'{}' not found in vigil.lock — install it first",
            args.package
        ));
    }

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
