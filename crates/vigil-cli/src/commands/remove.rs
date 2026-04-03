use clap::Args;
use std::collections::HashSet;
use std::env;
use vigil_core::{
    bun::BunRunner,
    config::VigilConfig,
    lockfile::VigilLockfile,
    overrides::OverridesManager,
};
use owo_colors::OwoColorize;

use crate::audit_log::{AuditEntry, AuditLog};

#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Package(s) to remove.
    pub packages: Vec<String>,
}

pub async fn run(args: RemoveArgs) -> miette::Result<()> {
    if args.packages.is_empty() {
        return Err(miette::miette!("specify at least one package to remove"));
    }

    let project_dir = env::current_dir()
        .map_err(|e| miette::miette!("cannot determine current directory: {e}"))?;

    let _config = VigilConfig::load(&project_dir)
        .map_err(|e| miette::miette!("failed to load vigil.toml: {e}"))?;

    let mut lockfile = VigilLockfile::read(&project_dir)
        .map_err(|e| miette::miette!(
            "vigil.lock not found — run `vigil install` first: {e}"
        ))?;

    let username = whoami::username();
    let audit = AuditLog::new(&project_dir);

    // ── Resolve which direct packages to remove ───────────────────────────────
    let mut direct_keys: Vec<String> = Vec::new();
    let mut removed_names: HashSet<String> = HashSet::new();

    for pkg_name in &args.packages {
        let key = lockfile.packages.iter()
            .find(|(k, p)| {
                p.direct && k.rsplit_once('@').map(|(n, _)| n) == Some(pkg_name.as_str())
            })
            .map(|(k, _)| k.clone());

        match key {
            Some(k) => {
                direct_keys.push(k);
                removed_names.insert(pkg_name.clone());
            }
            None => {
                eprintln!("  {} '{}' not found in vigil.lock — skipping", "!".yellow(), pkg_name);
            }
        }
    }

    if direct_keys.is_empty() {
        return Ok(());
    }

    // ── Single-pass orphan detection across ALL removed packages ─────────────
    // A transitive is orphaned when every entry in its transitive_of list
    // is in the set being removed in this invocation. Computing this upfront
    // (before any mutation) ensures multi-package removes are handled correctly
    // (e.g. `vigil remove express koa` orphans `ms` if ms.transitive_of == ["express","koa"]).
    let removed_name_refs: HashSet<&str> = removed_names.iter().map(|s| s.as_str()).collect();
    let orphan_keys = collect_orphans(&lockfile, &removed_name_refs);

    // ── Remove direct packages ────────────────────────────────────────────────
    for key in &direct_keys {
        let (name, version) = key.rsplit_once('@').unwrap_or((key.as_str(), ""));
        lockfile.packages.remove(key);
        eprintln!("  {} {key}", "-".red().bold());
        let _ = audit.append(&AuditEntry {
            ts: chrono::Utc::now(),
            event: "remove".to_string(),
            package: name.to_string(),
            version: version.to_string(),
            age_days: 0,
            checks_passed: vec![],
            user: username.clone(),
            reason: None,
        });
    }

    // ── Remove orphaned transitives ───────────────────────────────────────────
    for orphan_key in &orphan_keys {
        let (oname, over) = orphan_key.rsplit_once('@').unwrap_or((orphan_key.as_str(), ""));
        lockfile.packages.remove(orphan_key);
        eprintln!("  {} {} (orphaned transitive)", "-".red(), orphan_key);
        let _ = audit.append(&AuditEntry {
            ts: chrono::Utc::now(),
            event: "remove".to_string(),
            package: oname.to_string(),
            version: over.to_string(),
            age_days: 0,
            checks_passed: vec![],
            user: username.clone(),
            reason: Some(format!("orphaned transitive of {}", removed_names.iter().cloned().collect::<Vec<_>>().join(", "))),
        });
    }

    // ── Write overrides (removes entries for removed/orphaned packages) ────────
    let overrides = OverridesManager::generate_overrides(&lockfile);
    OverridesManager::write_overrides(&project_dir, &overrides)
        .map_err(|e| miette::miette!("failed to update package.json overrides: {e}"))?;

    // ── Run bun remove ────────────────────────────────────────────────────────
    let bun = BunRunner::new(&project_dir)
        .map_err(|e| miette::miette!("{e}"))?;

    let pkg_refs: Vec<&str> = args.packages.iter().map(|s| s.as_str()).collect();
    bun.remove(&pkg_refs)
        .await
        .map_err(|e| miette::miette!("bun failed: {e}"))?;

    // ── Write lockfile ────────────────────────────────────────────────────────
    lockfile
        .write(&project_dir)
        .map_err(|e| miette::miette!("failed to write vigil.lock: {e}"))?;

    eprintln!(
        "\n  {} Removed {}",
        "✓".green().bold(),
        args.packages.join(", "),
    );
    Ok(())
}

// ── Orphan detection ──────────────────────────────────────────────────────────

/// Return the lockfile keys of all transitives that become orphaned when
/// `removed_names` are removed.
///
/// A transitive is orphaned when **every** entry in its `transitive_of` list
/// is in `removed_names`. Because `transitive_of` stores direct package names
/// (never intermediate transitives), one pass is always sufficient.
#[cfg_attr(not(test), allow(dead_code))]
pub fn collect_orphans<'a>(lockfile: &VigilLockfile, removed_names: &HashSet<&'a str>) -> Vec<String> {
    lockfile
        .packages
        .iter()
        .filter(|(_, p)| {
            !p.direct
                && !p.transitive_of.is_empty()
                && p.transitive_of.iter().all(|owner| removed_names.contains(owner.as_str()))
        })
        .map(|(k, _)| k.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_core::lockfile::{LockedPackage, VigilLockfile};
    use chrono::Utc;

    fn pkg(direct: bool, transitive_of: &[&str]) -> LockedPackage {
        LockedPackage {
            content_hash: "sha512-x".into(),
            published_at: Utc::now(),
            age_at_install_days: 30,
            direct,
            transitive_of: transitive_of.iter().map(|s| s.to_string()).collect(),
            postinstall_approved: false,
            installed_at: Utc::now(),
            installed_by: "test".into(),
        }
    }

    fn build_lockfile(entries: &[(&str, LockedPackage)]) -> VigilLockfile {
        let mut lf = VigilLockfile::new();
        for (key, p) in entries {
            lf.packages.insert(key.to_string(), p.clone());
        }
        lf
    }

    fn names<'a>(s: &[&'a str]) -> HashSet<&'a str> {
        s.iter().copied().collect()
    }

    #[test]
    fn orphan_detection_simple() {
        let lf = build_lockfile(&[
            ("express@4.18.2", pkg(true, &[])),
            ("ms@2.1.3", pkg(false, &["express"])),
        ]);
        let orphans = collect_orphans(&lf, &names(&["express"]));
        assert_eq!(orphans, vec!["ms@2.1.3"]);
    }

    #[test]
    fn shared_transitive_not_orphaned_single_remove() {
        let lf = build_lockfile(&[
            ("express@4.18.2", pkg(true, &[])),
            ("debug@4.4.3",    pkg(true, &[])),
            ("ms@2.1.3", pkg(false, &["express", "debug"])),
        ]);
        let orphans = collect_orphans(&lf, &names(&["express"]));
        assert!(orphans.is_empty(), "ms is still owned by debug: {orphans:?}");
    }

    #[test]
    fn shared_transitive_orphaned_when_both_owners_removed() {
        // This is the multi-remove case that the old inline logic got wrong.
        let lf = build_lockfile(&[
            ("express@4.18.2", pkg(true, &[])),
            ("debug@4.4.3",    pkg(true, &[])),
            ("ms@2.1.3", pkg(false, &["express", "debug"])),
        ]);
        let orphans = collect_orphans(&lf, &names(&["express", "debug"]));
        assert_eq!(orphans, vec!["ms@2.1.3"], "ms should be orphaned when both owners are removed");
    }

    #[test]
    fn multiple_orphans_removed() {
        let lf = build_lockfile(&[
            ("webpack@5.0.0", pkg(true, &[])),
            ("acorn@8.0.0",      pkg(false, &["webpack"])),
            ("acorn-walk@8.0.0", pkg(false, &["webpack"])),
        ]);
        let mut orphans = collect_orphans(&lf, &names(&["webpack"]));
        orphans.sort();
        assert_eq!(orphans, vec!["acorn-walk@8.0.0", "acorn@8.0.0"]);
    }

    #[test]
    fn removing_non_existent_package_returns_no_orphans() {
        let lf = build_lockfile(&[
            ("express@4.18.2", pkg(true, &[])),
        ]);
        let orphans = collect_orphans(&lf, &names(&["nonexistent"]));
        assert!(orphans.is_empty());
    }
}
