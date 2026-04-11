use clap::Args;
use std::env;
use vigil_core::{
    bun::BunRunner,
    config::VigilConfig,
    hash::hash_package_dir,
    lockfile::{diff, generate_from_tree, merge_into, VigilLockfile},
    overrides::OverridesManager,
    policy::PolicyEngine,
    resolver::DependencyResolver,
    types::PackageName,
};
use vigil_registry::NpmRegistryClient;
use owo_colors::OwoColorize;

use crate::{audit_log::{AuditEntry, AuditLog}, output};

#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Package(s) to update. Omit to use --all.
    pub packages: Vec<String>,

    /// Update only the transitive deps of the specified package, not the package itself.
    #[arg(long)]
    pub transitive: bool,

    /// Update all packages and their transitive deps.
    #[arg(long, conflicts_with = "packages")]
    pub all: bool,

    /// Bypass age gate for specific package(s). Requires --reason.
    #[arg(long, value_name = "PACKAGE")]
    pub allow_fresh: Vec<String>,

    /// Reason for bypassing a check.
    #[arg(long, requires = "allow_fresh")]
    pub reason: Option<String>,
}

pub async fn run(args: UpdateArgs) -> miette::Result<()> {
    let project_dir = env::current_dir()
        .map_err(|e| miette::miette!("cannot determine current directory: {e}"))?;

    // Validate user-supplied package names and bypass flags before any I/O.
    for name in &args.packages {
        PackageName::new(name)
            .map_err(|e| miette::miette!("invalid package name '{name}': {e}"))?;
    }
    for name in &args.allow_fresh {
        PackageName::new(name)
            .map_err(|e| miette::miette!("invalid package name '{name}': {e}"))?;
    }

    let (config, config_hash) = VigilConfig::load_with_hash(&project_dir)
        .map_err(|e| miette::miette!("failed to load vigil.toml: {e}"))?;

    let mut existing_lockfile = VigilLockfile::read(&project_dir)
        .map_err(|e| miette::miette!(
            "vigil.lock not found or invalid — run `vigil install` first: {e}"
        ))?;

    // ── Build specifier list ──────────────────────────────────────────────────
    // Targets get bare names (resolver picks latest). All other current directs
    // are pinned at their existing exact version so they don't change.
    let current_directs: Vec<(String, String)> = existing_lockfile
        .packages
        .iter()
        .filter(|(_, p)| p.direct)
        .map(|(key, _)| {
            let (name, ver) = key.rsplit_once('@').unwrap_or((key.as_str(), ""));
            (name.to_string(), ver.to_string())
        })
        .collect();

    let targets: Vec<String> = if args.all {
        current_directs.iter().map(|(n, _)| n.clone()).collect()
    } else if args.packages.is_empty() {
        return Err(miette::miette!("specify package(s) to update or use --all"));
    } else {
        args.packages.clone()
    };

    let target_set: std::collections::HashSet<&str> =
        targets.iter().map(|s| s.as_str()).collect();

    let specifiers: Vec<String> = current_directs
        .iter()
        .map(|(name, ver)| {
            if target_set.contains(name.as_str()) {
                name.clone() // bare → latest
            } else {
                format!("{name}@{ver}") // pinned at current version
            }
        })
        .collect();

    // ── Resolve new tree ──────────────────────────────────────────────────────
    let registry = NpmRegistryClient::new();
    let mut resolver = DependencyResolver::new(registry, config.policy.clone());

    eprintln!("Resolving {}…", targets.join(", "));
    let spec_refs: Vec<&str> = specifiers.iter().map(|s| s.as_str()).collect();
    let tree = resolver
        .resolve(&spec_refs)
        .await
        .map_err(|e| miette::miette!("dependency resolution failed: {e}"))?;

    // ── Policy checks ─────────────────────────────────────────────────────────
    let mut bypass = config.bypass.clone();
    bypass.allow_fresh.extend(args.allow_fresh.clone());

    let engine = PolicyEngine::new(config.policy.clone(), bypass, config.blocked.clone());
    let report = engine.check_tree(&tree, Some(&existing_lockfile));

    let has_blockers = output::print_check_report(&report, &tree);
    if has_blockers {
        return Err(output::print_blocked_and_fail(&report));
    }

    // ── Diff and display ──────────────────────────────────────────────────────
    let username = whoami::username();
    let new_lockfile = generate_from_tree(&tree, &username);
    let lockfile_diff = diff(&existing_lockfile, &new_lockfile);

    if lockfile_diff.is_empty() {
        eprintln!("  {} All specified packages already up to date.", "✓".green());
        return Ok(());
    }

    for key in &lockfile_diff.added {
        eprintln!("  {} {key}", "+".green());
    }
    for key in &lockfile_diff.removed {
        eprintln!("  {} {key}", "-".red());
    }
    for key in &lockfile_diff.changed {
        eprintln!("  {} {key}", "~".yellow());
    }

    // ── Merge into existing (preserves approvals) ─────────────────────────────
    merge_into(&mut existing_lockfile, new_lockfile);

    // ── Write overrides ───────────────────────────────────────────────────────
    let overrides = OverridesManager::generate_overrides(&existing_lockfile);
    OverridesManager::write_overrides(&project_dir, &overrides)
        .map_err(|e| miette::miette!("failed to update package.json overrides: {e}"))?;

    // ── Run bun install (re-resolves from updated package.json + overrides) ───
    let bun = BunRunner::new(&project_dir).await
        .map_err(|e| miette::miette!("{e}"))?;

    eprintln!("Running bun install…");
    bun.install(config.policy.block_postinstall)
        .await
        .map_err(|e| miette::miette!("bun failed: {e}"))?;

    // ── Re-hash only changed/added packages ───────────────────────────────────
    let node_modules = project_dir.join("node_modules");
    let changed_keys: std::collections::HashSet<&str> = lockfile_diff
        .added
        .iter()
        .chain(lockfile_diff.changed.iter())
        .map(|s| s.as_str())
        .collect();

    for node in tree.all_nodes() {
        let key = node.spec.to_key();
        if !changed_keys.contains(key.as_str()) {
            continue;
        }
        let hash = hash_package_dir(&node_modules, &node.spec.name.to_string())
            .map_err(|e| miette::miette!(
                "failed to hash {key} after update: {e}\n\
                 The package may not have been installed correctly by bun."
            ))?;
        if let Some(entry) = existing_lockfile.packages.get_mut(&key) {
            entry.content_hash = hash;
        }
    }

    // ── Write lockfile (with config hash for integrity tracking) ─────────────
    existing_lockfile.meta.config_hash = config_hash;
    existing_lockfile
        .write(&project_dir)
        .map_err(|e| miette::miette!("failed to write vigil.lock: {e}"))?;

    // ── Audit log ─────────────────────────────────────────────────────────────
    let audit = AuditLog::new(&project_dir);
    for key in lockfile_diff.added.iter().chain(lockfile_diff.changed.iter()) {
        let (name, version) = key.rsplit_once('@').unwrap_or((key.as_str(), ""));
        let pkg_entry = existing_lockfile.packages.get(key);
        let entry = AuditEntry {
            ts: chrono::Utc::now(),
            event: "update".to_string(),
            package: name.to_string(),
            version: version.to_string(),
            age_days: pkg_entry.map(|p| p.age_at_install_days).unwrap_or(0),
            checks_passed: report
                .for_package(key)
                .into_iter()
                .filter(|r| r.outcome.is_passed())
                .map(|r| r.check_name.to_string())
                .collect(),
            user: username.clone(),
            dev: pkg_entry.map(|p| p.dev).unwrap_or(false),
            optional: pkg_entry.map(|p| p.optional).unwrap_or(false),
            reason: if args.allow_fresh.contains(&name.to_string()) {
                args.reason.clone()
            } else {
                None
            },
            prev_hash: None,
        };
        if let Err(e) = audit.append(&entry) {
            eprintln!("  {} failed to write audit log: {e}", "!".yellow());
        }
    }

    let total = lockfile_diff.added.len() + lockfile_diff.changed.len();
    eprintln!(
        "\n  {} Updated {} package{}",
        "✓".green().bold(),
        total,
        if total == 1 { "" } else { "s" },
    );
    Ok(())
}
