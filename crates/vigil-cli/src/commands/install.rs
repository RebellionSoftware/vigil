use clap::Args;
use std::env;
use vigil_core::{
    bun::BunRunner,
    config::VigilConfig,
    hash::hash_package_dir,
    lockfile::{generate_from_tree, merge_into, VigilLockfile},
    overrides::OverridesManager,
    policy::PolicyEngine,
    resolver::DependencyResolver,
};
use vigil_registry::NpmRegistryClient;

use owo_colors::OwoColorize;
use crate::{audit_log::{AuditEntry, AuditLog}, output};

#[derive(Debug, Args)]
pub struct InstallArgs {
    /// Package(s) to install (e.g. "axios" or "axios@1.7.4").
    pub packages: Vec<String>,

    /// Bypass age gate for specific package(s). Requires --reason.
    #[arg(long, value_name = "PACKAGE")]
    pub allow_fresh: Vec<String>,

    /// Reason for bypassing a check (required when using --allow-fresh).
    #[arg(long, requires = "allow_fresh")]
    pub reason: Option<String>,
}

/// Return the package name portion of a specifier, stripping any version suffix.
/// Handles both unscoped ("ms@2.1.3" → "ms") and scoped ("@types/node@20" → "@types/node").
fn pkg_base_name(spec: &str) -> &str {
    if spec.starts_with('@') {
        // Find the '@' after the slash (version separator), if any
        match spec[1..].find('@') {
            Some(idx) => &spec[..idx + 1],
            None => spec,
        }
    } else {
        spec.split('@').next().unwrap_or(spec)
    }
}

pub async fn run(args: InstallArgs) -> miette::Result<()> {
    let project_dir = env::current_dir()
        .map_err(|e| miette::miette!("cannot determine current directory: {e}"))?;

    // ── 1. Load config (with hash for vigil.toml integrity tracking) ─────────
    let (config, config_hash) = VigilConfig::load_with_hash(&project_dir)
        .map_err(|e| miette::miette!("failed to load vigil.toml: {e}"))?;

    // ── 2. Load existing lockfile (preserves prior approvals across runs) ─────
    let existing_lockfile = VigilLockfile::read_optional(&project_dir)
        .map_err(|e| miette::miette!("failed to read vigil.lock: {e}"))?;

    // ── 3. Resolve dependency tree ────────────────────────────────────────────
    let registry = NpmRegistryClient::new();
    let mut resolver = DependencyResolver::new(registry, config.policy.clone());

    // Resolve ALL direct packages: existing ones pinned at current version + newly requested.
    // This ensures the lockfile always contains the complete set of directs, not just the
    // ones named in this invocation.
    let mut all_specs: Vec<String> = Vec::new();
    if let Some(ref existing) = existing_lockfile {
        for (key, pkg) in &existing.packages {
            if pkg.direct {
                all_specs.push(key.clone()); // "name@version" — exact pin
            }
        }
    }
    // New packages override any existing entry with the same base name.
    for new_pkg in &args.packages {
        let new_base = pkg_base_name(new_pkg);
        all_specs.retain(|s| {
            s.rsplit_once('@').map(|(n, _)| n).unwrap_or(s.as_str()) != new_base
        });
        all_specs.push(new_pkg.clone());
    }

    eprintln!("Resolving {}…", args.packages.join(", "));

    let pkg_refs: Vec<&str> = all_specs.iter().map(|s| s.as_str()).collect();
    let tree = resolver
        .resolve(&pkg_refs)
        .await
        .map_err(|e| miette::miette!("dependency resolution failed: {e}"))?;

    // ── 4. Run policy checks ──────────────────────────────────────────────────
    let mut bypass = config.bypass.clone();
    bypass.allow_fresh.extend(args.allow_fresh.clone());

    let engine = PolicyEngine::new(
        config.policy.clone(),
        bypass,
        config.blocked.clone(),
    );

    let report = engine.check_tree(&tree, existing_lockfile.as_ref());

    let has_blockers = output::print_check_report(&report, &tree);
    if has_blockers {
        return Err(output::print_blocked_and_fail(&report));
    }

    // ── 5. Build lockfile — merge new tree over existing to preserve approvals ─
    let username = whoami::username();
    let new_lockfile = generate_from_tree(&tree, &username);

    let mut lockfile = if let Some(mut existing) = existing_lockfile {
        merge_into(&mut existing, new_lockfile);
        existing
    } else {
        new_lockfile
    };

    // ── 6. Apply pre-approved postinstall trust from vigil.toml bypass config ─
    // Packages in [bypass] allow_postinstall were trusted before install; mark
    // them approved in the lockfile so subsequent verify/update don't re-block.
    for pkg_name in &config.bypass.allow_postinstall {
        for (key, pkg) in lockfile.packages.iter_mut() {
            let key_name = key.rsplit_once('@').map(|(n, _)| n).unwrap_or(key.as_str());
            if key_name == pkg_name.as_str() {
                pkg.postinstall_approved = true;
            }
        }
    }

    // ── 7. Write overrides to package.json ───────────────────────────────────
    let overrides = OverridesManager::generate_overrides(&lockfile);
    OverridesManager::write_overrides(&project_dir, &overrides)
        .map_err(|e| miette::miette!("failed to update package.json overrides: {e}"))?;

    // ── 8. Run bun add ────────────────────────────────────────────────────────
    let bun = BunRunner::new(&project_dir).await
        .map_err(|e| miette::miette!("{e}"))?;

    let direct_specs: Vec<_> = tree
        .direct_nodes()
        .into_iter()
        .map(|n| n.spec.clone())
        .collect();

    // Suppress lifecycle scripts unless at least one package has approved postinstall.
    // This covers both lockfile-approved (prior trust) and config-approved (pre-trust).
    let any_approved = lockfile.packages.values().any(|p| p.postinstall_approved)
        || !config.bypass.allow_postinstall.is_empty();
    let ignore_scripts = config.policy.block_postinstall && !any_approved;

    eprintln!("Running bun add…");
    bun.add(&direct_specs, ignore_scripts)
        .await
        .map_err(|e| miette::miette!("bun failed: {e}"))?;

    // ── 9. Hash installed packages and update lockfile ────────────────────────
    let node_modules = project_dir.join("node_modules");

    for node in tree.all_nodes() {
        let pkg_name = node.spec.name.to_string();
        let hash = hash_package_dir(&node_modules, &pkg_name)
            .map_err(|e| miette::miette!(
                "failed to hash {} after install: {e}\n\
                 The package may not have been installed correctly by bun.",
                node.spec.to_key()
            ))?;
        let key = node.spec.to_key();
        if let Some(entry) = lockfile.packages.get_mut(&key) {
            entry.content_hash = hash;
        }
    }

    // ── 10. Write vigil.lock (with config hash for integrity tracking) ────────
    lockfile.meta.config_hash = config_hash;
    lockfile
        .write(&project_dir)
        .map_err(|e| miette::miette!("failed to write vigil.lock: {e}"))?;

    // ── 11. Append audit log entries ──────────────────────────────────────────
    let audit = AuditLog::new(&project_dir);

    for node in tree.all_nodes() {
        let key = node.spec.to_key();
        let pkg_entry = lockfile.packages.get(&key);
        let checks_passed: Vec<String> = report
            .for_package(&key)
            .into_iter()
            .filter(|r| r.outcome.is_passed())
            .map(|r| r.check_name.to_string())
            .collect();

        let entry = AuditEntry {
            ts: chrono::Utc::now(),
            event: "install".to_string(),
            package: node.spec.name.to_string(),
            version: node.spec.version.to_string(),
            age_days: pkg_entry.map(|p| p.age_at_install_days).unwrap_or(0),
            checks_passed,
            user: username.clone(),
            reason: if args.allow_fresh.contains(&node.spec.name.to_string()) {
                args.reason.clone()
            } else {
                None
            },
        };

        if let Err(e) = audit.append(&entry) {
            eprintln!("  {} failed to write audit log: {e}", "!".yellow());
        }
    }

    // ── 12. Print success ─────────────────────────────────────────────────────
    output::print_install_success(tree.nodes.len());

    Ok(())
}
