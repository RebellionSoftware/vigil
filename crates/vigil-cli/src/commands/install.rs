use clap::Args;
use std::env;
use vigil_core::{
    bun::BunRunner,
    config::VigilConfig,
    hash::hash_package_dir,
    lockfile::{generate_from_tree, merge_into, VigilLockfile},
    overrides::OverridesManager,
    package_json::{read_package_json, write_package_json},
    policy::PolicyEngine,
    resolver::DependencyResolver,
    types::PackageName,
};
use vigil_registry::NpmRegistryClient;

use owo_colors::OwoColorize;
use crate::{audit_log::{AuditEntry, AuditLog}, output};

#[derive(Debug, Args)]
pub struct InstallArgs {
    /// Package(s) to install (e.g. "axios" or "axios@1.7.4").
    pub packages: Vec<String>,

    /// Install as a dev dependency (devDependencies). All policy checks still apply.
    /// If the package is already installed as a production dependency, it will be
    /// reclassified to devDependencies.
    #[arg(long, conflicts_with = "optional")]
    pub dev: bool,

    /// Install as an optional dependency (optionalDependencies). All policy checks still apply.
    /// If the package is already installed as a production dependency, it will be
    /// reclassified to optionalDependencies.
    #[arg(long, conflicts_with = "dev")]
    pub optional: bool,

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

    // Validate all install targets and --allow-fresh names before any I/O.
    // Resolver errors on invalid names produce confusing network-layer messages;
    // catching them here gives a clear "invalid package name" error upfront.
    for spec in &args.packages {
        let base = pkg_base_name(spec);
        PackageName::new(base)
            .map_err(|e| miette::miette!("invalid package name '{base}': {e}"))?;
    }
    for name in &args.allow_fresh {
        PackageName::new(name)
            .map_err(|e| miette::miette!("invalid package name '{name}': {e}"))?;
    }

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

    // ── 4a. Write block audit entries before aborting ─────────────────────────
    // Log one "block" entry per unique package that failed a check so the audit
    // trail records attempted installs, not just successful ones.
    if has_blockers {
        let username = whoami::username();
        let audit = AuditLog::new(&project_dir);
        let now = chrono::Utc::now();

        // Collect unique blocked packages; aggregate all reasons per package.
        let mut seen_keys: Vec<String> = Vec::new();
        let mut seen_set: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut reasons: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        for result in report.blocked() {
            let key = result.package.to_key();
            if let vigil_core::policy::CheckOutcome::Blocked { reason } = &result.outcome {
                reasons.entry(key.clone()).or_default().push(reason.clone());
            }
            if seen_set.insert(key.clone()) {
                seen_keys.push(key);
            }
        }

        for key in &seen_keys {
            if let Some(node) = tree.get(key) {
                let age_days = now.signed_duration_since(node.published_at).num_days().max(0) as u32;
                let reason_text = reasons.get(key).map(|rs| rs.join("; "));
                let block_entry = AuditEntry {
                    ts: now,
                    event: "block".to_string(),
                    package: node.spec.name.to_string(),
                    version: node.spec.version.to_string(),
                    age_days,
                    checks_passed: vec![],
                    user: username.clone(),
                    dev: args.dev,
                    optional: args.optional,
                    reason: reason_text,
                    prev_hash: None,
                };
                if let Err(e) = audit.append(&block_entry) {
                    eprintln!("  {} failed to write block event to audit log: {e}", "!".yellow());
                }
            }
        }

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

    // Mark newly-requested direct packages with their dev/optional designation.
    // Packages already in the lockfile (re-resolved for the full tree) retain
    // whatever designation they had when they were first installed.
    let new_base_names: std::collections::HashSet<&str> = args.packages
        .iter()
        .map(|p| pkg_base_name(p))
        .collect();
    for node in tree.direct_nodes() {
        let name = node.spec.name.to_string();
        if new_base_names.contains(name.as_str()) {
            if let Some(pkg) = lockfile.packages.get_mut(&node.spec.to_key()) {
                pkg.dev = args.dev;
                pkg.optional = args.optional;
            }
        }
    }

    // Suppress lifecycle scripts unless at least one package has approved postinstall.
    // This covers both lockfile-approved (prior trust) and config-approved (pre-trust).
    let any_approved = lockfile.packages.values().any(|p| p.postinstall_approved)
        || !config.bypass.allow_postinstall.is_empty();
    let ignore_scripts = config.policy.block_postinstall && !any_approved;

    // Split direct_specs into newly-requested packages and already-existing ones.
    // bun add applies --dev/--optional to EVERY package in the invocation, so
    // passing all direct specs with a global flag would silently move existing
    // production deps into devDependencies/optionalDependencies in package.json.
    let (new_specs, existing_specs): (Vec<_>, Vec<_>) = direct_specs
        .into_iter()
        .partition(|spec| new_base_names.contains(spec.name.as_str()));

    let dep_kind = if args.dev { " (dev)" } else if args.optional { " (optional)" } else { "" };
    eprintln!("Running bun add{dep_kind}…");

    // Install newly-requested packages with their correct designation.
    if !new_specs.is_empty() {
        // Strip new packages from peerDependencies before calling bun add.
        // Bun does not reclassify packages that are already in peerDependencies
        // when given --dev or --optional — it leaves them there silently.
        // Removing them first ensures bun places them in the correct section.
        let peer_names: std::collections::HashSet<&str> =
            new_specs.iter().map(|s| s.name.as_str()).collect();
        let mut pkg_json = read_package_json(&project_dir)
            .map_err(|e| miette::miette!("failed to read package.json: {e}"))?;
        if let Some(peers) = pkg_json.get_mut("peerDependencies").and_then(|v| v.as_object_mut()) {
            let stale: Vec<String> = peers.keys()
                .filter(|k| peer_names.contains(k.as_str()))
                .cloned()
                .collect();
            if !stale.is_empty() {
                for k in &stale {
                    peers.remove(k);
                }
                write_package_json(&project_dir, &pkg_json)
                    .map_err(|e| miette::miette!("failed to update package.json: {e}"))?;
            }
        }

        bun.add(&new_specs, args.dev, args.optional, ignore_scripts)
            .await
            .map_err(|e| miette::miette!("bun failed: {e}"))?;
    }

    // Re-install existing direct packages grouped by their recorded designation
    // so their package.json classification is not disturbed.
    if !existing_specs.is_empty() {
        // Strip existing packages from peerDependencies before calling bun add.
        // The same bun behaviour applies: packages already in peerDependencies
        // are not reclassified when --dev or --optional is passed.
        let existing_peer_names: std::collections::HashSet<&str> =
            existing_specs.iter().map(|s| s.name.as_str()).collect();
        let mut pkg_json = read_package_json(&project_dir)
            .map_err(|e| miette::miette!("failed to read package.json: {e}"))?;
        if let Some(peers) = pkg_json.get_mut("peerDependencies").and_then(|v| v.as_object_mut()) {
            let stale: Vec<String> = peers.keys()
                .filter(|k| existing_peer_names.contains(k.as_str()))
                .cloned()
                .collect();
            if !stale.is_empty() {
                for k in &stale {
                    peers.remove(k);
                }
                write_package_json(&project_dir, &pkg_json)
                    .map_err(|e| miette::miette!("failed to update package.json: {e}"))?;
            }
        }

        let mut groups: std::collections::BTreeMap<(bool, bool), Vec<vigil_core::types::PackageSpec>> =
            std::collections::BTreeMap::new();
        for spec in existing_specs {
            let key = spec.to_key();
            let (dev, optional) = lockfile.packages.get(&key)
                .map(|p| (p.dev, p.optional))
                .unwrap_or((false, false));
            groups.entry((dev, optional)).or_default().push(spec);
        }
        for ((dev, optional), specs) in groups {
            bun.add(&specs, dev, optional, ignore_scripts)
                .await
                .map_err(|e| miette::miette!("bun failed: {e}"))?;
        }
    }

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
            dev: pkg_entry.map(|p| p.dev).unwrap_or(false),
            optional: pkg_entry.map(|p| p.optional).unwrap_or(false),
            reason: if args.allow_fresh.contains(&node.spec.name.to_string()) {
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

    // ── 12. Print success ─────────────────────────────────────────────────────
    output::print_install_success(tree.nodes.len(), args.dev, args.optional);

    Ok(())
}
