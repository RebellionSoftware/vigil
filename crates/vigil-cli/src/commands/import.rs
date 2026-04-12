use clap::Args;
use std::env;
use vigil_core::{
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

use crate::{
    audit_log::{AuditEntry, AuditLog},
    commands::init::VIGIL_TOML_TEMPLATE,
    output,
};

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Also import devDependencies from package.json.
    #[arg(long)]
    pub include_dev: bool,

    /// Use npm instead of bun as the package manager.
    #[arg(long)]
    pub npm: bool,
}

pub async fn run(args: ImportArgs) -> miette::Result<()> {
    let project_dir = env::current_dir()
        .map_err(|e| miette::miette!("cannot determine current directory: {e}"))?;

    // ── 1. Check for package.json ─────────────────────────────────────────────
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(miette::miette!(
            "no package.json found in the current directory.\n\
             Run `vigil init` to start a new project."
        ));
    }

    // ── 2. Read deps from package.json ────────────────────────────────────────
    let pkg_json = read_package_json(&project_dir)
        .map_err(|e| miette::miette!("failed to read package.json: {e}"))?;

    let node_modules = project_dir.join("node_modules");
    let nm_exists = node_modules.exists();

    let mut specs: Vec<String> = Vec::new();
    let mut uninstalled: Vec<String> = Vec::new();
    // Track which package names came from devDependencies so we can mark them
    // in the lockfile after resolution. Names only — version is resolved later.
    let mut dev_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    let dep_sections = if args.include_dev {
        vec!["dependencies", "devDependencies"]
    } else {
        vec!["dependencies"]
    };

    for &section in &dep_sections {
        if let Some(deps) = pkg_json[section].as_object() {
            for name in deps.keys() {
                // Reject malformed names early — prevents path traversal in
                // installed_version() and avoids sending garbage to the registry.
                if PackageName::new(name).is_err() {
                    eprintln!(
                        "  {} skipping invalid package name in {section}: {name}",
                        "!".yellow()
                    );
                    continue;
                }

                if section == "devDependencies" {
                    dev_names.insert(name.clone());
                }

                // Prefer the exact version already installed in node_modules over
                // resolving from the registry — import should reflect current reality.
                match installed_version(&node_modules, name) {
                    Some(v) => specs.push(format!("{name}@{v}")),
                    None => {
                        // Not installed — resolve latest from registry using the
                        // range in package.json as the constraint.
                        let range = deps.get(name)
                            .and_then(|v| v.as_str())
                            .unwrap_or_else(|| {
                                eprintln!(
                                    "  {} {name}: non-string version range in {section}, \
                                     resolving latest",
                                    "!".yellow()
                                );
                                "latest"
                            });
                        specs.push(format!("{name}@{range}"));
                        uninstalled.push(name.clone());
                    }
                }
            }
        }
    }

    if specs.is_empty() {
        eprintln!("  {} No dependencies found in package.json — nothing to import.", "!".yellow());
        return Ok(());
    }

    eprintln!(
        "\nImporting {} package{} from package.json…",
        specs.len(),
        if specs.len() == 1 { "" } else { "s" },
    );

    if !uninstalled.is_empty() {
        eprintln!(
            "  {} {} package{} not installed — will resolve from registry: {}",
            "!".yellow(),
            uninstalled.len(),
            if uninstalled.len() == 1 { "" } else { "s" },
            uninstalled.join(", "),
        );
    }

    if !nm_exists {
        eprintln!(
            "  {} node_modules not found — resolving all versions from registry",
            "!".yellow(),
        );
    }

    // ── 3. Load existing vigil.lock early so policy checks can honour prior
    //       approvals (e.g. postinstall_approved set on a previous import).
    //       Reading it once here also avoids a TOCTOU window from reading it
    //       again later at the merge step.
    let existing_lockfile = VigilLockfile::read_optional(&project_dir)
        .map_err(|e| miette::miette!("failed to read existing vigil.lock: {e}"))?;

    // ── 4. Load or create vigil.toml ──────────────────────────────────────────
    // Note: VIGIL_TOML_TEMPLATE values must match PolicyConfig::default() —
    // the template is written after config is loaded, so the first import uses
    // defaults and subsequent imports use the file. They must stay in sync.
    let (config, config_hash) = VigilConfig::load_with_hash(&project_dir)
        .map_err(|e| miette::miette!("failed to load vigil.toml: {e}"))?;

    let vigil_toml_created = if !project_dir.join("vigil.toml").exists() {
        // vigil.toml doesn't exist yet — write from template before continuing.
        let template = if args.npm {
            format!("package_manager = \"npm\"\n\n{VIGIL_TOML_TEMPLATE}")
        } else {
            VIGIL_TOML_TEMPLATE.to_string()
        };
        let tmp = project_dir.join("vigil.toml.tmp");
        std::fs::write(&tmp, &template)
            .map_err(|e| miette::miette!("failed to write vigil.toml: {e}"))?;
        std::fs::rename(&tmp, project_dir.join("vigil.toml"))
            .map_err(|e| miette::miette!("failed to create vigil.toml: {e}"))?;
        true
    } else {
        false
    };

    if args.npm && !vigil_toml_created {
        eprintln!(
            "  {} --npm ignored: vigil.toml already exists (package_manager = \"{}\")",
            "!".yellow(),
            config.package_manager,
        );
    }

    // ── 5. Resolve full dependency tree ───────────────────────────────────────
    let registry = NpmRegistryClient::new();
    let mut resolver = DependencyResolver::new(registry, config.policy.clone());
    let pkg_refs: Vec<&str> = specs.iter().map(|s| s.as_str()).collect();

    let tree = resolver
        .resolve(&pkg_refs)
        .await
        .map_err(|e| miette::miette!("dependency resolution failed: {e}"))?;

    // ── 6. Run policy checks (warn only — do not block) ───────────────────────
    // Pass the existing lockfile so packages with prior approvals (e.g.
    // postinstall_approved = true from a previous import or trust command)
    // are not spuriously flagged as "would be blocked" in the warning output.
    let engine = PolicyEngine::new(
        config.policy.clone(),
        config.bypass.clone(),
        config.blocked.clone(),
    );
    let report = engine.check_tree(&tree, existing_lockfile.as_ref());

    // Print the full check report regardless of blockers.
    output::print_check_report(&report, &tree);

    // ── 7. Warn about policy violations without blocking ──────────────────────
    if report.has_blockers() {
        let blocked = report.blocked();
        let n = blocked.iter()
            .map(|r| r.package.to_key())
            .collect::<std::collections::HashSet<_>>()
            .len();

        eprintln!("{}", format!(
            "\n  ⚠  {n} package{} would be blocked on a fresh `vigil install`.",
            if n == 1 { "" } else { "s" },
        ).yellow().bold());
        eprintln!(
            "     They are imported but flagged — any prior postinstall approvals have been \
             revoked.\n     Review and use `vigil trust` to re-approve, or remove them:\n"
        );

        // Collect unique packages with their failing check names.
        let mut pkg_checks: std::collections::HashMap<String, Vec<&str>> =
            std::collections::HashMap::new();
        for r in &blocked {
            pkg_checks
                .entry(r.package.to_key())
                .or_default()
                .push(r.check_name);
        }
        let mut pkg_list: Vec<_> = pkg_checks.iter().collect();
        pkg_list.sort_by_key(|(k, _)| k.as_str());
        for (pkg, checks) in pkg_list {
            eprintln!("     {}  [{}]", pkg.bold(), checks.join(", "));
        }
        eprintln!();
    }

    // ── 8. Generate lockfile ──────────────────────────────────────────────────
    let username = whoami::username();
    let mut lockfile = generate_from_tree(&tree, &username);

    // Mark direct packages that came from devDependencies.
    if !dev_names.is_empty() {
        for (key, pkg) in lockfile.packages.iter_mut() {
            if !pkg.direct {
                continue;
            }
            let pkg_name = key.rsplit_once('@').map(|(n, _)| n).unwrap_or(key.as_str());
            if dev_names.contains(pkg_name) {
                pkg.dev = true;
            }
        }
    }

    // ── 9. Hash installed packages — skip gracefully if not on disk ───────────
    let mut hashed = 0usize;
    let mut not_on_disk = 0usize;

    for node in tree.all_nodes() {
        let pkg_name = node.spec.name.to_string();
        let key = node.spec.to_key();

        match hash_package_dir(&node_modules, &pkg_name) {
            Ok(hash) => {
                if let Some(entry) = lockfile.packages.get_mut(&key) {
                    entry.content_hash = hash;
                }
                hashed += 1;
            }
            Err(_) => {
                not_on_disk += 1;
                // Leave the content_hash as the registry dist.integrity value.
                // vigil verify will flag this as "not yet recorded" until the
                // user runs `vigil install` to actually install the package.
            }
        }
    }

    // ── 10. Apply pre-approved postinstall from bypass config ─────────────────
    for pkg_name in &config.bypass.allow_postinstall {
        for (key, pkg) in lockfile.packages.iter_mut() {
            let key_name = key.rsplit_once('@').map(|(n, _)| n).unwrap_or(key.as_str());
            if key_name == pkg_name.as_str() {
                pkg.postinstall_approved = true;
            }
        }
    }

    // ── 11. Pin exact versions for direct deps in package.json ────────────────
    // The semver range in dependencies (e.g. "^0.33.0") lets Bun resolve a newer
    // version on any bare `bun install`. Update direct dep entries to the exact
    // resolved version to keep package.json in sync with vigil.lock.
    // Note: `vigil install` does this automatically because it delegates to
    // `bun add pkg@exact`, but import bypasses Bun entirely.
    {
        let direct_pins: std::collections::HashMap<String, String> = lockfile
            .packages
            .iter()
            .filter(|(_, pkg)| pkg.direct)
            .filter_map(|(key, _)| {
                key.rsplit_once('@')
                    .map(|(name, ver)| (name.to_string(), ver.to_string()))
            })
            .collect();

        if !direct_pins.is_empty() {
            let mut pkg_json_val = read_package_json(&project_dir)
                .map_err(|e| miette::miette!("failed to read package.json: {e}"))?;
            for section in ["dependencies", "devDependencies"] {
                if let Some(deps) = pkg_json_val[section].as_object_mut() {
                    for (name, val) in deps.iter_mut() {
                        if let Some(exact) = direct_pins.get(name.as_str()) {
                            *val = serde_json::json!(exact);
                        }
                    }
                }
            }
            write_package_json(&project_dir, &pkg_json_val)
                .map_err(|e| miette::miette!("failed to pin direct dep versions in package.json: {e}"))?;
        }
    }

    // ── 12. Write overrides to package.json ───────────────────────────────────
    let overrides = OverridesManager::generate_overrides(&lockfile);
    OverridesManager::write_overrides(&project_dir, &overrides)
        .map_err(|e| miette::miette!("failed to update package.json overrides: {e}"))?;

    // ── 13. Write vigil.lock ──────────────────────────────────────────────────
    // Use the lockfile snapshot loaded at step 3 — do NOT re-read from disk here.
    // A second read_optional would reopen a TOCTOU window that step 3 was
    // specifically designed to close.
    let mut final_lockfile = if let Some(mut existing) = existing_lockfile {
        merge_into(&mut existing, lockfile);
        existing
    } else {
        lockfile
    };

    // Revoke any preserved postinstall approvals for packages currently failing
    // policy checks. merge_into() would otherwise carry forward a prior approval
    // for a package that now triggers a new check (e.g. velocity, block list),
    // silently undermining the deny-by-default guarantee.
    if report.has_blockers() {
        let blocked_keys: std::collections::HashSet<String> = report
            .blocked()
            .iter()
            .map(|r| r.package.to_key())
            .collect();
        for (key, pkg) in final_lockfile.packages.iter_mut() {
            if blocked_keys.contains(key) {
                pkg.postinstall_approved = false;
            }
        }
    }

    final_lockfile.meta.config_hash = config_hash;
    final_lockfile
        .write(&project_dir)
        .map_err(|e| miette::miette!("failed to write vigil.lock: {e}"))?;

    // ── 14. Append audit log entries ──────────────────────────────────────────
    let audit = AuditLog::new(&project_dir);
    for node in tree.all_nodes() {
        let key = node.spec.to_key();
        let pkg_entry = final_lockfile.packages.get(&key);
        let checks_passed: Vec<String> = report
            .for_package(&key)
            .into_iter()
            .filter(|r| r.outcome.is_passed())
            .map(|r| r.check_name.to_string())
            .collect();

        let entry = AuditEntry {
            ts: chrono::Utc::now(),
            event: "import".to_string(),
            package: node.spec.name.to_string(),
            version: node.spec.version.to_string(),
            age_days: pkg_entry.map(|p| p.age_at_install_days).unwrap_or(0),
            checks_passed,
            user: username.clone(),
            dev: pkg_entry.map(|p| p.dev).unwrap_or(false),
            optional: pkg_entry.map(|p| p.optional).unwrap_or(false),
            reason: None,
            prev_hash: None,
        };
        if let Err(e) = audit.append(&entry) {
            eprintln!("  {} failed to write audit log: {e}", "!".yellow());
        }
    }

    // ── 15. Print summary ─────────────────────────────────────────────────────
    eprintln!("\n  {} Imported {} package{} into vigil.lock",
        "✓".green().bold(),
        tree.nodes.len(),
        if tree.nodes.len() == 1 { "" } else { "s" },
    );

    if vigil_toml_created {
        eprintln!("  {} Created vigil.toml with default policy", "✓".green().bold());
    }

    if not_on_disk > 0 {
        eprintln!(
            "  {} {} package{} not in node_modules — run `vigil install` to install and hash them",
            "!".yellow(),
            not_on_disk,
            if not_on_disk == 1 { "" } else { "s" },
        );
    } else {
        eprintln!("  {} {} package{} hashed from node_modules",
            "✓".green().bold(),
            hashed,
            if hashed == 1 { "" } else { "s" },
        );
    }

    if report.has_blockers() {
        eprintln!(
            "\n  {} Review flagged packages above, then use `vigil trust` to approve or \
             remove them from package.json.",
            "→".dimmed(),
        );
    } else {
        eprintln!("\n  {} All packages passed policy checks — you're good to go.", "→".dimmed());
    }

    Ok(())
}

/// Read the exact version of a package already installed in node_modules.
/// Returns `None` if the package is not installed or the manifest is unreadable.
///
/// Canonicalizes both paths before reading to prevent path traversal via
/// symlinked or `..`-escaped package names.
fn installed_version(node_modules: &std::path::Path, pkg_name: &str) -> Option<String> {
    let canonical_nm = node_modules.canonicalize().ok()?;
    let pkg_dir = node_modules.join(pkg_name);
    let canonical_pkg = pkg_dir.canonicalize().ok()?;
    if !canonical_pkg.starts_with(&canonical_nm) {
        return None;
    }
    let manifest = canonical_pkg.join("package.json");
    let contents = std::fs::read_to_string(manifest).ok()?;
    let value: serde_json::Value = serde_json::from_str(&contents).ok()?;
    value["version"].as_str().map(|s| s.to_string())
}
