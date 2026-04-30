use crate::{
    config::{BypassConfig, PolicyConfig},
    lockfile::VigilLockfile,
    policy::{CheckOutcome, CheckResult},
    resolver::ResolvedNode,
};

/// Check whether a package has install lifecycle scripts and block if policy requires it.
///
/// Returns an empty Vec if the package has no install scripts.
/// Returns a blocked result if scripts are present and not approved.
/// Returns a passed result if scripts were previously approved via `vigil trust`.
pub fn check(
    node: &ResolvedNode,
    _config: &PolicyConfig,
    bypass: &BypassConfig,
    lockfile: Option<&VigilLockfile>,
) -> Vec<CheckResult> {
    if !node.has_install_script && !node.metadata.has_postinstall() {
        return vec![];
    }

    // Detect which script types are present
    let script_types: Vec<&str> = ["postinstall", "preinstall", "install"]
        .iter()
        .filter(|&&s| node.metadata.scripts.contains_key(s))
        .copied()
        .collect();

    let script_label = if script_types.is_empty() {
        "install script (hasInstallScript flag)".to_string()
    } else {
        script_types.join(", ")
    };

    let name = node.spec.name.to_string();

    // Approved via vigil.toml [bypass] allow_postinstall (pre-install trust)
    // or via vigil.lock postinstall_approved (post-install trust).
    let key = node.spec.to_key();
    let approved = bypass.allow_postinstall.contains(&name)
        || lockfile
            .and_then(|lf| lf.packages.get(&key))
            .map(|pkg| pkg.postinstall_approved)
            .unwrap_or(false);

    let outcome = if approved {
        CheckOutcome::Passed
    } else {
        CheckOutcome::Blocked {
            reason: format!(
                "has {} script(s): [{}]. \
                 Run `vigil trust {} --allow postinstall` to approve, \
                 or set block_postinstall = false in vigil.toml",
                if script_types.is_empty() { "install" } else { "lifecycle" },
                script_label,
                node.spec.name,
            ),
        }
    };

    vec![CheckResult {
        package: node.spec.clone(),
        check_name: "postinstall",
        outcome,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{BypassConfig, PolicyConfig},
        lockfile::{LockedPackage, VigilLockfile},
        registry::{DistInfo, VersionMetadata},
        resolver::ResolvedNode,
        types::{ExactVersion, PackageName, PackageSpec},
    };
    use chrono::Utc;
    use std::collections::HashMap;

    fn make_node(name: &str, scripts: &[&str], has_install_flag: bool) -> ResolvedNode {
        let mut script_map = HashMap::new();
        for s in scripts {
            script_map.insert(s.to_string(), serde_json::Value::String("node ./setup.js".to_string()));
        }
        ResolvedNode {
            spec: PackageSpec::new(
                PackageName::new(name).unwrap(),
                ExactVersion::new("1.0.0"),
            ),
            dependencies: vec![],
            dependents: vec![],
            metadata: VersionMetadata {
                name: name.to_string(),
                version: "1.0.0".to_string(),
                dependencies: HashMap::new(),
                peer_dependencies: HashMap::new(),
                dist: DistInfo {
                    integrity: None,
                    shasum: "fake".to_string(),
                    tarball: "https://example.com/pkg.tgz".to_string(),
                },
                scripts: script_map,
                has_install_script: has_install_flag,
                maintainers: vec![],
            },
            published_at: Utc::now(),
            is_direct: true,
            has_install_script: has_install_flag || scripts.iter().any(|s| ["postinstall","preinstall","install"].contains(s)),
            days_since_prior_publish: None,
        }
    }

    fn lockfile_with_approval(pkg_key: &str) -> VigilLockfile {
        let mut lf = VigilLockfile::new();
        lf.packages.insert(pkg_key.to_string(), LockedPackage {
            content_hash: "sha512-fake".to_string(),
            published_at: Utc::now(),
            age_at_install_days: 30,
            direct: true, dev: false, optional: false,
            transitive_of: vec![],
            postinstall_approved: true,
            installed_at: Utc::now(),
            installed_by: "testuser".to_string(),
        });
        lf
    }

    #[test]
    fn clean_package_returns_no_results() {
        let node = make_node("ms", &[], false);
        let results = check(&node, &PolicyConfig::default(), &BypassConfig::default(), None);
        assert!(results.is_empty());
    }

    #[test]
    fn postinstall_script_blocks() {
        let node = make_node("esbuild", &["postinstall"], false);
        let results = check(&node, &PolicyConfig::default(), &BypassConfig::default(), None);
        assert_eq!(results.len(), 1);
        assert!(results[0].outcome.is_blocked());
        match &results[0].outcome {
            CheckOutcome::Blocked { reason } => {
                assert!(reason.contains("postinstall"), "reason: {reason}");
            }
            _ => panic!("expected blocked"),
        }
    }

    #[test]
    fn preinstall_script_blocks() {
        let node = make_node("pkg", &["preinstall"], false);
        let results = check(&node, &PolicyConfig::default(), &BypassConfig::default(), None);
        assert_eq!(results.len(), 1);
        assert!(results[0].outcome.is_blocked());
    }

    #[test]
    fn has_install_script_flag_blocks() {
        let node = make_node("pkg", &[], true); // flag set but no named scripts
        let results = check(&node, &PolicyConfig::default(), &BypassConfig::default(), None);
        assert_eq!(results.len(), 1);
        assert!(results[0].outcome.is_blocked());
        match &results[0].outcome {
            CheckOutcome::Blocked { reason } => {
                assert!(reason.contains("hasInstallScript"), "reason: {reason}");
            }
            _ => panic!("expected blocked"),
        }
    }

    #[test]
    fn approved_in_lockfile_passes() {
        let node = make_node("esbuild", &["postinstall"], false);
        let lf = lockfile_with_approval("esbuild@1.0.0");
        let results = check(&node, &PolicyConfig::default(), &BypassConfig::default(), Some(&lf));
        assert_eq!(results.len(), 1);
        assert!(results[0].outcome.is_passed(), "should pass with lockfile approval");
    }

    #[test]
    fn unapproved_in_lockfile_still_blocks() {
        let node = make_node("esbuild", &["postinstall"], false);
        // Lockfile exists but postinstall_approved = false (default)
        let lf = VigilLockfile::new();
        let results = check(&node, &PolicyConfig::default(), &BypassConfig::default(), Some(&lf));
        assert_eq!(results.len(), 1);
        assert!(results[0].outcome.is_blocked());
    }

    #[test]
    fn bypass_allow_postinstall_passes() {
        let node = make_node("esbuild", &["postinstall"], false);
        let bypass = BypassConfig {
            allow_postinstall: vec!["esbuild".to_string()],
            ..Default::default()
        };
        let results = check(&node, &PolicyConfig::default(), &bypass, None);
        assert_eq!(results.len(), 1);
        assert!(results[0].outcome.is_passed(), "bypass.allow_postinstall should pass");
    }

    #[test]
    fn reason_includes_trust_command() {
        let node = make_node("esbuild", &["postinstall"], false);
        let results = check(&node, &PolicyConfig::default(), &BypassConfig::default(), None);
        match &results[0].outcome {
            CheckOutcome::Blocked { reason } => {
                assert!(reason.contains("vigil trust"), "should mention trust command: {reason}");
            }
            _ => panic!("expected blocked"),
        }
    }
}
