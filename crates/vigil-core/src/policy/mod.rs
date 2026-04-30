pub mod age_gate;
pub mod postinstall;
pub mod velocity;

use crate::{
    config::{BlockedConfig, BypassConfig, PolicyConfig},
    lockfile::VigilLockfile,
    resolver::{ResolvedNode, ResolvedTree},
    types::PackageSpec,
};

/// The outcome of a single policy check against a single package.
#[derive(Debug, Clone)]
pub enum CheckOutcome {
    Passed,
    Blocked { reason: String },
    Warning { reason: String },
}

impl CheckOutcome {
    pub fn is_blocked(&self) -> bool {
        matches!(self, CheckOutcome::Blocked { .. })
    }

    pub fn is_warning(&self) -> bool {
        matches!(self, CheckOutcome::Warning { .. })
    }

    pub fn is_passed(&self) -> bool {
        matches!(self, CheckOutcome::Passed)
    }
}

/// The result of one check applied to one package.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub package: PackageSpec,
    pub check_name: &'static str,
    pub outcome: CheckOutcome,
}

/// All check results for a resolved dependency tree.
#[derive(Debug)]
pub struct TreeCheckReport {
    pub results: Vec<CheckResult>,
}

impl TreeCheckReport {
    pub fn has_blockers(&self) -> bool {
        self.results.iter().any(|r| r.outcome.is_blocked())
    }

    pub fn blocked(&self) -> Vec<&CheckResult> {
        self.results.iter().filter(|r| r.outcome.is_blocked()).collect()
    }

    pub fn warnings(&self) -> Vec<&CheckResult> {
        self.results.iter().filter(|r| r.outcome.is_warning()).collect()
    }

    pub fn passed(&self) -> Vec<&CheckResult> {
        self.results.iter().filter(|r| r.outcome.is_passed()).collect()
    }

    /// All results for a specific package.
    pub fn for_package(&self, key: &str) -> Vec<&CheckResult> {
        self.results
            .iter()
            .filter(|r| r.package.to_key() == key)
            .collect()
    }
}

/// Runs all registered policy checks against a resolved dependency tree.
pub struct PolicyEngine {
    config: PolicyConfig,
    bypass: BypassConfig,
    blocked: BlockedConfig,
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig, bypass: BypassConfig, blocked: BlockedConfig) -> Self {
        PolicyEngine { config, bypass, blocked }
    }

    fn config_blocked_packages(&self) -> Vec<String> {
        self.blocked.packages.clone()
    }

    /// Run all checks on every node in the tree.
    ///
    /// `lockfile` is the existing lockfile (if any) — used to check prior approvals
    /// (e.g. a postinstall script that was already reviewed and approved).
    pub fn check_tree(
        &self,
        tree: &ResolvedTree,
        lockfile: Option<&VigilLockfile>,
    ) -> TreeCheckReport {
        let mut results = Vec::new();

        let blocked_packages = self.config_blocked_packages();
        for node in tree.all_nodes() {
            results.extend(self.check_node(node, lockfile, &blocked_packages));
        }

        // Stable order: direct packages first, then transitives, alphabetical within each group
        results.sort_by(|a, b| {
            let a_node = tree.get(&a.package.to_key());
            let b_node = tree.get(&b.package.to_key());
            let a_direct = a_node.map(|n| n.is_direct).unwrap_or(false);
            let b_direct = b_node.map(|n| n.is_direct).unwrap_or(false);
            b_direct
                .cmp(&a_direct)
                .then(a.package.to_key().cmp(&b.package.to_key()))
                .then(a.check_name.cmp(b.check_name))
        });

        TreeCheckReport { results }
    }

    fn check_node(
        &self,
        node: &ResolvedNode,
        lockfile: Option<&VigilLockfile>,
        blocked_packages: &[String],
    ) -> Vec<CheckResult> {
        let mut results = Vec::new();

        // Hard block list — checked before anything else
        let name = node.spec.name.to_string();
        if blocked_packages.contains(&name) {
            results.push(CheckResult {
                package: node.spec.clone(),
                check_name: "blocked",
                outcome: CheckOutcome::Blocked {
                    reason: format!(
                        "'{name}' is on the blocked list in vigil.toml. \
                         Remove it from [blocked].packages to allow installation."
                    ),
                },
            });
            // Still run other checks so the full picture is visible
        }

        // Age gate
        if self.config.min_age_days > 0 {
            let apply = node.is_direct || self.config.transitive_age_gate;
            if apply {
                let bypassed = self.bypass.allow_fresh.contains(&name);
                if !bypassed {
                    results.extend(age_gate::check(node, &self.config));
                }
            }
        }

        // Postinstall blocking
        if self.config.block_postinstall {
            results.extend(postinstall::check(node, &self.config, &self.bypass, lockfile));
        }

        // Velocity / inactivity check
        let apply_velocity = node.is_direct || self.config.transitive_velocity_check;
        if self.config.inactivity_days > 0 && apply_velocity {
            results.extend(velocity::check(node, &self.config, &self.bypass));
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{BypassConfig, PolicyConfig},
        registry::{DistInfo, VersionMetadata},
        resolver::ResolvedNode,
        types::{ExactVersion, PackageName, PackageSpec},
    };
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    fn make_node(name: &str, version: &str, published_days_ago: i64, is_direct: bool) -> ResolvedNode {
        let published_at = Utc::now() - Duration::days(published_days_ago);
        ResolvedNode {
            spec: PackageSpec::new(
                PackageName::new(name).unwrap(),
                ExactVersion::new(version),
            ),
            dependencies: vec![],
            dependents: vec![],
            metadata: VersionMetadata {
                name: name.to_string(),
                version: version.to_string(),
                dependencies: HashMap::new(),
                peer_dependencies: HashMap::new(),
                dist: DistInfo {
                    integrity: None,
                    shasum: "fake".to_string(),
                    tarball: "https://example.com/pkg.tgz".to_string(),
                },
                scripts: HashMap::new(),
                has_install_script: false,
                maintainers: vec![],
            },
            published_at,
            is_direct,
            has_install_script: false,
            days_since_prior_publish: None,
        }
    }

    fn make_node_with_postinstall(name: &str, version: &str, is_direct: bool) -> ResolvedNode {
        let mut node = make_node(name, version, 30, is_direct);
        node.has_install_script = true;
        let mut scripts = HashMap::new();
        scripts.insert("postinstall".to_string(), serde_json::Value::String("node setup.js".to_string()));
        node.metadata.scripts = scripts;
        node.metadata.has_install_script = true;
        node
    }

    fn default_engine() -> PolicyEngine {
        PolicyEngine::new(PolicyConfig::default(), BypassConfig::default(), BlockedConfig::default())
    }

    // ---- age gate ----

    #[test]
    fn age_gate_blocks_fresh_package() {
        let engine = default_engine();
        let node = make_node("new-pkg", "1.0.0", 2, true);
        let results = age_gate::check(&node, &engine.config);
        assert!(results[0].outcome.is_blocked(), "2-day-old package should be blocked");
    }

    #[test]
    fn age_gate_passes_old_package() {
        let engine = default_engine();
        let node = make_node("old-pkg", "1.0.0", 10, true);
        let results = age_gate::check(&node, &engine.config);
        assert!(results[0].outcome.is_passed(), "10-day-old package should pass");
    }

    #[test]
    fn age_gate_passes_exactly_at_threshold() {
        let engine = default_engine();
        let node = make_node("pkg", "1.0.0", 7, true);
        let results = age_gate::check(&node, &engine.config);
        assert!(results[0].outcome.is_passed(), "package at exactly min_age_days should pass");
    }

    // ---- postinstall ----

    #[test]
    fn postinstall_blocks_when_present() {
        let engine = default_engine();
        let node = make_node_with_postinstall("esbuild", "0.19.0", true);
        let results = postinstall::check(&node, &engine.config, &engine.bypass, None);
        assert!(results.iter().any(|r| r.outcome.is_blocked()));
    }

    #[test]
    fn postinstall_passes_clean_package() {
        let engine = default_engine();
        let node = make_node("ms", "2.1.3", 30, true);
        let results = postinstall::check(&node, &engine.config, &engine.bypass, None);
        assert!(results.is_empty() || results.iter().all(|r| r.outcome.is_passed()));
    }

    // ---- check_tree integration ----

    #[test]
    fn check_tree_mixed_results() {
        use crate::resolver::ResolvedTree;

        let engine = default_engine();

        let old_node = make_node("express", "4.18.2", 30, true);
        let fresh_node = make_node("new-dep", "1.0.0", 1, false);

        let mut nodes = HashMap::new();
        nodes.insert(old_node.spec.to_key(), old_node.clone());
        nodes.insert(fresh_node.spec.to_key(), fresh_node.clone());

        let tree = ResolvedTree {
            direct: vec![old_node.spec.clone()],
            nodes,
            warnings: vec![],
        };

        let report = engine.check_tree(&tree, None);
        assert!(report.has_blockers(), "fresh transitive should be blocked");
        let blockers = report.blocked();
        assert_eq!(blockers.len(), 1);
        assert_eq!(blockers[0].package.name.to_string(), "new-dep");
    }

    #[test]
    fn check_tree_transitive_age_gate_disabled() {
        use crate::resolver::ResolvedTree;

        let mut config = PolicyConfig::default();
        config.transitive_age_gate = false;
        let engine = PolicyEngine::new(config, BypassConfig::default(), BlockedConfig::default());

        let fresh_transitive = make_node("fresh-dep", "1.0.0", 1, false); // not direct

        let mut nodes = HashMap::new();
        nodes.insert(fresh_transitive.spec.to_key(), fresh_transitive.clone());

        let tree = ResolvedTree {
            direct: vec![],
            nodes,
            warnings: vec![],
        };

        let report = engine.check_tree(&tree, None);
        // Transitive age gate disabled → fresh transitive should NOT be blocked
        assert!(!report.has_blockers());
    }

    #[test]
    fn bypass_allow_fresh_skips_age_gate() {
        use crate::resolver::ResolvedTree;

        let bypass = BypassConfig {
            allow_fresh: vec!["trusted-pkg".to_string()],
            allow_postinstall: vec![],
            allow_inactivity: vec![],
        };
        let engine = PolicyEngine::new(PolicyConfig::default(), bypass, BlockedConfig::default());

        let node = make_node("trusted-pkg", "1.0.0", 1, true); // 1 day old, but bypassed

        let mut nodes = HashMap::new();
        nodes.insert(node.spec.to_key(), node.clone());

        let tree = ResolvedTree {
            direct: vec![node.spec.clone()],
            nodes,
            warnings: vec![],
        };

        let report = engine.check_tree(&tree, None);
        assert!(!report.has_blockers(), "bypassed package should not be blocked");
    }

    #[test]
    fn blocked_packages_list_enforced() {
        use crate::resolver::ResolvedTree;

        let blocked = BlockedConfig {
            packages: vec!["evil-pkg".to_string()],
        };
        let engine = PolicyEngine::new(PolicyConfig::default(), BypassConfig::default(), blocked);

        let node = make_node("evil-pkg", "1.0.0", 30, true); // old enough to pass age gate

        let mut nodes = HashMap::new();
        nodes.insert(node.spec.to_key(), node.clone());

        let tree = ResolvedTree {
            direct: vec![node.spec.clone()],
            nodes,
            warnings: vec![],
        };

        let report = engine.check_tree(&tree, None);
        assert!(report.has_blockers(), "package on blocked list should be blocked");
        let blocked_results: Vec<_> = report.blocked();
        assert!(
            blocked_results.iter().any(|r| r.check_name == "blocked"),
            "should have a 'blocked' check result"
        );
    }

    #[test]
    fn fresh_package_with_postinstall_produces_two_blockers() {
        use crate::resolver::ResolvedTree;

        let engine = default_engine();
        let node = make_node_with_postinstall("danger-pkg", "1.0.0", true);
        // Override published_at to make it fresh (make_node_with_postinstall uses 30 days)
        let mut fresh_node = node;
        fresh_node.published_at = chrono::Utc::now() - chrono::Duration::days(1);

        let mut nodes = HashMap::new();
        nodes.insert(fresh_node.spec.to_key(), fresh_node.clone());

        let tree = ResolvedTree {
            direct: vec![fresh_node.spec.clone()],
            nodes,
            warnings: vec![],
        };

        let report = engine.check_tree(&tree, None);
        let blockers = report.blocked();
        assert_eq!(blockers.len(), 2, "should have age-gate AND postinstall blockers, got: {:?}",
            blockers.iter().map(|r| r.check_name).collect::<Vec<_>>());
        let check_names: Vec<&str> = blockers.iter().map(|r| r.check_name).collect();
        assert!(check_names.contains(&"age-gate"), "missing age-gate blocker");
        assert!(check_names.contains(&"postinstall"), "missing postinstall blocker");
    }

    #[test]
    fn age_gate_blocks_unknown_publish_timestamp() {
        // epoch-0 timestamp = unknown publish time → must block, not silently pass
        use crate::resolver::ResolvedTree;

        let engine = default_engine();
        let mut node = make_node("mystery-pkg", "1.0.0", 0, true);
        node.published_at = chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap();

        let mut nodes = HashMap::new();
        nodes.insert(node.spec.to_key(), node.clone());

        let tree = ResolvedTree {
            direct: vec![node.spec.clone()],
            nodes,
            warnings: vec![],
        };

        let report = engine.check_tree(&tree, None);
        assert!(report.has_blockers(), "unknown publish timestamp should be blocked, not pass");
        let blockers = report.blocked();
        let reason = match &blockers[0].outcome {
            CheckOutcome::Blocked { reason } => reason,
            _ => panic!("expected blocked"),
        };
        assert!(reason.contains("unknown"), "reason should mention unknown timestamp: {reason}");
    }
}
