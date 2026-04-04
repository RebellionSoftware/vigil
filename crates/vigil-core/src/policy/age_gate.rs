use chrono::Utc;
use crate::{
    config::PolicyConfig,
    policy::{CheckOutcome, CheckResult},
    resolver::ResolvedNode,
};

/// Check whether a package's published age meets the minimum age requirement.
///
/// Returns a single-element Vec for consistency with other check functions.
/// Returns an empty Vec only if `min_age_days == 0` (check disabled at engine level).
pub fn check(node: &ResolvedNode, config: &PolicyConfig) -> Vec<CheckResult> {
    // Unknown publish time — treat as maximally suspicious (block, not pass)
    if node.published_at == chrono::DateTime::<chrono::Utc>::UNIX_EPOCH {
        return vec![CheckResult {
            package: node.spec.clone(),
            check_name: "age-gate",
            outcome: CheckOutcome::Blocked {
                reason: format!(
                    "publish timestamp is unknown or missing from registry. \
                     Use --allow-fresh {} --reason \"<reason>\" to override.",
                    node.spec.name,
                ),
            },
        }];
    }

    let age_days = age_in_days(node);

    let outcome = if age_days >= config.min_age_days as i64 {
        CheckOutcome::Passed
    } else {
        let days_until_ok = config.min_age_days as i64 - age_days;
        CheckOutcome::Blocked {
            reason: format!(
                "published {} day{} ago (minimum: {}). \
                 Retry in {} day{}, or use --allow-fresh {} --reason \"<reason>\"",
                age_days,
                if age_days == 1 { "" } else { "s" },
                config.min_age_days,
                days_until_ok,
                if days_until_ok == 1 { "" } else { "s" },
                node.spec.name,
            ),
        }
    };

    vec![CheckResult {
        package: node.spec.clone(),
        check_name: "age-gate",
        outcome,
    }]
}

/// Return how many days ago the package was published, clamped to 0.
pub fn age_in_days(node: &ResolvedNode) -> i64 {
    let duration = Utc::now().signed_duration_since(node.published_at);
    duration.num_days().max(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::PolicyConfig,
        registry::{DistInfo, VersionMetadata},
        resolver::ResolvedNode,
        types::{ExactVersion, PackageName, PackageSpec},
    };
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    fn node_published_days_ago(days: i64) -> ResolvedNode {
        ResolvedNode {
            spec: PackageSpec::new(
                PackageName::new("test-pkg").unwrap(),
                ExactVersion::new("1.0.0"),
            ),
            dependencies: vec![],
            dependents: vec![],
            metadata: VersionMetadata {
                name: "test-pkg".to_string(),
                version: "1.0.0".to_string(),
                dependencies: HashMap::new(),
                peer_dependencies: HashMap::new(),
                dist: DistInfo {
                    integrity: None,
                    shasum: "fake".to_string(),
                    tarball: "https://example.com".to_string(),
                },
                scripts: HashMap::new(),
                has_install_script: false,
                maintainers: vec![],
            },
            published_at: Utc::now() - Duration::days(days),
            is_direct: true,
            has_install_script: false,
            days_since_prior_publish: None,
        }
    }

    #[test]
    fn blocks_package_published_2_days_ago() {
        let config = PolicyConfig { min_age_days: 7, ..Default::default() };
        let node = node_published_days_ago(2);
        let results = check(&node, &config);
        assert_eq!(results.len(), 1);
        assert!(results[0].outcome.is_blocked(), "2-day-old package should be blocked");
        let reason = match &results[0].outcome {
            CheckOutcome::Blocked { reason } => reason.clone(),
            _ => panic!("expected blocked"),
        };
        assert!(reason.contains("2 days ago"), "reason: {reason}");
        assert!(reason.contains("minimum: 7"), "reason: {reason}");
    }

    #[test]
    fn passes_package_published_10_days_ago() {
        let config = PolicyConfig { min_age_days: 7, ..Default::default() };
        let node = node_published_days_ago(10);
        let results = check(&node, &config);
        assert_eq!(results.len(), 1);
        assert!(results[0].outcome.is_passed());
    }

    #[test]
    fn passes_at_exactly_threshold() {
        let config = PolicyConfig { min_age_days: 7, ..Default::default() };
        let node = node_published_days_ago(7);
        let results = check(&node, &config);
        assert_eq!(results.len(), 1);
        assert!(results[0].outcome.is_passed());
    }

    #[test]
    fn blocks_with_correct_retry_days() {
        let config = PolicyConfig { min_age_days: 14, ..Default::default() };
        let node = node_published_days_ago(4);
        let results = check(&node, &config);
        assert_eq!(results.len(), 1);
        let reason = match &results[0].outcome {
            CheckOutcome::Blocked { reason } => reason.clone(),
            _ => panic!("expected blocked"),
        };
        assert!(reason.contains("10 days"), "retry days should be 10, got: {reason}");
    }

    #[test]
    fn zero_min_age_would_always_pass() {
        let config = PolicyConfig { min_age_days: 0, ..Default::default() };
        let node = node_published_days_ago(0);
        let results = check(&node, &config);
        assert_eq!(results.len(), 1);
        assert!(results[0].outcome.is_passed());
    }

    #[test]
    fn epoch_zero_timestamp_blocks_not_passes() {
        // A missing publish timestamp falls back to epoch 0 in parse_published_at.
        // This must block (unsafe direction), not silently pass.
        let config = PolicyConfig { min_age_days: 7, ..Default::default() };
        let mut node = node_published_days_ago(999); // would normally pass
        node.published_at = chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap();
        let results = check(&node, &config);
        assert_eq!(results.len(), 1);
        assert!(results[0].outcome.is_blocked(), "epoch-0 timestamp must block");
        match &results[0].outcome {
            CheckOutcome::Blocked { reason } => {
                assert!(reason.contains("unknown"), "reason: {reason}");
            }
            _ => panic!("expected blocked"),
        }
    }
}
