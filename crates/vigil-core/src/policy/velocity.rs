use crate::{
    config::{BypassConfig, PolicyConfig},
    resolver::ResolvedNode,
};
use super::{CheckOutcome, CheckResult};

pub fn check(node: &ResolvedNode, config: &PolicyConfig, bypass: &BypassConfig) -> Vec<CheckResult> {
    if config.inactivity_days == 0 {
        return vec![];
    }

    let name = node.spec.name.to_string();

    if bypass.allow_inactivity.contains(&name) {
        return vec![CheckResult {
            package: node.spec.clone(),
            check_name: "velocity",
            outcome: CheckOutcome::Passed,
        }];
    }

    let outcome = match node.days_since_prior_publish {
        // Genuinely first-ever version — no prior publish to compare against.
        None => CheckOutcome::Passed,

        // Prior version entries exist but timestamps are malformed or manipulated
        // (future-dated prior versions, unparseable values, etc.). Treat as maximally
        // suspicious rather than silently passing.
        Some(i64::MAX) => CheckOutcome::Blocked {
            reason: format!(
                "'{name}' has unverifiable publish history — prior version timestamps are \
                 malformed or inconsistent. This may indicate registry data tampering. \
                 Run `vigil trust {name} --allow inactivity` to override after investigating."
            ),
        },

        Some(gap_days) if gap_days >= config.inactivity_days as i64 => CheckOutcome::Blocked {
            reason: format!(
                "'{name}' was dormant for {gap_days} days before this publish — \
                 sudden activity after long inactivity is a common account-takeover signal. \
                 Run `vigil trust {name} --allow inactivity` to approve after reviewing the changelog."
            ),
        },

        Some(_) => CheckOutcome::Passed,
    };

    vec![CheckResult {
        package: node.spec.clone(),
        check_name: "velocity",
        outcome,
    }]
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

    fn make_node(name: &str, days_since_prior: Option<i64>) -> ResolvedNode {
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
                scripts: HashMap::new(),
                has_install_script: false,
                maintainers: vec![],
            },
            published_at: Utc::now() - Duration::days(10),
            is_direct: true,
            has_install_script: false,
            days_since_prior_publish: days_since_prior,
        }
    }

    fn default_config() -> PolicyConfig {
        PolicyConfig::default() // inactivity_days = 180
    }

    fn default_bypass() -> BypassConfig {
        BypassConfig::default()
    }

    #[test]
    fn blocks_after_long_dormancy() {
        let node = make_node("comeback-pkg", Some(200));
        let results = check(&node, &default_config(), &default_bypass());
        assert!(results[0].outcome.is_blocked(), "200-day gap should be blocked");
    }

    #[test]
    fn passes_within_threshold() {
        let node = make_node("active-pkg", Some(30));
        let results = check(&node, &default_config(), &default_bypass());
        assert!(results[0].outcome.is_passed());
    }

    #[test]
    fn passes_exactly_at_threshold() {
        let node = make_node("borderline-pkg", Some(180));
        let results = check(&node, &default_config(), &default_bypass());
        assert!(results[0].outcome.is_blocked(), "exactly at threshold should block");
    }

    #[test]
    fn passes_first_ever_version() {
        let node = make_node("brand-new-pkg", None);
        let results = check(&node, &default_config(), &default_bypass());
        assert!(results[0].outcome.is_passed(), "first version should not trigger velocity check");
    }

    #[test]
    fn disabled_when_inactivity_days_zero() {
        let mut config = PolicyConfig::default();
        config.inactivity_days = 0;
        let node = make_node("comeback-pkg", Some(500));
        let results = check(&node, &config, &default_bypass());
        assert!(results.is_empty(), "check disabled when inactivity_days = 0");
    }

    #[test]
    fn bypass_allow_inactivity_passes() {
        let bypass = BypassConfig {
            allow_fresh: vec![],
            allow_postinstall: vec![],
            allow_inactivity: vec!["comeback-pkg".to_string()],
        };
        let node = make_node("comeback-pkg", Some(500));
        let results = check(&node, &default_config(), &bypass);
        assert!(results[0].outcome.is_passed(), "bypassed package should pass");
    }

    #[test]
    fn reason_mentions_gap_days() {
        let node = make_node("old-pkg", Some(365));
        let results = check(&node, &default_config(), &default_bypass());
        match &results[0].outcome {
            CheckOutcome::Blocked { reason } => {
                assert!(reason.contains("365"), "reason should mention gap days: {reason}");
                assert!(reason.contains("vigil trust"), "reason should include trust command: {reason}");
            }
            _ => panic!("expected blocked"),
        }
    }

    #[test]
    fn tampered_timestamps_blocks() {
        // i64::MAX sentinel = malformed/manipulated registry timestamps
        let node = make_node("tampered-pkg", Some(i64::MAX));
        let results = check(&node, &default_config(), &default_bypass());
        assert!(results[0].outcome.is_blocked(), "unverifiable timestamps should block");
        match &results[0].outcome {
            CheckOutcome::Blocked { reason } => {
                assert!(reason.contains("tamper") || reason.contains("malformed"),
                    "reason should mention tampering: {reason}");
            }
            _ => panic!("expected blocked"),
        }
    }

    #[test]
    fn tampered_timestamps_bypassed_by_allow_inactivity() {
        let bypass = BypassConfig {
            allow_fresh: vec![],
            allow_postinstall: vec![],
            allow_inactivity: vec!["tampered-pkg".to_string()],
        };
        let node = make_node("tampered-pkg", Some(i64::MAX));
        let results = check(&node, &default_config(), &bypass);
        assert!(results[0].outcome.is_passed(), "bypass should work even for tampered timestamps");
    }
}
