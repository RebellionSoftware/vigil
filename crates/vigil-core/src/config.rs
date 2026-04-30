use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Top-level configuration loaded from `vigil.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VigilConfig {
    #[serde(default = "default_package_manager")]
    pub package_manager: String,

    #[serde(default)]
    pub policy: PolicyConfig,

    #[serde(default)]
    pub bypass: BypassConfig,

    #[serde(default)]
    pub blocked: BlockedConfig,
}

impl Default for VigilConfig {
    fn default() -> Self {
        VigilConfig {
            package_manager: default_package_manager(),
            policy: PolicyConfig::default(),
            bypass: BypassConfig::default(),
            blocked: BlockedConfig::default(),
        }
    }
}

impl VigilConfig {
    /// Load config from `vigil.toml` in the given directory.
    /// Returns defaults if no config file exists.
    pub fn load(project_dir: &Path) -> Result<Self> {
        let (config, _) = Self::load_with_hash(project_dir)?;
        Ok(config)
    }

    /// Load config and also return the SHA-256 of the raw file contents.
    /// Returns `None` for the hash if `vigil.toml` does not exist.
    pub fn load_with_hash(project_dir: &Path) -> Result<(Self, Option<String>)> {
        let path = project_dir.join("vigil.toml");
        if !path.exists() {
            return Ok((VigilConfig::default(), None));
        }
        let contents = std::fs::read_to_string(&path).map_err(Error::Io)?;
        let digest = Sha256::digest(contents.as_bytes());
        let hash = format!("{digest:x}");
        let config: VigilConfig = toml::from_str(&contents)?;
        // Validate package_manager — it is a top-level structural field whose
        // value gates which runner RunnerFactory::create will return.
        match config.package_manager.as_str() {
            "bun" | "npm" => {}
            other => {
                return Err(Error::Config(format!(
                    "unknown package_manager '{other}' — supported values: bun, npm"
                )))
            }
        }
        config.policy.validate()?;
        Ok((config, Some(hash)))
    }
}

/// Security policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Minimum days since publish before a package can be installed. 0 to disable.
    #[serde(default = "default_min_age_days")]
    pub min_age_days: u32,

    /// Require Sigstore provenance attestation (Phase 2).
    #[serde(default)]
    pub require_provenance: bool,

    /// Allow pre-release versions (alpha/beta/rc).
    #[serde(default)]
    pub allow_prerelease: bool,

    /// Block postinstall scripts by default.
    #[serde(default = "default_true")]
    pub block_postinstall: bool,

    /// Enable edit-distance typosquat name checking (Phase 2).
    #[serde(default = "default_true")]
    pub typosquat_check: bool,

    /// Prevent silent transitive dependency updates.
    #[serde(default = "default_true")]
    pub freeze_transitive: bool,

    /// Apply age gate to transitive dependency changes.
    #[serde(default = "default_true")]
    pub transitive_age_gate: bool,

    /// Apply velocity checks to transitive dependency changes (Phase 2).
    #[serde(default = "default_true")]
    pub transitive_velocity_check: bool,

    /// Days of inactivity after which a sudden new publish is flagged. 0 = disabled.
    #[serde(default = "default_inactivity_days")]
    pub inactivity_days: u32,

    /// How old the dormancy-breaking version must be (in days) before the velocity
    /// check is suppressed. If the activating version is at least this many days old
    /// it is considered "settled" and allowed through. 0 = always flag regardless of age.
    #[serde(default = "default_inactivity_settle_days")]
    pub inactivity_settle_days: u32,
}

impl PolicyConfig {
    /// Validate logical constraints on the policy configuration.
    ///
    /// TOML deserialization already rejects type-level errors (e.g. negative
    /// values for `u32` fields). This method catches semantic errors that the
    /// type system cannot express: values that are syntactically valid but
    /// operationally nonsensical.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.min_age_days > 365 {
            return Err(Error::Config(format!(
                "policy.min_age_days = {} is unreasonably large (maximum is 365 days). \
                 Values above 365 are almost certainly a misconfiguration.",
                self.min_age_days,
            )));
        }

        // inactivity_days = 0 disables the check; any other value must be sane.
        if self.inactivity_days > 3650 {
            return Err(Error::Config(format!(
                "policy.inactivity_days = {} is unreasonably large (maximum is 3650 days). \
                 Values above 3650 are almost certainly a misconfiguration.",
                self.inactivity_days,
            )));
        }

        // An inactivity window smaller than the age gate is a logic error: every
        // new publish on an inactive package would already be blocked by the age
        // gate before inactivity detection could act.
        if self.inactivity_days > 0 && self.inactivity_days < self.min_age_days {
            return Err(Error::Config(format!(
                "policy.inactivity_days ({}) must be greater than or equal to \
                 policy.min_age_days ({}), or set to 0 to disable. \
                 An inactivity window shorter than the age gate is always shadowed \
                 by the age gate and will never trigger.",
                self.inactivity_days, self.min_age_days,
            )));
        }

        if self.inactivity_settle_days > 365 {
            return Err(Error::Config(format!(
                "policy.inactivity_settle_days = {} is unreasonably large (maximum is 365 days). \
                 Values above 365 are almost certainly a misconfiguration.",
                self.inactivity_settle_days,
            )));
        }

        Ok(())
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            min_age_days: default_min_age_days(),
            require_provenance: false,
            allow_prerelease: false,
            block_postinstall: true,
            typosquat_check: true,
            freeze_transitive: true,
            transitive_age_gate: true,
            transitive_velocity_check: true,
            inactivity_days: default_inactivity_days(),
            inactivity_settle_days: default_inactivity_settle_days(),
        }
    }
}

fn default_package_manager() -> String {
    "bun".to_string()
}

fn default_min_age_days() -> u32 {
    7
}

fn default_inactivity_days() -> u32 {
    180
}

fn default_inactivity_settle_days() -> u32 {
    60
}

fn default_true() -> bool {
    true
}

/// Bypass rules — packages exempted from certain checks.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BypassConfig {
    /// Packages permanently exempt from the age gate.
    #[serde(default)]
    pub allow_fresh: Vec<String>,

    /// Packages pre-approved to run postinstall scripts.
    /// Written by `vigil trust <pkg> --allow postinstall` when the package
    /// is not yet installed. Once installed, approval moves to vigil.lock.
    #[serde(default)]
    pub allow_postinstall: Vec<String>,

    /// Packages approved to install despite long inactivity gap.
    /// Written by `vigil trust <pkg> --allow inactivity`.
    #[serde(default)]
    pub allow_inactivity: Vec<String>,
}

/// Blocked packages — can never be installed regardless of policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockedConfig {
    #[serde(default)]
    pub packages: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec() {
        let config = VigilConfig::default();
        assert_eq!(config.policy.min_age_days, 7);
        assert!(config.policy.block_postinstall);
        assert!(config.policy.freeze_transitive);
        assert!(config.policy.transitive_age_gate);
        assert!(!config.policy.allow_prerelease);
        assert!(!config.policy.require_provenance);
        assert_eq!(config.policy.inactivity_days, 180);
        assert_eq!(config.policy.inactivity_settle_days, 60);
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[policy]
min_age_days = 14
allow_prerelease = true
block_postinstall = false
freeze_transitive = true
inactivity_days = 90

[bypass]
allow_fresh = ["@internal/shared"]

[blocked]
packages = ["colors", "faker"]
"#;
        let config: VigilConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.policy.min_age_days, 14);
        assert!(config.policy.allow_prerelease);
        assert!(!config.policy.block_postinstall);
        assert_eq!(config.bypass.allow_fresh, vec!["@internal/shared"]);
        assert_eq!(config.blocked.packages, vec!["colors", "faker"]);
        assert_eq!(config.policy.inactivity_days, 90);
        assert!(config.policy.validate().is_ok());
    }

    #[test]
    fn parse_empty_config_uses_defaults() {
        let config: VigilConfig = toml::from_str("").unwrap();
        assert_eq!(config.policy.min_age_days, 7);
        assert!(config.policy.block_postinstall);
        assert!(config.policy.validate().is_ok());
    }

    #[test]
    fn load_returns_defaults_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = VigilConfig::load(dir.path()).unwrap();
        assert_eq!(config.policy.min_age_days, 7);
    }

    // ── Policy validation tests ───────────────────────────────────────────────

    #[test]
    fn valid_policy_passes_validation() {
        let mut p = PolicyConfig::default();
        p.min_age_days = 7;
        p.inactivity_days = 180;
        assert!(p.validate().is_ok());
    }

    #[test]
    fn min_age_days_at_maximum_passes() {
        let mut p = PolicyConfig::default();
        p.min_age_days = 365;
        p.inactivity_days = 365; // must be >= min_age_days when non-zero
        assert!(p.validate().is_ok());
    }

    #[test]
    fn min_age_days_above_maximum_fails() {
        let mut p = PolicyConfig::default();
        p.min_age_days = 366;
        let err = p.validate().unwrap_err();
        assert!(
            err.to_string().contains("min_age_days"),
            "error should mention the field: {err}"
        );
    }

    #[test]
    fn inactivity_days_zero_disables_check_passes() {
        let mut p = PolicyConfig::default();
        p.min_age_days = 30;
        p.inactivity_days = 0;
        assert!(p.validate().is_ok());
    }

    #[test]
    fn inactivity_days_above_maximum_fails() {
        let mut p = PolicyConfig::default();
        p.inactivity_days = 3651;
        let err = p.validate().unwrap_err();
        assert!(
            err.to_string().contains("inactivity_days"),
            "error should mention the field: {err}"
        );
    }

    #[test]
    fn inactivity_days_less_than_min_age_days_fails() {
        let mut p = PolicyConfig::default();
        p.min_age_days = 30;
        p.inactivity_days = 10; // non-zero, smaller than min_age_days
        let err = p.validate().unwrap_err();
        assert!(
            err.to_string().contains("inactivity_days"),
            "error should mention the field: {err}"
        );
    }

    #[test]
    fn inactivity_days_equal_to_min_age_days_passes() {
        let mut p = PolicyConfig::default();
        p.min_age_days = 30;
        p.inactivity_days = 30;
        assert!(p.validate().is_ok());
    }

    #[test]
    fn inactivity_days_at_maximum_passes() {
        let mut p = PolicyConfig::default();
        p.min_age_days = 7;
        p.inactivity_days = 3650;
        assert!(p.validate().is_ok());
    }

    #[test]
    fn both_checks_disabled_passes() {
        // min_age_days = 0 disables the age gate; inactivity_days = 0 disables
        // inactivity detection. Both disabled is a valid (if weak) configuration.
        let mut p = PolicyConfig::default();
        p.min_age_days = 0;
        p.inactivity_days = 0;
        assert!(p.validate().is_ok());
    }

    #[test]
    fn age_gate_disabled_inactivity_enabled_passes() {
        // min_age_days = 0 + non-zero inactivity_days is an odd combination —
        // the age gate is off but inactivity detection still fires. The ordering
        // constraint (inactivity >= min_age) uses inactivity_days > 0 as a guard,
        // so 30 > 0 && 30 < 0 is false and this correctly passes validation.
        let mut p = PolicyConfig::default();
        p.min_age_days = 0;
        p.inactivity_days = 30;
        assert!(p.validate().is_ok());
    }

    #[test]
    fn inactivity_settle_days_above_maximum_fails() {
        let mut p = PolicyConfig::default();
        p.inactivity_settle_days = 366;
        let err = p.validate().unwrap_err();
        assert!(
            err.to_string().contains("inactivity_settle_days"),
            "error should mention the field: {err}"
        );
    }

    #[test]
    fn inactivity_settle_days_zero_is_valid() {
        let mut p = PolicyConfig::default();
        p.inactivity_settle_days = 0;
        assert!(p.validate().is_ok());
    }

    #[test]
    fn inactivity_settle_days_at_maximum_passes() {
        let mut p = PolicyConfig::default();
        p.inactivity_settle_days = 365;
        assert!(p.validate().is_ok());
    }

    #[test]
    fn parse_inactivity_settle_days_from_toml() {
        let toml = r#"
[policy]
inactivity_days = 180
inactivity_settle_days = 90
"#;
        let config: VigilConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.policy.inactivity_settle_days, 90);
        assert!(config.policy.validate().is_ok());
    }

    #[test]
    fn load_with_invalid_policy_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("vigil.toml"),
            "[policy]\nmin_age_days = 400\n",
        )
        .unwrap();
        let err = VigilConfig::load(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("min_age_days"),
            "error should mention the invalid field: {err}"
        );
    }

    // ── package_manager tests ───────────────────────────────────────────────────

    #[test]
    fn package_manager_default_is_bun() {
        let config = VigilConfig::default();
        assert_eq!(config.package_manager, "bun");
    }

    #[test]
    fn package_manager_npm_passes_load_validation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("vigil.toml"),
            "package_manager = \"npm\"\n",
        )
        .unwrap();
        let (config, _) = VigilConfig::load_with_hash(dir.path()).unwrap();
        assert_eq!(config.package_manager, "npm");
    }

    #[test]
    fn package_manager_yarn_fails_at_load_time() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("vigil.toml"),
            "package_manager = \"yarn\"\n",
        )
        .unwrap();
        let err = VigilConfig::load(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("package_manager"),
            "error should mention package_manager: {err}"
        );
        assert!(
            err.to_string().contains("yarn"),
            "error should mention the invalid value: {err}"
        );
    }
}
