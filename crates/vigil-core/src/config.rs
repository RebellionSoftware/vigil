use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use crate::error::{Error, Result};

/// Top-level configuration loaded from `vigil.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VigilConfig {
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
        }
    }
}

fn default_min_age_days() -> u32 {
    7
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
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[policy]
min_age_days = 14
allow_prerelease = true
block_postinstall = false
freeze_transitive = true

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
    }

    #[test]
    fn parse_empty_config_uses_defaults() {
        let config: VigilConfig = toml::from_str("").unwrap();
        assert_eq!(config.policy.min_age_days, 7);
        assert!(config.policy.block_postinstall);
    }

    #[test]
    fn load_returns_defaults_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = VigilConfig::load(dir.path()).unwrap();
        assert_eq!(config.policy.min_age_days, 7);
    }
}
