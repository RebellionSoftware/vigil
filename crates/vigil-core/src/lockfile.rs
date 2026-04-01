use std::collections::BTreeMap;
use std::path::Path;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::error::{Error, Result};

pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;
pub const LOCKFILE_FILENAME: &str = "vigil.lock";

/// The full vigil lockfile, recording every approved package (direct and transitive).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VigilLockfile {
    pub meta: LockfileMeta,
    /// Keys are "name@version" strings.
    pub packages: BTreeMap<String, LockedPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockfileMeta {
    pub schema_version: u32,
    pub vigil_version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A single package entry in the lockfile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedPackage {
    /// SHA-512 hash of the installed package directory contents.
    pub content_hash: String,
    /// When the package version was published to npm.
    pub published_at: DateTime<Utc>,
    /// Age in days at time of install (for audit trail).
    pub age_at_install_days: u32,
    /// True if this is a direct (user-requested) dependency.
    pub direct: bool,
    /// Names of direct packages that pulled this in (empty if direct=true).
    pub transitive_of: Vec<String>,
    /// Whether a postinstall script has been explicitly approved via `vigil trust`.
    pub postinstall_approved: bool,
    /// When this entry was written to the lockfile.
    pub installed_at: DateTime<Utc>,
    /// The system user who ran the install.
    pub installed_by: String,
}

impl VigilLockfile {
    pub fn new() -> Self {
        let now = Utc::now();
        VigilLockfile {
            meta: LockfileMeta {
                schema_version: SUPPORTED_SCHEMA_VERSION,
                vigil_version: env!("CARGO_PKG_VERSION").to_string(),
                created_at: now,
                updated_at: now,
            },
            packages: BTreeMap::new(),
        }
    }

    /// Read vigil.lock from the given project directory.
    pub fn read(project_dir: &Path) -> Result<Self> {
        let path = project_dir.join(LOCKFILE_FILENAME);
        let contents = std::fs::read_to_string(&path)?;
        let lockfile: VigilLockfile = toml::from_str(&contents)?;

        if lockfile.meta.schema_version > SUPPORTED_SCHEMA_VERSION {
            return Err(Error::LockfileSchemaTooNew {
                found: lockfile.meta.schema_version,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }

        Ok(lockfile)
    }

    /// Read vigil.lock if it exists, or return None.
    pub fn read_optional(project_dir: &Path) -> Result<Option<Self>> {
        let path = project_dir.join(LOCKFILE_FILENAME);
        if !path.exists() {
            return Ok(None);
        }
        Self::read(project_dir).map(Some)
    }

    /// Write vigil.lock to the given project directory.
    pub fn write(&mut self, project_dir: &Path) -> Result<()> {
        self.meta.updated_at = Utc::now();
        let path = project_dir.join(LOCKFILE_FILENAME);
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Returns true if the lockfile contains the given "name@version" key.
    pub fn contains(&self, key: &str) -> bool {
        self.packages.contains_key(key)
    }

    /// Returns all packages that are transitive deps of the given direct package name.
    pub fn transitives_of(&self, direct_name: &str) -> Vec<(&String, &LockedPackage)> {
        self.packages
            .iter()
            .filter(|(_, pkg)| pkg.transitive_of.iter().any(|p| p == direct_name))
            .collect()
    }
}

impl Default for VigilLockfile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_lockfile() -> VigilLockfile {
        let mut lf = VigilLockfile::new();
        lf.packages.insert(
            "axios@1.7.4".to_string(),
            LockedPackage {
                content_hash: "sha512-abc123".to_string(),
                published_at: "2025-03-14T10:00:00Z".parse().unwrap(),
                age_at_install_days: 14,
                direct: true,
                transitive_of: vec![],
                postinstall_approved: false,
                installed_at: Utc::now(),
                installed_by: "testuser".to_string(),
            },
        );
        lf.packages.insert(
            "follow-redirects@1.15.6".to_string(),
            LockedPackage {
                content_hash: "sha512-def456".to_string(),
                published_at: "2025-02-01T09:00:00Z".parse().unwrap(),
                age_at_install_days: 55,
                direct: false,
                transitive_of: vec!["axios".to_string()],
                postinstall_approved: false,
                installed_at: Utc::now(),
                installed_by: "testuser".to_string(),
            },
        );
        lf
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut lf = sample_lockfile();
        lf.write(dir.path()).unwrap();

        let read_back = VigilLockfile::read(dir.path()).unwrap();
        assert_eq!(read_back.packages.len(), 2);
        assert!(read_back.contains("axios@1.7.4"));
        assert!(read_back.contains("follow-redirects@1.15.6"));
    }

    #[test]
    fn read_optional_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let result = VigilLockfile::read_optional(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn schema_version_too_new_errors() {
        let dir = tempfile::tempdir().unwrap();
        let contents = r#"
[meta]
schema_version = 999
vigil_version = "0.1.0"
created_at = "2026-04-01T00:00:00Z"
updated_at = "2026-04-01T00:00:00Z"

[packages]
"#;
        std::fs::write(dir.path().join("vigil.lock"), contents).unwrap();
        let result = VigilLockfile::read(dir.path());
        assert!(matches!(result, Err(Error::LockfileSchemaTooNew { .. })));
    }

    #[test]
    fn transitives_of() {
        let lf = sample_lockfile();
        let transitives = lf.transitives_of("axios");
        assert_eq!(transitives.len(), 1);
        assert_eq!(transitives[0].0, "follow-redirects@1.15.6");
    }

    #[test]
    fn schema_version_is_1() {
        let lf = VigilLockfile::new();
        assert_eq!(lf.meta.schema_version, SUPPORTED_SCHEMA_VERSION);
    }
}
