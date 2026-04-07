use std::collections::BTreeMap;
use std::path::Path;
use serde_json::json;
use crate::{
    error::{Error, Result},
    lockfile::VigilLockfile,
    package_json,
};

/// Sentinel value written into `overrides._vigil` to mark the block as vigil-managed.
pub const VIGIL_SENTINEL_KEY: &str = "_vigil";
pub const VIGIL_SENTINEL_VALUE: &str = "DO NOT EDIT — managed by vigil";

/// A single entry in a drift report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftEntry {
    pub package: String,
    pub issue: DriftIssue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftIssue {
    /// Package is in the lockfile (as transitive) but missing from overrides.
    MissingFromOverrides { expected_version: String },
    /// Package is in overrides but not in the lockfile — may have been removed.
    ExtraInOverrides { actual_version: String },
    /// Package is in both but the pinned version differs.
    VersionMismatch { expected: String, actual: String },
    /// The `_vigil` sentinel is absent — the block was not created by vigil.
    SentinelMissing,
}

pub struct OverridesManager;

impl OverridesManager {
    /// Read the `overrides` block from `package.json`.
    ///
    /// Returns `None` if no `overrides` key is present.
    pub fn read_overrides(project_dir: &Path) -> Result<Option<BTreeMap<String, String>>> {
        let v = package_json::read_package_json(project_dir)?;
        let Some(overrides_val) = v.get("overrides") else {
            return Ok(None);
        };
        let Some(obj) = overrides_val.as_object() else {
            return Err(Error::PackageJsonWrite(
                "overrides field is not a JSON object".to_string(),
            ));
        };
        let map: BTreeMap<String, String> = obj
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();
        Ok(Some(map))
    }

    /// Write a vigil-managed `overrides` block into `package.json`.
    ///
    /// - Preserves all other fields in `package.json`.
    /// - Injects the `_vigil` sentinel.
    /// - Creates a backup before writing (see `package_json::write_package_json`).
    /// - Errors if an `overrides` block exists but was **not** created by vigil
    ///   (i.e. sentinel is absent), to avoid silently overwriting user-managed overrides.
    pub fn write_overrides(
        project_dir: &Path,
        overrides: &BTreeMap<String, String>,
    ) -> Result<()> {
        let mut v = package_json::read_package_json(project_dir)?;

        // Guard: if a non-empty overrides block exists without the sentinel, refuse to
        // overwrite — it was created by the user or another tool, not by vigil.
        if let Some(obj) = v.get("overrides").and_then(|v| v.as_object()) {
            if !obj.is_empty() && !obj.contains_key(VIGIL_SENTINEL_KEY) {
                return Err(Error::PackageJsonWrite(
                    "package.json already has an overrides block not managed by vigil \
                     (missing _vigil sentinel). Remove it manually or add the sentinel \
                     to let vigil manage it."
                        .to_string(),
                ));
            }
        }

        // Build the new overrides object with sentinel first.
        let mut obj = serde_json::Map::new();
        obj.insert(VIGIL_SENTINEL_KEY.to_string(), json!(VIGIL_SENTINEL_VALUE));
        for (name, version) in overrides {
            obj.insert(name.clone(), json!(version));
        }

        v["overrides"] = serde_json::Value::Object(obj);
        package_json::write_package_json(project_dir, &v)
    }

    /// Build the `overrides` map from a lockfile.
    ///
    /// Only **transitive** (non-direct) packages are included — direct deps are
    /// managed by `dependencies`/`devDependencies` and don't belong in overrides.
    pub fn generate_overrides(lockfile: &VigilLockfile) -> BTreeMap<String, String> {
        lockfile
            .packages
            .iter()
            .filter(|(_, pkg)| !pkg.direct)
            .filter_map(|(key, _)| {
                // key format: "name@version" or "@scope/name@version"
                // rsplit_once('@') correctly handles scoped packages.
                // A key with no '@' is a malformed lockfile entry — skip it rather
                // than emitting an empty version string into package.json.
                key.rsplit_once('@')
                    .map(|(name, version)| (name.to_string(), version.to_string()))
            })
            .collect()
    }

    /// Compare the `overrides` block in `package.json` against the lockfile.
    ///
    /// Returns a list of discrepancies. An empty list means the file is in sync.
    pub fn detect_drift(project_dir: &Path, lockfile: &VigilLockfile) -> Result<Vec<DriftEntry>> {
        let mut entries = Vec::new();

        let expected = Self::generate_overrides(lockfile);

        let actual = match Self::read_overrides(project_dir)? {
            None => {
                // No overrides block at all — sentinel is missing and every entry is missing.
                entries.push(DriftEntry {
                    package: VIGIL_SENTINEL_KEY.to_string(),
                    issue: DriftIssue::SentinelMissing,
                });
                for (pkg, ver) in &expected {
                    entries.push(DriftEntry {
                        package: pkg.clone(),
                        issue: DriftIssue::MissingFromOverrides {
                            expected_version: ver.clone(),
                        },
                    });
                }
                return Ok(entries);
            }
            Some(m) => m,
        };

        // Check for sentinel
        if !actual.contains_key(VIGIL_SENTINEL_KEY) {
            entries.push(DriftEntry {
                package: VIGIL_SENTINEL_KEY.to_string(),
                issue: DriftIssue::SentinelMissing,
            });
        }

        // Check expected entries
        for (pkg, expected_ver) in &expected {
            match actual.get(pkg) {
                None => entries.push(DriftEntry {
                    package: pkg.clone(),
                    issue: DriftIssue::MissingFromOverrides {
                        expected_version: expected_ver.clone(),
                    },
                }),
                Some(actual_ver) => {
                    if actual_ver != expected_ver {
                        entries.push(DriftEntry {
                            package: pkg.clone(),
                            issue: DriftIssue::VersionMismatch {
                                expected: expected_ver.clone(),
                                actual: actual_ver.clone(),
                            },
                        });
                    }
                }
            }
        }

        // Check for extra entries (ignoring the sentinel key)
        for pkg in actual.keys() {
            if pkg == VIGIL_SENTINEL_KEY {
                continue;
            }
            if !expected.contains_key(pkg) {
                entries.push(DriftEntry {
                    package: pkg.clone(),
                    issue: DriftIssue::ExtraInOverrides {
                        actual_version: actual[pkg].clone(),
                    },
                });
            }
        }

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::{LockedPackage, VigilLockfile};
    use chrono::Utc;

    fn write_package_json(dir: &Path, content: &str) {
        std::fs::write(dir.join("package.json"), content).unwrap();
    }

    // ── generate_overrides ────────────────────────────────────────────────────

    fn lockfile_with_packages() -> VigilLockfile {
        let mut lf = VigilLockfile::new();
        lf.packages.insert("express@4.18.2".into(), LockedPackage {
            content_hash: "sha512-e".into(), published_at: Utc::now(),
            age_at_install_days: 100, direct: true, dev: false, optional: false, transitive_of: vec![],
            postinstall_approved: false, installed_at: Utc::now(), installed_by: "u".into(),
        });
        lf.packages.insert("ms@2.1.3".into(), LockedPackage {
            content_hash: "sha512-m".into(), published_at: Utc::now(),
            age_at_install_days: 30, direct: false, dev: false, optional: false, transitive_of: vec!["express".into()],
            postinstall_approved: false, installed_at: Utc::now(), installed_by: "u".into(),
        });
        lf.packages.insert("debug@4.4.3".into(), LockedPackage {
            content_hash: "sha512-d".into(), published_at: Utc::now(),
            age_at_install_days: 30, direct: false, dev: false, optional: false, transitive_of: vec!["express".into()],
            postinstall_approved: false, installed_at: Utc::now(), installed_by: "u".into(),
        });
        lf
    }

    #[test]
    fn generate_overrides_excludes_direct_deps() {
        let lf = lockfile_with_packages();
        let overrides = OverridesManager::generate_overrides(&lf);
        assert!(!overrides.contains_key("express"), "direct dep should not be in overrides");
        assert!(overrides.contains_key("ms"), "transitive should be in overrides");
        assert!(overrides.contains_key("debug"), "transitive should be in overrides");
        assert_eq!(overrides["ms"], "2.1.3");
        assert_eq!(overrides["debug"], "4.4.3");
    }

    #[test]
    fn generate_overrides_scoped_package() {
        let mut lf = VigilLockfile::new();
        lf.packages.insert("@scope/pkg@1.2.3".into(), LockedPackage {
            content_hash: "sha512-s".into(), published_at: Utc::now(),
            age_at_install_days: 10, direct: false, dev: false, optional: false, transitive_of: vec!["root".into()],
            postinstall_approved: false, installed_at: Utc::now(), installed_by: "u".into(),
        });
        let overrides = OverridesManager::generate_overrides(&lf);
        assert_eq!(overrides.get("@scope/pkg").map(|v| v.as_str()), Some("1.2.3"));
    }

    // ── write_overrides / read_overrides ──────────────────────────────────────

    #[test]
    fn write_and_read_overrides_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), r#"{"name":"app","version":"1.0.0"}"#);

        let lf = lockfile_with_packages();
        let overrides = OverridesManager::generate_overrides(&lf);
        OverridesManager::write_overrides(dir.path(), &overrides).unwrap();

        let read_back = OverridesManager::read_overrides(dir.path()).unwrap().unwrap();
        assert_eq!(read_back["ms"], "2.1.3");
        assert_eq!(read_back["debug"], "4.4.3");
        assert_eq!(read_back[VIGIL_SENTINEL_KEY], VIGIL_SENTINEL_VALUE);
    }

    #[test]
    fn write_overrides_preserves_other_fields() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), r#"{"name":"my-app","version":"2.0.0","scripts":{"build":"tsc"}}"#);

        let overrides: BTreeMap<String, String> = [("ms".into(), "2.1.3".into())].into();
        OverridesManager::write_overrides(dir.path(), &overrides).unwrap();

        let v = crate::package_json::read_package_json(dir.path()).unwrap();
        assert_eq!(v["name"], serde_json::json!("my-app"));
        assert_eq!(v["scripts"]["build"], serde_json::json!("tsc"));
    }

    #[test]
    fn write_overrides_errors_on_non_vigil_overrides() {
        let dir = tempfile::tempdir().unwrap();
        // Existing overrides block with no _vigil sentinel
        write_package_json(dir.path(), r#"{"name":"app","overrides":{"lodash":"4.17.21"}}"#);

        let overrides: BTreeMap<String, String> = [("ms".into(), "2.1.3".into())].into();
        let result = OverridesManager::write_overrides(dir.path(), &overrides);
        assert!(result.is_err(), "should refuse to overwrite non-vigil overrides");
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("sentinel"), "error should mention sentinel: {err_msg}");
    }

    #[test]
    fn write_overrides_allows_empty_existing_overrides() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), r#"{"name":"app","overrides":{}}"#);

        let overrides: BTreeMap<String, String> = [("ms".into(), "2.1.3".into())].into();
        // Empty overrides block (no sentinel) should be fine — vigil is claiming it for the first time.
        assert!(OverridesManager::write_overrides(dir.path(), &overrides).is_ok());
    }

    #[test]
    fn read_overrides_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), r#"{"name":"app"}"#);
        assert!(OverridesManager::read_overrides(dir.path()).unwrap().is_none());
    }

    // ── detect_drift ──────────────────────────────────────────────────────────

    fn write_vigil_overrides(dir: &Path, entries: &[(&str, &str)]) {
        let mut obj = serde_json::Map::new();
        obj.insert(VIGIL_SENTINEL_KEY.into(), serde_json::json!(VIGIL_SENTINEL_VALUE));
        for (k, v) in entries {
            obj.insert((*k).into(), serde_json::json!(*v));
        }
        let content = serde_json::json!({"name":"app","overrides": obj});
        std::fs::write(dir.join("package.json"), serde_json::to_string(&content).unwrap()).unwrap();
    }

    #[test]
    fn detect_drift_clean_state() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lockfile_with_packages();
        write_vigil_overrides(dir.path(), &[("ms", "2.1.3"), ("debug", "4.4.3")]);

        let drift = OverridesManager::detect_drift(dir.path(), &lf).unwrap();
        assert!(drift.is_empty(), "should detect no drift: {:?}", drift);
    }

    #[test]
    fn detect_drift_missing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lockfile_with_packages();
        // Omit debug from overrides
        write_vigil_overrides(dir.path(), &[("ms", "2.1.3")]);

        let drift = OverridesManager::detect_drift(dir.path(), &lf).unwrap();
        assert!(
            drift.iter().any(|e| e.package == "debug" && matches!(e.issue, DriftIssue::MissingFromOverrides { .. })),
            "should detect missing debug: {:?}", drift
        );
    }

    #[test]
    fn detect_drift_extra_entry() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lockfile_with_packages();
        // Add lodash which is not in the lockfile
        write_vigil_overrides(dir.path(), &[("ms", "2.1.3"), ("debug", "4.4.3"), ("lodash", "4.17.21")]);

        let drift = OverridesManager::detect_drift(dir.path(), &lf).unwrap();
        assert!(
            drift.iter().any(|e| e.package == "lodash" && matches!(e.issue, DriftIssue::ExtraInOverrides { .. })),
            "should detect extra lodash: {:?}", drift
        );
    }

    #[test]
    fn detect_drift_version_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lockfile_with_packages();
        // ms pinned to wrong version
        write_vigil_overrides(dir.path(), &[("ms", "2.0.0"), ("debug", "4.4.3")]);

        let drift = OverridesManager::detect_drift(dir.path(), &lf).unwrap();
        assert!(
            drift.iter().any(|e| e.package == "ms" && matches!(&e.issue, DriftIssue::VersionMismatch { expected, actual } if expected == "2.1.3" && actual == "2.0.0")),
            "should detect ms version mismatch: {:?}", drift
        );
    }

    #[test]
    fn detect_drift_sentinel_missing() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lockfile_with_packages();
        // Write overrides without sentinel
        let content = serde_json::json!({"name":"app","overrides":{"ms":"2.1.3","debug":"4.4.3"}});
        std::fs::write(dir.path().join("package.json"), serde_json::to_string(&content).unwrap()).unwrap();

        let drift = OverridesManager::detect_drift(dir.path(), &lf).unwrap();
        assert!(
            drift.iter().any(|e| matches!(e.issue, DriftIssue::SentinelMissing)),
            "should detect missing sentinel: {:?}", drift
        );
    }

    #[test]
    fn detect_drift_no_overrides_block() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), r#"{"name":"app"}"#);
        let lf = lockfile_with_packages();

        let drift = OverridesManager::detect_drift(dir.path(), &lf).unwrap();
        // Sentinel missing + both transitives missing
        assert!(
            drift.iter().any(|e| matches!(e.issue, DriftIssue::SentinelMissing)),
            "should report sentinel missing when block is absent: {:?}", drift
        );
        assert_eq!(
            drift.iter().filter(|e| matches!(e.issue, DriftIssue::MissingFromOverrides { .. })).count(),
            2,
            "ms and debug should both be reported missing: {:?}", drift
        );
        assert_eq!(drift.len(), 3, "sentinel + ms + debug = 3 entries: {:?}", drift);
    }

    #[test]
    fn write_overrides_idempotent_on_vigil_managed_block() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), r#"{"name":"app"}"#);

        let overrides: BTreeMap<String, String> = [("ms".into(), "2.1.3".into())].into();
        // First write
        OverridesManager::write_overrides(dir.path(), &overrides).unwrap();
        // Second write — sentinel is present; should succeed without error
        let overrides2: BTreeMap<String, String> = [("ms".into(), "2.1.4".into())].into();
        OverridesManager::write_overrides(dir.path(), &overrides2).unwrap();

        let read_back = OverridesManager::read_overrides(dir.path()).unwrap().unwrap();
        assert_eq!(read_back["ms"], "2.1.4", "second write should update the version");
    }
}
