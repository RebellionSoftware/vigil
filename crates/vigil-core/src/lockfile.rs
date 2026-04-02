use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::Path;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::error::{Error, Result};
use crate::resolver::ResolvedTree;

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
    ///
    /// Uses a write-to-tmp-then-rename pattern so the file on disk is never
    /// in a partially-written state even if the process is killed mid-write.
    pub fn write(&mut self, project_dir: &Path) -> Result<()> {
        self.meta.updated_at = Utc::now();
        let path = project_dir.join(LOCKFILE_FILENAME);
        let tmp_path = project_dir.join(format!("{LOCKFILE_FILENAME}.tmp"));
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(&tmp_path, contents)?;
        std::fs::rename(&tmp_path, &path)?;
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

// ── Lockfile generation ───────────────────────────────────────────────────────

/// Generate a fresh `VigilLockfile` from a fully-resolved dependency tree.
///
/// `user` is the system user running the install (stored for audit trail).
/// Content hashes are taken from the registry `dist.integrity` field (Phase 1f
/// will replace these with on-disk directory hashes after Bun installs the files).
pub fn generate_from_tree(tree: &ResolvedTree, user: &str) -> VigilLockfile {
    let mut lf = VigilLockfile::new();
    let now = Utc::now();

    for node in tree.all_nodes() {
        let key = node.spec.to_key();
        let age_days = {
            let d = now.signed_duration_since(node.published_at).num_days();
            d.max(0) as u32
        };

        let content_hash = node
            .metadata
            .dist
            .integrity
            .clone()
            .unwrap_or_else(|| format!("sha1-{}", node.metadata.dist.shasum));

        let transitive_of = if node.is_direct {
            vec![]
        } else {
            direct_ancestors(tree, &key)
        };

        lf.packages.insert(
            key,
            LockedPackage {
                content_hash,
                published_at: node.published_at,
                age_at_install_days: age_days,
                direct: node.is_direct,
                transitive_of,
                postinstall_approved: false,
                installed_at: now,
                installed_by: user.to_string(),
            },
        );
    }

    lf
}

/// Merge a newly-generated lockfile into an existing one.
///
/// - New packages are added.
/// - Existing packages that disappeared from the new tree are removed.
/// - For packages in both: `postinstall_approved` is preserved from the old entry
///   (so prior approvals survive an update), but all other fields come from the new entry.
pub fn merge_into(existing: &mut VigilLockfile, fresh: VigilLockfile) {
    // Remove packages no longer in the tree.
    existing.packages.retain(|k, _| fresh.packages.contains_key(k));

    for (key, mut new_pkg) in fresh.packages {
        if let Some(old_pkg) = existing.packages.get(&key) {
            // Preserve postinstall approval across updates.
            new_pkg.postinstall_approved = old_pkg.postinstall_approved;
        }
        existing.packages.insert(key, new_pkg);
    }
}

// ── Lockfile diffing ──────────────────────────────────────────────────────────

/// The difference between two lockfile snapshots.
#[derive(Debug, Default)]
pub struct LockfileDiff {
    /// Keys present in `new` but not in `old`.
    pub added: Vec<String>,
    /// Keys present in `old` but not in `new`.
    pub removed: Vec<String>,
    /// Keys present in both but with a different content hash or version.
    pub changed: Vec<String>,
    /// Keys present in both and identical.
    pub unchanged: Vec<String>,
}

impl LockfileDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// Compute the diff between two lockfile snapshots.
pub fn diff(old: &VigilLockfile, new: &VigilLockfile) -> LockfileDiff {
    let mut result = LockfileDiff::default();

    for key in new.packages.keys() {
        if !old.packages.contains_key(key) {
            result.added.push(key.clone());
        }
    }

    for (key, old_pkg) in &old.packages {
        match new.packages.get(key) {
            None => result.removed.push(key.clone()),
            Some(new_pkg) => {
                if new_pkg.content_hash != old_pkg.content_hash {
                    result.changed.push(key.clone());
                } else {
                    result.unchanged.push(key.clone());
                }
            }
        }
    }

    result.added.sort();
    result.removed.sort();
    result.changed.sort();
    result.unchanged.sort();
    result
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// BFS upward through the dependency graph to find all direct (user-requested)
/// package names that are ancestors of `start_key`.
fn direct_ancestors(tree: &ResolvedTree, start_key: &str) -> Vec<String> {
    let mut found: HashSet<String> = HashSet::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    if let Some(node) = tree.get(start_key) {
        for dep in &node.dependents {
            queue.push_back(dep.to_key());
        }
    }

    while let Some(k) = queue.pop_front() {
        if !visited.insert(k.clone()) {
            continue;
        }
        if let Some(parent) = tree.get(&k) {
            if parent.is_direct {
                found.insert(parent.spec.name.to_string());
            } else {
                for dep in &parent.dependents {
                    queue.push_back(dep.to_key());
                }
            }
        }
    }

    let mut v: Vec<String> = found.into_iter().collect();
    v.sort();
    v
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

    // ── generate_from_tree ────────────────────────────────────────────────────

    #[allow(unused_imports)]
    fn make_tree_for_gen() -> crate::resolver::ResolvedTree {
        use crate::{
            registry::{DistInfo, VersionMetadata},
            resolver::{ResolvedNode, ResolvedTree},
            types::{ExactVersion, PackageName, PackageSpec},
        };
        use std::collections::HashMap;

        let direct_spec = PackageSpec::new(PackageName::new("express").unwrap(), ExactVersion::new("4.18.2"));
        let trans_spec  = PackageSpec::new(PackageName::new("ms").unwrap(),      ExactVersion::new("2.1.3"));

        let trans_node = ResolvedNode {
            spec: trans_spec.clone(),
            dependencies: vec![],
            dependents: vec![direct_spec.clone()],
            metadata: VersionMetadata {
                name: "ms".into(), version: "2.1.3".into(),
                dependencies: HashMap::new(), peer_dependencies: HashMap::new(),
                dist: DistInfo { integrity: Some("sha512-ms".into()), shasum: "abc".into(), tarball: "https://example.com/ms.tgz".into() },
                scripts: HashMap::new(), has_install_script: false, maintainers: vec![],
            },
            published_at: Utc::now() - chrono::Duration::days(30),
            is_direct: false,
            has_install_script: false,
        };

        let direct_node = ResolvedNode {
            spec: direct_spec.clone(),
            dependencies: vec![trans_spec.clone()],
            dependents: vec![],
            metadata: VersionMetadata {
                name: "express".into(), version: "4.18.2".into(),
                dependencies: HashMap::new(), peer_dependencies: HashMap::new(),
                dist: DistInfo { integrity: Some("sha512-express".into()), shasum: "def".into(), tarball: "https://example.com/express.tgz".into() },
                scripts: HashMap::new(), has_install_script: false, maintainers: vec![],
            },
            published_at: Utc::now() - chrono::Duration::days(100),
            is_direct: true,
            has_install_script: false,
        };

        let mut nodes = HashMap::new();
        nodes.insert(direct_spec.to_key(), direct_node);
        nodes.insert(trans_spec.to_key(), trans_node);

        ResolvedTree { nodes, direct: vec![direct_spec], warnings: vec![] }
    }

    #[test]
    fn generate_from_tree_produces_correct_entries() {
        let tree = make_tree_for_gen();
        let lf = generate_from_tree(&tree, "testuser");

        assert_eq!(lf.packages.len(), 2);

        let express = lf.packages.get("express@4.18.2").expect("express should be in lockfile");
        assert!(express.direct);
        assert!(express.transitive_of.is_empty());
        assert_eq!(express.content_hash, "sha512-express");
        assert_eq!(express.installed_by, "testuser");

        let ms = lf.packages.get("ms@2.1.3").expect("ms should be in lockfile");
        assert!(!ms.direct);
        assert_eq!(ms.transitive_of, vec!["express"]);
        assert_eq!(ms.content_hash, "sha512-ms");
    }

    #[test]
    fn generate_from_tree_round_trip() {
        let tree = make_tree_for_gen();
        let mut lf = generate_from_tree(&tree, "ci");
        let dir = tempfile::tempdir().unwrap();
        lf.write(dir.path()).unwrap();
        let read_back = VigilLockfile::read(dir.path()).unwrap();
        assert_eq!(read_back.packages.len(), 2);
        assert!(read_back.packages.get("ms@2.1.3").unwrap().transitive_of.contains(&"express".to_string()));
    }

    #[test]
    fn merge_preserves_postinstall_approval() {
        let tree = make_tree_for_gen();
        let mut existing = generate_from_tree(&tree, "user1");
        // Mark express as postinstall-approved
        existing.packages.get_mut("express@4.18.2").unwrap().postinstall_approved = true;

        let fresh = generate_from_tree(&tree, "user2");
        merge_into(&mut existing, fresh);

        // Approval should survive the merge
        assert!(existing.packages.get("express@4.18.2").unwrap().postinstall_approved);
        // installed_by should be from the fresh lockfile
        assert_eq!(existing.packages.get("express@4.18.2").unwrap().installed_by, "user2");
    }

    #[test]
    fn merge_removes_dropped_packages() {
        let tree = make_tree_for_gen();
        let mut existing = generate_from_tree(&tree, "user");
        // Add a stale package to the existing lockfile
        existing.packages.insert("stale-pkg@1.0.0".to_string(), LockedPackage {
            content_hash: "sha512-stale".into(),
            published_at: Utc::now(),
            age_at_install_days: 30,
            direct: false,
            transitive_of: vec!["express".into()],
            postinstall_approved: false,
            installed_at: Utc::now(),
            installed_by: "user".into(),
        });

        // Fresh tree doesn't include stale-pkg
        let fresh = generate_from_tree(&tree, "user");
        merge_into(&mut existing, fresh);

        assert!(!existing.packages.contains_key("stale-pkg@1.0.0"), "stale package should be removed");
        assert_eq!(existing.packages.len(), 2);
    }

    // ── diff ──────────────────────────────────────────────────────────────────

    #[test]
    fn diff_detects_added_removed_changed() {
        let mut old = VigilLockfile::new();
        old.packages.insert("a@1.0.0".into(), LockedPackage {
            content_hash: "sha512-aaa".into(), published_at: Utc::now(),
            age_at_install_days: 10, direct: true, transitive_of: vec![],
            postinstall_approved: false, installed_at: Utc::now(), installed_by: "u".into(),
        });
        old.packages.insert("b@1.0.0".into(), LockedPackage {
            content_hash: "sha512-bbb".into(), published_at: Utc::now(),
            age_at_install_days: 10, direct: false, transitive_of: vec!["a".into()],
            postinstall_approved: false, installed_at: Utc::now(), installed_by: "u".into(),
        });

        let mut new = VigilLockfile::new();
        // a stays, but hash changed
        new.packages.insert("a@1.0.0".into(), LockedPackage {
            content_hash: "sha512-aaa-new".into(), published_at: Utc::now(),
            age_at_install_days: 10, direct: true, transitive_of: vec![],
            postinstall_approved: false, installed_at: Utc::now(), installed_by: "u".into(),
        });
        // b removed
        // c added
        new.packages.insert("c@2.0.0".into(), LockedPackage {
            content_hash: "sha512-ccc".into(), published_at: Utc::now(),
            age_at_install_days: 5, direct: false, transitive_of: vec!["a".into()],
            postinstall_approved: false, installed_at: Utc::now(), installed_by: "u".into(),
        });

        let d = diff(&old, &new);
        assert_eq!(d.added, vec!["c@2.0.0"]);
        assert_eq!(d.removed, vec!["b@1.0.0"]);
        assert_eq!(d.changed, vec!["a@1.0.0"]);
        assert!(d.unchanged.is_empty());
        assert!(!d.is_empty());
    }

    #[test]
    fn diff_identical_lockfiles_is_empty() {
        let tree = make_tree_for_gen();
        let lf = generate_from_tree(&tree, "u");
        let d = diff(&lf, &lf);
        assert!(d.is_empty());
    }

    // ── direct_ancestors edge cases ───────────────────────────────────────────

    /// Build a 3-hop chain: express (direct) → debug (trans) → ms (trans)
    #[allow(unused_imports)]
    fn make_deep_tree() -> crate::resolver::ResolvedTree {
        use crate::{
            registry::{DistInfo, VersionMetadata},
            resolver::{ResolvedNode, ResolvedTree},
            types::{ExactVersion, PackageName, PackageSpec},
        };
        use std::collections::HashMap;

        let express_spec = PackageSpec::new(PackageName::new("express").unwrap(), ExactVersion::new("4.18.2"));
        let debug_spec   = PackageSpec::new(PackageName::new("debug").unwrap(),   ExactVersion::new("4.4.3"));
        let ms_spec      = PackageSpec::new(PackageName::new("ms").unwrap(),      ExactVersion::new("2.1.3"));

        let make_meta = |name: &str, ver: &str, hash: &str| VersionMetadata {
            name: name.into(), version: ver.into(),
            dependencies: HashMap::new(), peer_dependencies: HashMap::new(),
            dist: DistInfo { integrity: Some(hash.into()), shasum: "x".into(), tarball: "https://x".into() },
            scripts: HashMap::new(), has_install_script: false, maintainers: vec![],
        };

        let ms_node = ResolvedNode {
            spec: ms_spec.clone(),
            dependencies: vec![],
            dependents: vec![debug_spec.clone()],   // parent is debug (not direct)
            metadata: make_meta("ms", "2.1.3", "sha512-ms"),
            published_at: Utc::now() - chrono::Duration::days(30),
            is_direct: false, has_install_script: false,
        };
        let debug_node = ResolvedNode {
            spec: debug_spec.clone(),
            dependencies: vec![ms_spec.clone()],
            dependents: vec![express_spec.clone()], // parent is express (direct)
            metadata: make_meta("debug", "4.4.3", "sha512-debug"),
            published_at: Utc::now() - chrono::Duration::days(30),
            is_direct: false, has_install_script: false,
        };
        let express_node = ResolvedNode {
            spec: express_spec.clone(),
            dependencies: vec![debug_spec.clone()],
            dependents: vec![],
            metadata: make_meta("express", "4.18.2", "sha512-express"),
            published_at: Utc::now() - chrono::Duration::days(100),
            is_direct: true, has_install_script: false,
        };

        let mut nodes = HashMap::new();
        nodes.insert(express_spec.to_key(), express_node);
        nodes.insert(debug_spec.to_key(), debug_node);
        nodes.insert(ms_spec.to_key(), ms_node);

        ResolvedTree { nodes, direct: vec![express_spec], warnings: vec![] }
    }

    #[test]
    fn deep_transitive_chain_traced_to_direct_root() {
        let tree = make_deep_tree();
        let lf = generate_from_tree(&tree, "u");

        let ms = lf.packages.get("ms@2.1.3").expect("ms should be in lockfile");
        assert!(!ms.direct);
        assert_eq!(ms.transitive_of, vec!["express"],
            "ms (3 hops from root) should trace back to express: {:?}", ms.transitive_of);

        let debug = lf.packages.get("debug@4.4.3").expect("debug should be in lockfile");
        assert!(!debug.direct);
        assert_eq!(debug.transitive_of, vec!["express"],
            "debug should trace back to express: {:?}", debug.transitive_of);
    }

    /// Diamond: two directs (A, B) share one transitive (C).
    #[allow(unused_imports)]
    fn make_diamond_tree() -> crate::resolver::ResolvedTree {
        use crate::{
            registry::{DistInfo, VersionMetadata},
            resolver::{ResolvedNode, ResolvedTree},
            types::{ExactVersion, PackageName, PackageSpec},
        };
        use std::collections::HashMap;

        let a_spec = PackageSpec::new(PackageName::new("pkg-a").unwrap(), ExactVersion::new("1.0.0"));
        let b_spec = PackageSpec::new(PackageName::new("pkg-b").unwrap(), ExactVersion::new("1.0.0"));
        let c_spec = PackageSpec::new(PackageName::new("pkg-c").unwrap(), ExactVersion::new("1.0.0"));

        let make_meta = |name: &str| VersionMetadata {
            name: name.into(), version: "1.0.0".into(),
            dependencies: HashMap::new(), peer_dependencies: HashMap::new(),
            dist: DistInfo { integrity: Some(format!("sha512-{name}")), shasum: "x".into(), tarball: "https://x".into() },
            scripts: HashMap::new(), has_install_script: false, maintainers: vec![],
        };

        let c_node = ResolvedNode {
            spec: c_spec.clone(),
            dependencies: vec![],
            dependents: vec![a_spec.clone(), b_spec.clone()],  // two direct parents
            metadata: make_meta("pkg-c"),
            published_at: Utc::now() - chrono::Duration::days(30),
            is_direct: false, has_install_script: false,
        };
        let a_node = ResolvedNode {
            spec: a_spec.clone(), dependencies: vec![c_spec.clone()], dependents: vec![],
            metadata: make_meta("pkg-a"),
            published_at: Utc::now() - chrono::Duration::days(50),
            is_direct: true, has_install_script: false,
        };
        let b_node = ResolvedNode {
            spec: b_spec.clone(), dependencies: vec![c_spec.clone()], dependents: vec![],
            metadata: make_meta("pkg-b"),
            published_at: Utc::now() - chrono::Duration::days(50),
            is_direct: true, has_install_script: false,
        };

        let mut nodes = HashMap::new();
        nodes.insert(a_spec.to_key(), a_node);
        nodes.insert(b_spec.to_key(), b_node);
        nodes.insert(c_spec.to_key(), c_node);

        ResolvedTree { nodes, direct: vec![a_spec, b_spec], warnings: vec![] }
    }

    #[test]
    fn diamond_transitive_lists_both_direct_owners() {
        let tree = make_diamond_tree();
        let lf = generate_from_tree(&tree, "u");

        let c = lf.packages.get("pkg-c@1.0.0").expect("pkg-c should be in lockfile");
        assert!(!c.direct);
        let mut owners = c.transitive_of.clone();
        owners.sort();
        assert_eq!(owners, vec!["pkg-a", "pkg-b"],
            "pkg-c should list both direct owners: {:?}", owners);
    }
}
