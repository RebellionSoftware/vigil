use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Full package document from the npm registry.
/// Fetched via `GET https://registry.npmjs.org/<name>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,

    /// e.g. `{ "latest": "4.18.2" }`
    #[serde(rename = "dist-tags", default)]
    pub dist_tags: HashMap<String, String>,

    /// Full version history: version string → metadata.
    #[serde(default)]
    pub versions: HashMap<String, VersionMetadata>,

    /// Publish timestamps: version string (and "created"/"modified") → ISO 8601.
    #[serde(default)]
    pub time: HashMap<String, String>,
}

impl PackageMetadata {
    /// Return the version string pointed to by `latest`, if present.
    pub fn latest_version(&self) -> Option<&str> {
        self.dist_tags.get("latest").map(|s| s.as_str())
    }

    /// All concrete version strings (excludes "created"/"modified" keys from the time map).
    pub fn all_versions(&self) -> Vec<&str> {
        self.versions.keys().map(|s| s.as_str()).collect()
    }
}

/// Metadata for a single version of a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMetadata {
    pub name: String,
    pub version: String,

    /// Runtime dependency ranges.
    #[serde(default)]
    pub dependencies: HashMap<String, String>,

    /// Peer dependency ranges (informational only, not installed).
    #[serde(rename = "peerDependencies", default)]
    pub peer_dependencies: HashMap<String, String>,

    /// Distribution info (tarball URL, hash).
    pub dist: DistInfo,

    /// Lifecycle scripts (look for "postinstall", "preinstall", "install").
    #[serde(default)]
    pub scripts: HashMap<String, String>,

    /// Set by npm when any install script is present.
    #[serde(rename = "hasInstallScript", default)]
    pub has_install_script: bool,

    /// Maintainer list at publish time.
    #[serde(default)]
    pub maintainers: Vec<Maintainer>,
}

impl VersionMetadata {
    /// Returns true if this version has any install lifecycle script.
    pub fn has_postinstall(&self) -> bool {
        self.has_install_script
            || self.scripts.contains_key("postinstall")
            || self.scripts.contains_key("preinstall")
            || self.scripts.contains_key("install")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistInfo {
    /// SRI hash of the tarball: "sha512-<base64>".
    pub integrity: Option<String>,

    /// Hex SHA-1 of the tarball (legacy field).
    pub shasum: String,

    /// URL to download the tarball.
    pub tarball: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Maintainer {
    pub name: String,
    pub email: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_postinstall_via_scripts_map() {
        let mut scripts = HashMap::new();
        scripts.insert("postinstall".to_string(), "node ./setup.js".to_string());
        let v = VersionMetadata {
            name: "pkg".to_string(),
            version: "1.0.0".to_string(),
            dependencies: HashMap::new(),
            peer_dependencies: HashMap::new(),
            dist: DistInfo {
                integrity: None,
                shasum: "abc".to_string(),
                tarball: "https://example.com/pkg.tgz".to_string(),
            },
            scripts,
            has_install_script: false,
            maintainers: vec![],
        };
        assert!(v.has_postinstall());
    }

    #[test]
    fn has_postinstall_via_flag() {
        let v = VersionMetadata {
            name: "pkg".to_string(),
            version: "1.0.0".to_string(),
            dependencies: HashMap::new(),
            peer_dependencies: HashMap::new(),
            dist: DistInfo {
                integrity: None,
                shasum: "abc".to_string(),
                tarball: "https://example.com/pkg.tgz".to_string(),
            },
            scripts: HashMap::new(),
            has_install_script: true,
            maintainers: vec![],
        };
        assert!(v.has_postinstall());
    }

    #[test]
    fn no_postinstall() {
        let v = VersionMetadata {
            name: "pkg".to_string(),
            version: "1.0.0".to_string(),
            dependencies: HashMap::new(),
            peer_dependencies: HashMap::new(),
            dist: DistInfo {
                integrity: None,
                shasum: "abc".to_string(),
                tarball: "https://example.com/pkg.tgz".to_string(),
            },
            scripts: HashMap::new(),
            has_install_script: false,
            maintainers: vec![],
        };
        assert!(!v.has_postinstall());
    }
}
