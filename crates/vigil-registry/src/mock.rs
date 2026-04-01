use std::collections::HashMap;
use async_trait::async_trait;
use vigil_core::registry::{
    DistInfo, PackageMetadata, RegistryClient, RegistryError, RegistryResult, VersionMetadata,
};

/// A registry client backed by in-memory fixture data.
/// Used in tests to avoid network access.
pub struct MockRegistryClient {
    packages: HashMap<String, PackageMetadata>,
}

impl MockRegistryClient {
    pub fn new() -> Self {
        MockRegistryClient {
            packages: HashMap::new(),
        }
    }

    pub fn add(&mut self, name: impl Into<String>, metadata: PackageMetadata) -> &mut Self {
        self.packages.insert(name.into(), metadata);
        self
    }

    pub fn add_from_file(&mut self, path: &std::path::Path) -> RegistryResult<&mut Self> {
        let content = std::fs::read_to_string(path).map_err(|e| RegistryError::ParseError {
            package: path.display().to_string(),
            reason: e.to_string(),
        })?;
        let metadata: PackageMetadata =
            serde_json::from_str(&content).map_err(|e| RegistryError::ParseError {
                package: path.display().to_string(),
                reason: e.to_string(),
            })?;
        self.packages.insert(metadata.name.clone(), metadata);
        Ok(self)
    }

    pub fn add_fixture(
        &mut self,
        fixtures_dir: &std::path::Path,
        package_name: &str,
    ) -> RegistryResult<&mut Self> {
        let filename = package_name.replace('/', "__").replace('@', "");
        let filename = if package_name.starts_with('@') {
            format!("@{filename}.json")
        } else {
            format!("{filename}.json")
        };
        self.add_from_file(&fixtures_dir.join(filename))
    }
}

impl Default for MockRegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RegistryClient for MockRegistryClient {
    async fn get_package_metadata(&self, name: &str) -> RegistryResult<PackageMetadata> {
        self.packages
            .get(name)
            .cloned()
            .ok_or_else(|| RegistryError::PackageNotFound(name.to_string()))
    }
}

/// Builder for constructing PackageMetadata in tests.
pub struct PackageMetadataBuilder {
    name: String,
    entries: Vec<(String, String)>, // (published_at, version)
    latest: Option<String>,
    deps_by_version: HashMap<String, HashMap<String, String>>,
    scripts_by_version: HashMap<String, HashMap<String, String>>,
    has_install_script_by_version: HashMap<String, bool>,
}

impl PackageMetadataBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        PackageMetadataBuilder {
            name: name.into(),
            entries: vec![],
            latest: None,
            deps_by_version: HashMap::new(),
            scripts_by_version: HashMap::new(),
            has_install_script_by_version: HashMap::new(),
        }
    }

    pub fn version(mut self, version: impl Into<String>, published_at: impl Into<String>) -> Self {
        self.entries.push((published_at.into(), version.into()));
        self
    }

    pub fn with_deps(mut self, version: impl Into<String>, deps: &[(&str, &str)]) -> Self {
        let v = version.into();
        self.deps_by_version.insert(
            v,
            deps.iter().map(|(n, r)| (n.to_string(), r.to_string())).collect(),
        );
        self
    }

    pub fn with_postinstall(mut self, version: impl Into<String>) -> Self {
        let v = version.into();
        let mut scripts = HashMap::new();
        scripts.insert("postinstall".to_string(), "node ./setup.js".to_string());
        self.scripts_by_version.insert(v, scripts);
        self
    }

    pub fn latest(mut self, version: impl Into<String>) -> Self {
        self.latest = Some(version.into());
        self
    }

    pub fn build(self) -> PackageMetadata {
        let mut versions = HashMap::new();
        let mut time = HashMap::new();

        for (published_at, ver) in &self.entries {
            time.insert(ver.clone(), published_at.clone());
            let deps = self.deps_by_version.get(ver).cloned().unwrap_or_default();
            let scripts = self.scripts_by_version.get(ver).cloned().unwrap_or_default();
            let has_install = *self.has_install_script_by_version.get(ver).unwrap_or(&false)
                || scripts.contains_key("postinstall")
                || scripts.contains_key("preinstall");
            let meta = VersionMetadata {
                name: self.name.clone(),
                version: ver.clone(),
                dependencies: deps,
                peer_dependencies: HashMap::new(),
                dist: DistInfo {
                    integrity: Some(format!("sha512-fake-{ver}")),
                    shasum: format!("fake-{ver}"),
                    tarball: format!("https://registry.npmjs.org/{}/-/{}-{}.tgz", self.name, self.name, ver),
                },
                scripts,
                has_install_script: has_install,
                maintainers: vec![],
            };
            versions.insert(ver.clone(), meta);
        }

        let latest = self.latest
            .or_else(|| self.entries.last().map(|(_, v)| v.clone()))
            .unwrap_or_default();

        let mut dist_tags = HashMap::new();
        dist_tags.insert("latest".to_string(), latest);

        PackageMetadata {
            name: self.name,
            dist_tags,
            versions,
            time,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_client_returns_registered_package() {
        let mut client = MockRegistryClient::new();
        let metadata = PackageMetadataBuilder::new("ms")
            .version("2.1.3", "2021-01-01T00:00:00Z")
            .latest("2.1.3")
            .build();
        client.add("ms", metadata);

        let result = client.get_package_metadata("ms").await.unwrap();
        assert_eq!(result.name, "ms");
        assert_eq!(result.latest_version(), Some("2.1.3"));
    }

    #[tokio::test]
    async fn mock_client_errors_for_unknown_package() {
        let client = MockRegistryClient::new();
        let result = client.get_package_metadata("does-not-exist").await;
        assert!(matches!(result, Err(RegistryError::PackageNotFound(_))));
    }

    #[test]
    fn builder_sets_time_map() {
        let metadata = PackageMetadataBuilder::new("pkg")
            .version("1.0.0", "2022-06-01T00:00:00Z")
            .version("1.1.0", "2023-01-15T00:00:00Z")
            .latest("1.1.0")
            .build();

        assert_eq!(metadata.time.get("1.0.0").unwrap(), "2022-06-01T00:00:00Z");
        assert_eq!(metadata.time.get("1.1.0").unwrap(), "2023-01-15T00:00:00Z");
        assert_eq!(metadata.latest_version(), Some("1.1.0"));
    }
}
