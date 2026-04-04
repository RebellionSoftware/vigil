use std::collections::{HashMap, HashSet, VecDeque};
use chrono::{DateTime, Utc};
use crate::{
    config::PolicyConfig,
    registry::{PackageMetadata, RegistryClient, RegistryError, VersionMetadata},
    semver_resolve::resolve_version,
    types::{ExactVersion, PackageName, PackageSpec},
    error::Result,
};

/// The fully-resolved dependency graph for one or more root packages.
#[derive(Debug)]
pub struct ResolvedTree {
    /// All nodes in the graph, keyed by `name@version`.
    pub nodes: HashMap<String, ResolvedNode>,
    /// The specs of direct (user-requested) packages.
    pub direct: Vec<PackageSpec>,
    /// Non-fatal warnings produced during resolution (e.g. version conflicts).
    pub warnings: Vec<String>,
}

impl ResolvedTree {
    /// Iterate over all nodes.
    pub fn all_nodes(&self) -> impl Iterator<Item = &ResolvedNode> {
        self.nodes.values()
    }

    /// Look up a node by `name@version` key.
    pub fn get(&self, key: &str) -> Option<&ResolvedNode> {
        self.nodes.get(key)
    }

    /// All direct nodes.
    pub fn direct_nodes(&self) -> Vec<&ResolvedNode> {
        self.direct
            .iter()
            .filter_map(|s| self.nodes.get(&s.to_key()))
            .collect()
    }
}

/// A single resolved package in the dependency graph.
#[derive(Debug, Clone)]
pub struct ResolvedNode {
    pub spec: PackageSpec,
    /// Resolved specs of this package's own dependencies.
    pub dependencies: Vec<PackageSpec>,
    /// Specs of packages that depend on this one (reverse edges).
    pub dependents: Vec<PackageSpec>,
    /// Registry metadata for this exact version.
    pub metadata: VersionMetadata,
    /// When this version was published to npm.
    pub published_at: DateTime<Utc>,
    pub is_direct: bool,
    pub has_install_script: bool,
    /// Number of days between the previously published version and this one.
    /// `None` means this is the first version ever published (no prior publish to compare).
    pub days_since_prior_publish: Option<i64>,
}

/// Resolves a set of package specifiers to a complete, flat dependency graph.
pub struct DependencyResolver<R: RegistryClient> {
    client: R,
    config: PolicyConfig,
    /// In-memory cache: package name → full metadata (all versions).
    cache: HashMap<String, PackageMetadata>,
}

impl<R: RegistryClient> DependencyResolver<R> {
    pub fn new(client: R, config: PolicyConfig) -> Self {
        DependencyResolver {
            client,
            config,
            cache: HashMap::new(),
        }
    }

    /// Resolve a slice of package specifiers (e.g. `["axios", "express@4"]`) to a full tree.
    ///
    /// Each specifier may be:
    /// - A bare name (`"axios"`) → resolves `latest`
    /// - `name@range` (`"axios@^1.0.0"`) → resolves the range
    /// - `name@exact` (`"axios@1.7.4"`) → pinned exact version
    pub async fn resolve(&mut self, packages: &[&str]) -> Result<ResolvedTree> {
        let mut nodes: HashMap<String, ResolvedNode> = HashMap::new();
        let mut warnings: Vec<String> = Vec::new();
        // visited tracks package *names* (not name@version) to enforce one version per name
        let mut visited: HashSet<String> = HashSet::new();

        // queue entries: (spec_string, is_direct, dependent_spec_key)
        let mut queue: VecDeque<(String, bool, Option<String>)> = VecDeque::new();

        // Seed the queue with the user's requested packages
        let mut direct_specs: Vec<PackageSpec> = Vec::new();
        for &pkg_str in packages {
            queue.push_back((pkg_str.to_string(), true, None));
        }

        while let Some((spec_str, is_direct, dependent_key)) = queue.pop_front() {
            // Parse "name@range" or bare "name"
            let (name, range) = split_spec(&spec_str);

            // If we've already resolved this package name, just add the reverse edge
            if visited.contains(&name) {
                if let Some(dep_key) = &dependent_key {
                    // Find the existing node for this name and add the reverse edge
                    if let Some(existing_key) = find_by_name(&nodes, &name) {
                        let dep_spec = PackageSpec::parse(dep_key)
                            .map_err(|e| crate::error::Error::InvalidPackageSpec(e.to_string()))?;
                        if let Some(node) = nodes.get_mut(&existing_key) {
                            node.dependents.push(dep_spec);
                        }
                    }
                }
                continue;
            }

            // Snapshot config field before the mutable borrow of self for fetch
            let allow_prerelease = self.config.allow_prerelease;

            // Fetch metadata (from cache or registry)
            let metadata = self.fetch_metadata(&name).await
                .map_err(|e| crate::error::Error::InvalidPackageName(e.to_string()))?;

            // Resolve the range to an exact version
            let all_versions: Vec<&str> = metadata.all_versions();
            let exact_version = resolve_version(
                &range,
                &all_versions,
                allow_prerelease,
            ).map_err(|e| match e {
                RegistryError::NoMatchingVersion { range, .. } => {
                    crate::error::Error::InvalidPackageSpec(
                        format!("No version matching '{range}' for package '{name}'")
                    )
                }
                other => crate::error::Error::InvalidPackageSpec(other.to_string()),
            })?;

            // Mark visited before recursing to handle cycles
            visited.insert(name.clone());

            let version_meta = metadata.versions.get(&exact_version).cloned()
                .ok_or_else(|| crate::error::Error::InvalidPackageSpec(
                    format!("Version '{exact_version}' missing from metadata for '{name}'")
                ))?;

            // Parse published_at from the time map
            let published_at = parse_published_at(&metadata, &exact_version);
            let days_since_prior_publish = compute_days_since_prior_publish(&metadata, &exact_version);

            let spec = PackageSpec::new(
                PackageName::new(&name)
                    .map_err(|e| crate::error::Error::InvalidPackageName(e.to_string()))?,
                ExactVersion::new(&exact_version),
            );
            let node_key = spec.to_key();

            if is_direct {
                direct_specs.push(spec.clone());
            }

            // Build the initial node (dependents populated as we process children)
            let has_install_script = version_meta.has_postinstall();
            let dep_names: Vec<(String, String)> = version_meta
                .dependencies
                .iter()
                .map(|(n, r)| (n.clone(), r.clone()))
                .collect();

            // Add this node to the graph (no resolved dep specs yet — filled below)
            nodes.insert(node_key.clone(), ResolvedNode {
                spec: spec.clone(),
                dependencies: vec![],
                dependents: match &dependent_key {
                    Some(dk) => {
                        if let Ok(ds) = PackageSpec::parse(dk) { vec![ds] } else { vec![] }
                    }
                    None => vec![],
                },
                metadata: version_meta,
                published_at,
                is_direct,
                has_install_script,
                days_since_prior_publish,
            });

            // Enqueue all transitive dependencies
            for (dep_name, dep_range) in dep_names {
                let dep_spec_str = format!("{dep_name}@{dep_range}");
                queue.push_back((dep_spec_str, false, Some(node_key.clone())));
            }
        }

        // Second pass: fill in resolved dependency specs on each node
        // (We need all nodes in the map first before we can reference them)
        let name_to_key: HashMap<String, String> = nodes
            .values()
            .map(|n| (n.spec.name.to_string(), n.spec.to_key()))
            .collect();

        for node in nodes.values_mut() {
            let dep_names: Vec<String> = node.metadata.dependencies.keys().cloned().collect();
            let mut resolved_deps = Vec::new();
            for dep_name in dep_names {
                if let Some(key) = name_to_key.get(&dep_name) {
                    if let Ok(spec) = PackageSpec::parse(key) {
                        resolved_deps.push(spec);
                    }
                } else {
                    warnings.push(format!(
                        "Dependency '{}' of '{}' could not be resolved (missing from graph)",
                        dep_name,
                        node.spec.to_key()
                    ));
                }
            }
            node.dependencies = resolved_deps;
        }

        Ok(ResolvedTree { nodes, direct: direct_specs, warnings })
    }

    /// Fetch package metadata, using the in-memory cache.
    async fn fetch_metadata(&mut self, name: &str) -> std::result::Result<&PackageMetadata, RegistryError> {
        if !self.cache.contains_key(name) {
            let meta = self.client.get_package_metadata(name).await?;
            self.cache.insert(name.to_string(), meta);
        }
        Ok(self.cache.get(name).unwrap())
    }

    /// Return how many registry fetches were made (cache misses).
    pub fn fetch_count(&self) -> usize {
        self.cache.len()
    }
}

/// Split "name@range" into (name, range). Handles scoped packages.
fn split_spec(spec: &str) -> (String, String) {
    if spec.starts_with('@') {
        // Scoped: @scope/name or @scope/name@range
        // Find the '@' that separates name from version (after the first '/')
        if let Some(slash_pos) = spec.find('/') {
            let after_slash = &spec[slash_pos + 1..];
            if let Some(at_pos) = after_slash.find('@') {
                let name = spec[..slash_pos + 1 + at_pos].to_string();
                let range = after_slash[at_pos + 1..].to_string();
                return (name, range);
            }
        }
        // No version part
        (spec.to_string(), "latest".to_string())
    } else {
        match spec.rsplit_once('@') {
            Some((name, range)) => (name.to_string(), range.to_string()),
            None => (spec.to_string(), "latest".to_string()),
        }
    }
}

/// Find the map key for a package by its name (ignoring version).
fn find_by_name(nodes: &HashMap<String, ResolvedNode>, name: &str) -> Option<String> {
    let prefix = format!("{name}@");
    nodes.keys()
        .find(|k| k.starts_with(&prefix))
        .cloned()
}

/// Parse the published_at timestamp from the package metadata time map.
fn parse_published_at(metadata: &PackageMetadata, version: &str) -> DateTime<Utc> {
    metadata.time
        .get(version)
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .unwrap_or(DateTime::UNIX_EPOCH)
}

/// Compute how many days elapsed between the most recent prior version publish and this one.
///
/// Returns:
/// - `None`          — no prior version keys exist in the time map; genuinely first-ever publish
/// - `Some(i64::MAX)` — prior version keys exist but no valid, pre-current timestamps could be
///                      parsed (malformed data or timestamp manipulation); treat as maximally
///                      suspicious in the velocity check
/// - `Some(days)`    — the gap in days between the most recent prior publish and this one
fn compute_days_since_prior_publish(metadata: &PackageMetadata, version: &str) -> Option<i64> {
    let this_ts = metadata.time.get(version)?.parse::<DateTime<Utc>>().ok()?;

    // npm metadata keys that are not version publish events.
    let is_meta_key = |k: &str| matches!(k, "created" | "modified" | "unpublished");

    // Count prior version entries before filtering so we can distinguish
    // "no prior versions" (first publish) from "prior versions exist but unreadable"
    // (data integrity failure).
    let prior_key_count = metadata.time.keys()
        .filter(|k| !is_meta_key(k) && k.as_str() != version)
        .count();

    if prior_key_count == 0 {
        return None; // genuinely first-ever publish
    }

    // Parse timestamps for prior versions that predate this version.
    let mut prior_timestamps: Vec<DateTime<Utc>> = metadata.time.iter()
        .filter(|(k, _)| !is_meta_key(k) && k.as_str() != version)
        .filter_map(|(_, v)| v.parse::<DateTime<Utc>>().ok())
        .filter(|ts| *ts < this_ts)
        .collect();

    if prior_timestamps.is_empty() {
        // Prior version entries exist but none produced a valid, pre-current timestamp.
        // This indicates malformed registry data or deliberate timestamp manipulation
        // (e.g. future-dating prior versions to hide a dormancy gap).
        // Return i64::MAX so the velocity check treats this as maximally suspicious.
        return Some(i64::MAX);
    }

    prior_timestamps.sort();
    let prior_ts = prior_timestamps.last()?;
    let gap_days = (this_ts - *prior_ts).num_days();

    // A negative gap means a prior-version timestamp is in the future relative to the
    // current version's own timestamp — should not occur under normal conditions.
    // Treat as suspicious data rather than silently passing.
    if gap_days < 0 {
        return Some(i64::MAX);
    }

    Some(gap_days)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::PolicyConfig, registry::{DistInfo, RegistryClient, RegistryError, VersionMetadata}};
    use std::collections::HashMap;
    use async_trait::async_trait;

    fn test_config() -> PolicyConfig {
        PolicyConfig::default()
    }

    // ----- self-contained mock (avoids vigil-registry circular dev-dep) -----

    struct TestRegistry {
        packages: HashMap<String, PackageMetadata>,
        fetch_counts: std::sync::Arc<std::sync::Mutex<HashMap<String, usize>>>,
    }

    impl TestRegistry {
        fn new() -> Self {
            TestRegistry {
                packages: HashMap::new(),
                fetch_counts: Default::default(),
            }
        }

        fn add(&mut self, name: &str, version: &str, published: &str, deps: &[(&str, &str)]) {
            let vm = make_version(name, version, deps);
            let entry = self.packages.entry(name.to_string()).or_insert_with(|| PackageMetadata {
                name: name.to_string(),
                dist_tags: [("latest".to_string(), version.to_string())].into_iter().collect(),
                versions: HashMap::new(),
                time: HashMap::new(),
            });
            // Always update latest to the most recently added version
            entry.dist_tags.insert("latest".to_string(), version.to_string());
            entry.time.insert(version.to_string(), published.to_string());
            entry.versions.insert(version.to_string(), vm);
        }

        #[allow(dead_code)]
        fn total_fetches(&self) -> usize {
            self.fetch_counts.lock().unwrap().values().sum()
        }
    }

    #[async_trait]
    impl RegistryClient for TestRegistry {
        async fn get_package_metadata(&self, name: &str) -> crate::registry::RegistryResult<PackageMetadata> {
            *self.fetch_counts.lock().unwrap().entry(name.to_string()).or_insert(0) += 1;
            self.packages
                .get(name)
                .cloned()
                .ok_or_else(|| RegistryError::PackageNotFound(name.to_string()))
        }
    }

    fn make_version(name: &str, version: &str, deps: &[(&str, &str)]) -> VersionMetadata {
        VersionMetadata {
            name: name.to_string(),
            version: version.to_string(),
            dependencies: deps.iter().map(|(n, r)| (n.to_string(), r.to_string())).collect(),
            peer_dependencies: HashMap::new(),
            dist: DistInfo {
                integrity: Some(format!("sha512-fake-{version}")),
                shasum: "fake".to_string(),
                tarball: format!("https://example.com/{name}-{version}.tgz"),
            },
            scripts: HashMap::new(),
            has_install_script: false,
            maintainers: vec![],
        }
    }

    // ----- tests -----

    #[tokio::test]
    async fn single_package_no_deps() {
        let mut reg = TestRegistry::new();
        reg.add("ms", "2.1.3", "2021-01-01T00:00:00Z", &[]);

        let mut resolver = DependencyResolver::new(reg, test_config());
        let tree = resolver.resolve(&["ms"]).await.unwrap();

        assert_eq!(tree.nodes.len(), 1);
        assert!(tree.nodes.contains_key("ms@2.1.3"));
        assert_eq!(tree.direct.len(), 1);
        assert_eq!(tree.direct[0].to_key(), "ms@2.1.3");
        assert!(tree.warnings.is_empty());
    }

    #[tokio::test]
    async fn package_with_one_transitive() {
        let mut reg = TestRegistry::new();
        reg.add("ms", "2.1.3", "2021-01-01T00:00:00Z", &[]);
        reg.add("debug", "4.3.4", "2022-01-01T00:00:00Z", &[("ms", "^2.0.0")]);

        let mut resolver = DependencyResolver::new(reg, test_config());
        let tree = resolver.resolve(&["debug"]).await.unwrap();

        assert_eq!(tree.nodes.len(), 2);
        assert!(tree.nodes.contains_key("debug@4.3.4"));
        assert!(tree.nodes.contains_key("ms@2.1.3"));

        let debug_node = tree.nodes.get("debug@4.3.4").unwrap();
        assert!(debug_node.is_direct);
        assert_eq!(debug_node.dependencies.len(), 1);

        let ms_node = tree.nodes.get("ms@2.1.3").unwrap();
        assert!(!ms_node.is_direct);
        assert_eq!(ms_node.dependents.len(), 1);
        assert_eq!(ms_node.dependents[0].to_key(), "debug@4.3.4");
    }

    #[tokio::test]
    async fn diamond_dependency() {
        let mut reg = TestRegistry::new();
        reg.add("d", "1.0.0", "2020-01-01T00:00:00Z", &[]);
        reg.add("b", "1.0.0", "2020-06-01T00:00:00Z", &[("d", "^1.0.0")]);
        reg.add("c", "1.0.0", "2020-06-01T00:00:00Z", &[("d", "^1.0.0")]);
        reg.add("a", "1.0.0", "2021-01-01T00:00:00Z", &[("b", "^1.0.0"), ("c", "^1.0.0")]);

        let mut resolver = DependencyResolver::new(reg, test_config());
        let tree = resolver.resolve(&["a"]).await.unwrap();

        assert_eq!(tree.nodes.len(), 4, "nodes: {:?}", tree.nodes.keys().collect::<Vec<_>>());
        let d_node = tree.nodes.get("d@1.0.0").unwrap();
        assert_eq!(d_node.dependents.len(), 2, "d should have 2 dependents");
    }

    #[tokio::test]
    async fn cycle_does_not_infinite_loop() {
        let mut reg = TestRegistry::new();
        reg.add("a", "1.0.0", "2020-01-01T00:00:00Z", &[("b", "^1.0.0")]);
        reg.add("b", "1.0.0", "2020-01-01T00:00:00Z", &[("a", "^1.0.0")]);

        let mut resolver = DependencyResolver::new(reg, test_config());
        let tree = resolver.resolve(&["a"]).await.unwrap();
        assert_eq!(tree.nodes.len(), 2);
    }

    #[tokio::test]
    async fn cache_prevents_duplicate_fetches() {
        let mut reg = TestRegistry::new();
        reg.add("d", "1.0.0", "2020-01-01T00:00:00Z", &[]);
        reg.add("b", "1.0.0", "2020-06-01T00:00:00Z", &[("d", "^1.0.0")]);
        reg.add("c", "1.0.0", "2020-06-01T00:00:00Z", &[("d", "^1.0.0")]);
        reg.add("a", "1.0.0", "2021-01-01T00:00:00Z", &[("b", "^1.0.0"), ("c", "^1.0.0")]);

        let mut resolver = DependencyResolver::new(reg, test_config());
        resolver.resolve(&["a"]).await.unwrap();
        // 4 unique package names → 4 fetches regardless of how many references
        assert_eq!(resolver.fetch_count(), 4);
    }

    #[tokio::test]
    async fn version_range_resolved_to_highest() {
        let mut reg = TestRegistry::new();
        // Add ms with multiple versions manually
        let entry = reg.packages.entry("ms".to_string()).or_insert_with(|| PackageMetadata {
            name: "ms".to_string(),
            dist_tags: [("latest".to_string(), "2.1.3".to_string())].into_iter().collect(),
            versions: HashMap::new(),
            time: HashMap::new(),
        });
        for (v, t) in &[("2.0.0", "2019-01-01T00:00:00Z"), ("2.1.0", "2020-01-01T00:00:00Z"), ("2.1.3", "2021-01-01T00:00:00Z")] {
            entry.versions.insert(v.to_string(), make_version("ms", v, &[]));
            entry.time.insert(v.to_string(), t.to_string());
        }
        reg.add("debug", "4.3.4", "2022-01-01T00:00:00Z", &[("ms", "^2.0.0")]);

        let mut resolver = DependencyResolver::new(reg, test_config());
        let tree = resolver.resolve(&["debug"]).await.unwrap();

        // ^2.0.0 should resolve to 2.1.3
        assert!(tree.nodes.contains_key("ms@2.1.3"), "nodes: {:?}", tree.nodes.keys().collect::<Vec<_>>());
    }
}
