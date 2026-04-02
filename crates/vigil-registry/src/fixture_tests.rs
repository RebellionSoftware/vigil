#[cfg(test)]
mod fixture_tests {
    use crate::{MockRegistryClient, RegistryClient};
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
    }

    fn fixture_exists(name: &str) -> bool {
        fixtures_dir().join(format!("{name}.json")).exists()
    }

    #[tokio::test]
    async fn ms_fixture_loads_and_parses() {
        if !fixture_exists("ms") {
            eprintln!("Skipping: tests/fixtures/ms.json not found");
            return;
        }
        let mut client = MockRegistryClient::new();
        client.add_fixture(&fixtures_dir(), "ms").unwrap();
        let meta = client.get_package_metadata("ms").await.unwrap();
        assert_eq!(meta.name, "ms");
        assert!(meta.latest_version().is_some());
        assert!(!meta.time.is_empty());
        assert!(!meta.versions.is_empty());
    }

    #[tokio::test]
    async fn follow_redirects_fixture_loads_and_parses() {
        if !fixture_exists("follow-redirects") {
            eprintln!("Skipping: tests/fixtures/follow-redirects.json not found");
            return;
        }
        let mut client = MockRegistryClient::new();
        client.add_fixture(&fixtures_dir(), "follow-redirects").unwrap();
        let meta = client.get_package_metadata("follow-redirects").await.unwrap();
        assert_eq!(meta.name, "follow-redirects");
        assert!(meta.latest_version().is_some());
    }

    #[tokio::test]
    async fn has_flag_fixture_loads_and_parses() {
        if !fixture_exists("has-flag") {
            eprintln!("Skipping: tests/fixtures/has-flag.json not found");
            return;
        }
        let mut client = MockRegistryClient::new();
        client.add_fixture(&fixtures_dir(), "has-flag").unwrap();
        let meta = client.get_package_metadata("has-flag").await.unwrap();
        assert_eq!(meta.name, "has-flag");
    }

    #[tokio::test]
    async fn debug_fixture_has_ms_dependency() {
        if !fixture_exists("debug") {
            eprintln!("Skipping: tests/fixtures/debug.json not found");
            return;
        }
        let mut client = MockRegistryClient::new();
        client.add_fixture(&fixtures_dir(), "debug").unwrap();
        let meta = client.get_package_metadata("debug").await.unwrap();
        assert_eq!(meta.name, "debug");
        let latest = meta.latest_version().unwrap();
        let vm = meta.versions.get(latest).unwrap();
        assert!(
            vm.dependencies.contains_key("ms"),
            "debug@{latest} should depend on ms, got deps: {:?}", vm.dependencies.keys().collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn ms_fixture_has_stable_versions() {
        if !fixture_exists("ms") {
            eprintln!("Skipping: tests/fixtures/ms.json not found");
            return;
        }
        let mut client = MockRegistryClient::new();
        client.add_fixture(&fixtures_dir(), "ms").unwrap();
        let meta = client.get_package_metadata("ms").await.unwrap();
        let latest = meta.latest_version().unwrap();
        // latest should be in the versions map (pre-release-only capture was a bug)
        assert!(
            meta.versions.contains_key(latest),
            "ms latest ({latest}) should be in versions map"
        );
    }

    #[tokio::test]
    async fn esbuild_has_postinstall() {
        if !fixture_exists("esbuild") {
            eprintln!("Skipping: tests/fixtures/esbuild.json not found");
            return;
        }
        let mut client = MockRegistryClient::new();
        client.add_fixture(&fixtures_dir(), "esbuild").unwrap();
        let meta = client.get_package_metadata("esbuild").await.unwrap();
        let latest = meta.latest_version().unwrap();
        let vm = meta.versions.get(latest).unwrap();
        assert!(vm.has_postinstall(), "esbuild should have a postinstall script");
    }
}
