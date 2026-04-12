use async_trait::async_trait;
use std::path::Path;

use crate::{
    bun::BunRunner,
    error::{Error, Result},
    types::PackageSpec,
};

/// Abstraction over package manager subprocess runners.
///
/// Implemented by [`BunRunner`] and (in a later task) `NpmRunner`.
/// CLI commands receive a `Box<dyn PackageRunner>` from [`RunnerFactory`]
/// and call this trait — they never import a concrete runner type directly.
#[async_trait]
pub trait PackageRunner: Send + Sync + std::fmt::Debug {
    /// The name of the underlying package manager (e.g. `"bun"`, `"npm"`).
    fn package_manager(&self) -> &str;

    /// Run the equivalent of `bun add --exact` / `npm install --save-exact`.
    ///
    /// `dev` and `optional` are mutually exclusive. `ignore_scripts` suppresses
    /// lifecycle script execution when `block_postinstall` is enabled.
    async fn add(
        &self,
        packages: &[PackageSpec],
        dev: bool,
        optional: bool,
        ignore_scripts: bool,
    ) -> Result<()>;

    /// Run the equivalent of `bun remove` / `npm uninstall`.
    async fn remove(&self, package_names: &[&str]) -> Result<()>;

    /// Run a bare install from the existing manifest and lockfile
    /// (`bun install` / `npm install`).
    async fn install(&self, ignore_scripts: bool) -> Result<()>;

    /// Scaffold a new project interactively (`bun init` / `npm init`).
    ///
    /// Inherits stdin/stdout/stderr so the user can respond to prompts directly.
    async fn init(&self) -> Result<()>;
}

/// Creates the configured [`PackageRunner`] from a `package_manager` string.
pub struct RunnerFactory;

impl RunnerFactory {
    /// Return a boxed `PackageRunner` for the given `package_manager` name.
    ///
    /// Returns `Err(Error::Config)` for unknown or not-yet-implemented managers.
    /// Returns `Err(Error::PackageManagerNotFound)` if the binary is not in `$PATH`.
    pub async fn create(
        project_dir: &Path,
        package_manager: &str,
    ) -> Result<Box<dyn PackageRunner>> {
        match package_manager {
            "bun" => Ok(Box::new(BunRunner::new(project_dir).await?)),
            // TODO(Task 4): add "npm" arm once NpmRunner is implemented.
            // config.rs accepts "npm" as a valid config value, but the runner arm
            // does not exist yet — a user who sets package_manager = "npm" will
            // hit this error until Task 4 lands.
            other => Err(Error::Config(format!(
                "unknown package_manager '{other}' — supported values: bun, npm"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_unknown_manager_returns_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let result = RunnerFactory::create(dir.path(), "yarn").await;
        assert!(
            matches!(result, Err(Error::Config(_))),
            "unknown package manager should return Error::Config, got: {result:?}",
        );
    }

    /// "npm" is accepted by config validation but has no runner yet (until Task 4).
    /// Pin this behaviour so the test fails visibly when Task 4 wires it up.
    #[tokio::test]
    async fn create_npm_returns_config_error_until_task4() {
        let dir = tempfile::tempdir().unwrap();
        let result = RunnerFactory::create(dir.path(), "npm").await;
        assert!(
            matches!(result, Err(Error::Config(_))),
            "npm should return Error::Config until NpmRunner is implemented, got: {result:?}",
        );
    }

    #[tokio::test]
    async fn create_empty_string_returns_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let result = RunnerFactory::create(dir.path(), "").await;
        assert!(
            matches!(result, Err(Error::Config(_))),
            "empty string should return Error::Config, got: {result:?}",
        );
    }
}
