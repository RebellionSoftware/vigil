use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tokio::process::Command;

use crate::{
    error::{Error, Result},
    runner::PackageRunner,
    types::{PackageName, PackageSpec},
};

/// Wraps the npm subprocess for package installation operations.
#[derive(Debug)]
pub struct NpmRunner {
    /// Resolved path to the `npm` binary.
    npm_path: PathBuf,
    /// The project root (directory containing `package.json`).
    project_dir: PathBuf,
}

impl NpmRunner {
    /// Find `npm` in `$PATH` and verify it is executable.
    ///
    /// Returns `Err(Error::PackageManagerNotFound)` if `npm` is not found in `$PATH`.
    pub async fn new(project_dir: &Path) -> Result<Self> {
        let status = tokio::process::Command::new("npm")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Error::PackageManagerNotFound("npm".to_string()),
                _ => Error::Io(e),
            })?;

        if !status.success() {
            return Err(Error::PackageManagerNotFound("npm".to_string()));
        }

        Ok(NpmRunner {
            npm_path: PathBuf::from("npm"),
            project_dir: project_dir.to_path_buf(),
        })
    }

    /// Run `npm install --save-exact [--save-dev|--save-optional] [--ignore-scripts] <name>@<version>…`.
    pub async fn add(
        &self,
        packages: &[PackageSpec],
        dev: bool,
        optional: bool,
        ignore_scripts: bool,
    ) -> Result<()> {
        if dev && optional {
            return Err(Error::Config(
                "add(): dev and optional flags are mutually exclusive".to_string(),
            ));
        }
        let mut cmd = Command::new(&self.npm_path);
        cmd.current_dir(&self.project_dir);
        cmd.arg("install").arg("--save-exact");
        if dev {
            cmd.arg("--save-dev");
        } else if optional {
            cmd.arg("--save-optional");
        }
        if ignore_scripts {
            cmd.arg("--ignore-scripts");
        }
        for pkg in packages {
            cmd.arg(format!("{}@{}", pkg.name, pkg.version));
        }
        self.run(cmd).await
    }

    /// Run `npm uninstall <name>…`.
    pub async fn remove(&self, package_names: &[PackageName]) -> Result<()> {
        let mut cmd = Command::new(&self.npm_path);
        let name_strs: Vec<&str> = package_names.iter().map(|n| n.as_str()).collect();
        cmd.current_dir(&self.project_dir)
            .arg("uninstall")
            .args(&name_strs);
        self.run(cmd).await
    }

    /// Run `npm init` interactively.
    ///
    /// Inherits stdin/stdout/stderr so the user can respond to prompts directly.
    pub async fn init(&self) -> Result<()> {
        let status = tokio::process::Command::new(&self.npm_path)
            .current_dir(&self.project_dir)
            .arg("init")
            .status()
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Error::PackageManagerNotFound("npm".to_string()),
                _ => Error::Io(e),
            })?;

        if !status.success() {
            return Err(Error::PackageManagerFailed {
                manager: "npm".to_string(),
                status: status.code().unwrap_or(-1),
                output: String::new(),
            });
        }
        Ok(())
    }

    /// Run a bare `npm install` (installs from existing `package.json` + lockfile).
    pub async fn install(&self, ignore_scripts: bool) -> Result<()> {
        let mut cmd = Command::new(&self.npm_path);
        cmd.current_dir(&self.project_dir).arg("install");
        if ignore_scripts {
            cmd.arg("--ignore-scripts");
        }
        self.run(cmd).await
    }

    // ── internal ─────────────────────────────────────────────────────────────

    async fn run(&self, mut cmd: Command) -> Result<()> {
        let output = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Error::PackageManagerNotFound("npm".to_string()),
                _ => Error::Io(e),
            })?;

        if output.status.success() {
            return Ok(());
        }

        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let combined = if stderr.trim().is_empty() {
            stdout.trim().to_string()
        } else if stdout.trim().is_empty() {
            stderr.trim().to_string()
        } else {
            format!("{}\n{}", stderr.trim(), stdout.trim())
        };
        Err(Error::PackageManagerFailed {
            manager: "npm".to_string(),
            status: code,
            output: combined,
        })
    }
}

// ── PackageRunner impl ────────────────────────────────────────────────────────

#[async_trait]
impl PackageRunner for NpmRunner {
    fn package_manager(&self) -> &str {
        "npm"
    }

    async fn add(
        &self,
        packages: &[PackageSpec],
        dev: bool,
        optional: bool,
        ignore_scripts: bool,
    ) -> Result<()> {
        NpmRunner::add(self, packages, dev, optional, ignore_scripts).await
    }

    async fn remove(&self, package_names: &[PackageName]) -> Result<()> {
        // UFCS avoids ambiguity between the inherent method and this trait method.
        NpmRunner::remove(self, package_names).await
    }

    async fn install(&self, ignore_scripts: bool) -> Result<()> {
        NpmRunner::install(self, ignore_scripts).await
    }

    async fn init(&self) -> Result<()> {
        NpmRunner::init(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that passing both `dev` and `optional` returns a config error
    /// rather than silently misbehaving.
    #[tokio::test]
    async fn add_dev_and_optional_returns_config_error() {
        let runner = NpmRunner {
            npm_path: PathBuf::from("npm"),
            project_dir: std::env::temp_dir(),
        };
        let result = runner.add(&[], true, true, false).await;
        assert!(
            matches!(result, Err(Error::Config(_))),
            "expected Error::Config for dev+optional, got: {result:?}"
        );
    }

    /// Verify that `run` returns `PackageManagerNotFound` when the binary
    /// does not exist.
    #[tokio::test]
    async fn run_nonexistent_binary_returns_npm_not_found() {
        let runner = NpmRunner {
            npm_path: PathBuf::from("definitely-not-a-real-binary-12345"),
            project_dir: std::env::temp_dir(),
        };
        let mut cmd = Command::new(&runner.npm_path);
        cmd.arg("--version");
        let result = runner.run(cmd).await;
        assert!(matches!(result, Err(Error::PackageManagerNotFound(ref s)) if s == "npm"),
            "expected PackageManagerNotFound(\"npm\"), got: {result:?}");
    }
}
