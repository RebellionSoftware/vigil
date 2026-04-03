use std::path::{Path, PathBuf};
use tokio::process::Command;
use crate::{
    error::{Error, Result},
    types::PackageSpec,
};

/// Wraps the Bun subprocess for package installation operations.
pub struct BunRunner {
    /// Resolved path to the `bun` binary.
    bun_path: PathBuf,
    /// The project root (directory containing `package.json`).
    project_dir: PathBuf,
}

impl BunRunner {
    /// Find `bun` in `$PATH` and verify it is executable.
    ///
    /// Returns `Err(Error::BunNotFound)` if `bun` is not available.
    pub fn new(project_dir: &Path) -> Result<Self> {
        // Probe by running `bun --version`; if it fails bun is not installed.
        let status = std::process::Command::new("bun")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|_| Error::BunNotFound)?;

        if !status.success() {
            return Err(Error::BunNotFound);
        }

        Ok(BunRunner {
            bun_path: PathBuf::from("bun"),
            project_dir: project_dir.to_path_buf(),
        })
    }

    /// Run `bun add --exact [--ignore-scripts] <name>@<version>…`.
    ///
    /// `ignore_scripts` should be `true` when `block_postinstall` is enabled
    /// so that Bun does not execute lifecycle scripts during installation.
    pub async fn add(&self, packages: &[PackageSpec], ignore_scripts: bool) -> Result<()> {
        let mut cmd = Command::new(&self.bun_path);
        cmd.current_dir(&self.project_dir);
        cmd.arg("add").arg("--exact");
        if ignore_scripts {
            cmd.arg("--ignore-scripts");
        }
        for pkg in packages {
            cmd.arg(format!("{}@{}", pkg.name, pkg.version));
        }
        self.run(cmd).await
    }

    /// Run `bun remove <name>…`.
    pub async fn remove(&self, package_names: &[&str]) -> Result<()> {
        let mut cmd = Command::new(&self.bun_path);
        cmd.current_dir(&self.project_dir)
            .arg("remove")
            .args(package_names);
        self.run(cmd).await
    }

    /// Run a bare `bun install` (installs from existing `package.json` + lockfile).
    pub async fn install(&self, ignore_scripts: bool) -> Result<()> {
        let mut cmd = Command::new(&self.bun_path);
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
            .map_err(|_| Error::BunNotFound)?;

        if output.status.success() {
            return Ok(());
        }

        let code = output.status.code().unwrap_or(-1);
        let combined = format!(
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        Err(Error::BunFailed { status: code, output: combined })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `BunRunner::new` returns `BunNotFound` when the binary
    /// does not exist. We test this by constructing a runner manually with a
    /// bogus path and calling `run` directly.
    #[tokio::test]
    async fn run_nonexistent_binary_returns_bun_not_found() {
        let runner = BunRunner {
            bun_path: PathBuf::from("definitely-not-a-real-binary-12345"),
            project_dir: std::env::temp_dir(),
        };
        let mut cmd = Command::new(&runner.bun_path);
        cmd.arg("--version");
        let result = runner.run(cmd).await;
        assert!(matches!(result, Err(Error::BunNotFound)));
    }
}
