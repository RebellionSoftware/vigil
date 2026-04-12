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
    /// Returns `Err(Error::PackageManagerNotFound)` if `bun` is not found in `$PATH`.
    ///
    /// Uses `spawn_blocking` so the probe does not block a Tokio worker thread.
    pub async fn new(project_dir: &Path) -> Result<Self> {
        let status = tokio::task::spawn_blocking(|| {
            std::process::Command::new("bun")
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
        })
        .await
        .map_err(|_| Error::PackageManagerNotFound("bun".to_string()))? // JoinError — task panicked
        .map_err(|_| Error::PackageManagerNotFound("bun".to_string()))?; // io::Error — bun not in PATH

        if !status.success() {
            return Err(Error::PackageManagerNotFound("bun".to_string()));
        }

        Ok(BunRunner {
            bun_path: PathBuf::from("bun"),
            project_dir: project_dir.to_path_buf(),
        })
    }

    /// Run `bun add --exact [--dev|--optional] [--ignore-scripts] <name>@<version>…`.
    ///
    /// `dev` places packages in `devDependencies`; `optional` in `optionalDependencies`.
    /// These are mutually exclusive — callers must not set both. The flag applies to
    /// every package in the slice, so callers are responsible for grouping packages
    /// by type before calling this method.
    ///
    /// `ignore_scripts` should be `true` when `block_postinstall` is enabled
    /// so that Bun does not execute lifecycle scripts during installation.
    pub async fn add(
        &self,
        packages: &[PackageSpec],
        dev: bool,
        optional: bool,
        ignore_scripts: bool,
    ) -> Result<()> {
        debug_assert!(
            !(dev && optional),
            "dev and optional are mutually exclusive; caller must not set both"
        );
        let mut cmd = Command::new(&self.bun_path);
        cmd.current_dir(&self.project_dir);
        cmd.arg("add").arg("--exact");
        if dev {
            cmd.arg("--dev");
        } else if optional {
            cmd.arg("--optional");
        }
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

    /// Run `bun init` interactively.
    ///
    /// Unlike other methods, this inherits stdin/stdout/stderr so the user
    /// can respond to bun's prompts directly in the terminal.
    pub async fn init(&self) -> Result<()> {
        let status = tokio::process::Command::new(&self.bun_path)
            .current_dir(&self.project_dir)
            .arg("init")
            .status()
            .await
            .map_err(|_| Error::PackageManagerNotFound("bun".to_string()))?;

        if !status.success() {
            return Err(Error::PackageManagerFailed {
                manager: "bun".to_string(),
                status: status.code().unwrap_or(-1),
                // `bun init` inherits the terminal (stdin/stdout/stderr are not piped),
                // so there is no captured output to report.
                output: String::new(),
            });
        }
        Ok(())
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
            .map_err(|_| Error::PackageManagerNotFound("bun".to_string()))?;

        if output.status.success() {
            return Ok(());
        }

        let code = output.status.code().unwrap_or(-1);
        let combined = format!(
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        Err(Error::PackageManagerFailed { manager: "bun".to_string(), status: code, output: combined })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `run` returns `PackageManagerNotFound` when the binary
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
        assert!(matches!(result, Err(Error::PackageManagerNotFound(_))));
    }
}
