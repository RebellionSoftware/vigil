use clap::{Parser, Subcommand};
use miette::Result;

mod audit_log;
mod commands;
mod output;

use commands::{audit, import, init, install, remove, trust, update, verify};

#[derive(Debug, Parser)]
#[command(
    name = "vigil",
    version,
    about = "Hardened package manager wrapper for Bun",
    long_about = "Vigil enforces supply chain security policies before any package is installed.\nAll packages must pass pre-flight checks (age gate, postinstall audit, hash pinning)\nbefore Bun is invoked.",
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialise a new project with vigil.toml and run bun init.
    Init(init::InitArgs),

    /// Import an existing project's dependencies into vigil.lock.
    Import(import::ImportArgs),

    /// Install a package (runs all security checks first).
    Install(install::InstallArgs),

    /// Update a package and its transitive dependencies.
    Update(update::UpdateArgs),

    /// Remove a package and clean up orphaned transitives.
    Remove(remove::RemoveArgs),

    /// Re-verify all installed packages against vigil.lock.
    Verify(verify::VerifyArgs),

    /// View or manage the audit log.
    Audit(audit::AuditArgs),

    /// Approve specific permissions for a package (e.g. postinstall scripts).
    Trust(trust::TrustArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init(args) => init::run(args).await,
        Commands::Import(args) => import::run(args).await,
        Commands::Install(args) => install::run(args).await,
        Commands::Update(args) => update::run(args).await,
        Commands::Remove(args) => remove::run(args).await,
        Commands::Verify(args) => verify::run(args).await,
        Commands::Audit(args) => audit::run(args).await,
        Commands::Trust(args) => trust::run(args).await,
    }
}
