use clap::Args;

#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Package(s) to update. Omit to use --all.
    pub packages: Vec<String>,

    /// Update only the transitive deps of the specified package, not the package itself.
    #[arg(long)]
    pub transitive: bool,

    /// Update all packages and their transitive deps.
    #[arg(long, conflicts_with = "packages")]
    pub all: bool,

    /// Bypass age gate for specific package(s). Requires --reason.
    #[arg(long, value_name = "PACKAGE")]
    pub allow_fresh: Vec<String>,

    /// Reason for bypassing a check.
    #[arg(long, requires = "allow_fresh")]
    pub reason: Option<String>,
}

pub async fn run(args: UpdateArgs) -> miette::Result<()> {
    eprintln!("vigil update: not yet implemented");
    eprintln!("  packages: {:?}", args.packages);
    Ok(())
}
