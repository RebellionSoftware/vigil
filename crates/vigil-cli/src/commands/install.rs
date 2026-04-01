use clap::Args;

#[derive(Debug, Args)]
pub struct InstallArgs {
    /// Package(s) to install (e.g. "axios" or "axios@1.7.4").
    pub packages: Vec<String>,

    /// Bypass age gate for specific package(s). Requires --reason.
    #[arg(long, value_name = "PACKAGE")]
    pub allow_fresh: Vec<String>,

    /// Reason for bypassing a check (required when using --allow-fresh).
    #[arg(long, requires = "allow_fresh")]
    pub reason: Option<String>,
}

pub async fn run(args: InstallArgs) -> miette::Result<()> {
    eprintln!("vigil install: not yet implemented");
    eprintln!("  packages: {:?}", args.packages);
    Ok(())
}
