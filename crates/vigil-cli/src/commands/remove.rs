use clap::Args;

#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Package(s) to remove.
    pub packages: Vec<String>,
}

pub async fn run(args: RemoveArgs) -> miette::Result<()> {
    eprintln!("vigil remove: not yet implemented");
    eprintln!("  packages: {:?}", args.packages);
    Ok(())
}
