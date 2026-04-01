use clap::Args;

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Fail if vigil.lock is missing (useful in CI).
    #[arg(long)]
    pub ci: bool,
}

pub async fn run(args: VerifyArgs) -> miette::Result<()> {
    eprintln!("vigil verify: not yet implemented");
    let _ = args;
    Ok(())
}
