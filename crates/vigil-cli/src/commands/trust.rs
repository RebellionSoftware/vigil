use clap::Args;

#[derive(Debug, Args)]
pub struct TrustArgs {
    /// Package to configure trust for.
    pub package: String,

    /// Grant permission for postinstall scripts.
    #[arg(long = "allow", value_name = "PERMISSION")]
    pub allow: Vec<String>,
}

pub async fn run(args: TrustArgs) -> miette::Result<()> {
    eprintln!("vigil trust: not yet implemented");
    eprintln!("  package: {}", args.package);
    Ok(())
}
