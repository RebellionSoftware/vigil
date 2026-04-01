use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommand,
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Display the audit log.
    Log(AuditLogArgs),
}

#[derive(Debug, Args)]
pub struct AuditLogArgs {
    /// Filter by package name.
    #[arg(long)]
    pub package: Option<String>,

    /// Filter by event type (install, update, remove, bypass).
    #[arg(long)]
    pub event: Option<String>,
}

pub async fn run(args: AuditArgs) -> miette::Result<()> {
    match args.command {
        AuditCommand::Log(log_args) => {
            eprintln!("vigil audit log: not yet implemented");
            let _ = log_args;
        }
    }
    Ok(())
}
