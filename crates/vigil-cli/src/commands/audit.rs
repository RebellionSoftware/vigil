use clap::{Args, Subcommand};
use std::env;
use owo_colors::OwoColorize;

use crate::audit_log::AuditLog;

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

    /// Filter by event type (install, update, remove, block, import, trust).
    #[arg(long)]
    pub event: Option<String>,

    /// Show only the last N entries.
    #[arg(long, value_name = "N")]
    pub last: Option<usize>,
}

pub async fn run(args: AuditArgs) -> miette::Result<()> {
    match args.command {
        AuditCommand::Log(log_args) => show_log(log_args).await,
    }
}

async fn show_log(args: AuditLogArgs) -> miette::Result<()> {
    let project_dir = env::current_dir()
        .map_err(|e| miette::miette!("cannot determine current directory: {e}"))?;

    let log = AuditLog::new(&project_dir);
    let mut entries = log
        .read_all()
        .map_err(|e| miette::miette!("failed to read audit log: {e}"))?;

    // Apply filters
    if let Some(ref pkg) = args.package {
        entries.retain(|e| &e.package == pkg);
    }
    if let Some(ref event) = args.event {
        entries.retain(|e| &e.event == event);
    }
    if let Some(n) = args.last {
        let len = entries.len();
        if len > n {
            entries = entries.into_iter().skip(len - n).collect();
        }
    }

    if entries.is_empty() {
        eprintln!("  No audit log entries found.");
        return Ok(());
    }

    // Header
    eprintln!(
        "\n  {:<26} {:<12} {:<30} {:<10} {}",
        "TIMESTAMP".bold(),
        "EVENT".bold(),
        "PACKAGE".bold(),
        "AGE (days)".bold(),
        "USER".bold(),
    );
    eprintln!("  {}", "─".repeat(90));

    for entry in &entries {
        let ts = entry.ts.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let event_colored = match entry.event.as_str() {
            "install" => entry.event.green().to_string(),
            "update"  => entry.event.cyan().to_string(),
            "remove"  => entry.event.red().to_string(),
            "block"   => entry.event.red().bold().to_string(),
            "import"  => entry.event.yellow().to_string(),
            "trust"   => entry.event.magenta().to_string(),
            _         => entry.event.clone(),
        };

        let pkg_ver = format!("{}@{}", entry.package, entry.version);
        eprintln!(
            "  {:<26} {:<12} {:<30} {:<10} {}",
            ts,
            event_colored,
            pkg_ver,
            entry.age_days,
            entry.user,
        );

        if let Some(ref reason) = entry.reason {
            eprintln!("    {} reason: {reason}", "→".dimmed());
        }
    }

    eprintln!("\n  {} entries", entries.len());
    Ok(())
}
