use clap::Args;
use std::env;
use vigil_core::bun::BunRunner;
use owo_colors::OwoColorize;

/// The default `vigil.toml` written by `vigil init` and `vigil import`.
///
/// Written as a literal so comments are preserved — `toml::to_string_pretty`
/// on `VigilConfig::default()` would produce a valid file but strip all docs.
pub const VIGIL_TOML_TEMPLATE: &str = r#"[policy]
# Minimum age in days a package version must be before it can be installed.
# Blocks versions published less than N days ago to close the rapid-publish
# attack window. 0 to disable.
min_age_days = 7

# Block packages that have postinstall/preinstall/install lifecycle scripts.
# Scripts must be explicitly approved via `vigil trust <pkg> --allow postinstall`.
block_postinstall = true

# Apply the age gate to transitive dependencies as well as direct installs.
transitive_age_gate = true

# Flag packages that were dormant for this many days and then suddenly publish.
# Sudden activity after long inactivity is a common account-takeover signal.
# 0 to disable.
inactivity_days = 180

# Apply the inactivity check to transitive dependencies as well as directs.
transitive_velocity_check = true

# Allow pre-release versions (e.g. 1.0.0-beta.1) to be resolved.
# Prereleases pinned explicitly in a dependency's package.json are always allowed.
allow_prerelease = false

[bypass]
# Packages that skip the age gate entirely (e.g. internal packages you own).
allow_fresh = []

# Packages pre-approved to run postinstall scripts.
# Populated automatically by `vigil trust <pkg> --allow postinstall`.
allow_postinstall = []

# Packages approved despite long publish inactivity.
# Populated automatically by `vigil trust <pkg> --allow inactivity`.
allow_inactivity = []

[blocked]
# Packages that are always rejected regardless of other policy settings.
# Useful for banning known-bad packages or enforcing organisational policy.
packages = []
"#;

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Overwrite an existing vigil.toml if one already exists.
    #[arg(long)]
    pub force: bool,
}

pub async fn run(args: InitArgs) -> miette::Result<()> {
    let project_dir = env::current_dir()
        .map_err(|e| miette::miette!("cannot determine current directory: {e}"))?;

    let vigil_toml = project_dir.join("vigil.toml");

    if vigil_toml.exists() && !args.force {
        return Err(miette::miette!(
            "vigil.toml already exists in this directory.\n\
             Run `vigil init --force` to overwrite it."
        ));
    }

    // ── Write vigil.toml ──────────────────────────────────────────────────────
    let tmp = project_dir.join("vigil.toml.tmp");
    std::fs::write(&tmp, VIGIL_TOML_TEMPLATE)
        .map_err(|e| miette::miette!("failed to write vigil.toml: {e}"))?;
    std::fs::rename(&tmp, &vigil_toml)
        .map_err(|e| miette::miette!("failed to create vigil.toml: {e}"))?;

    eprintln!("  {} Created vigil.toml", "✓".green().bold());

    // ── Run bun init ──────────────────────────────────────────────────────────
    eprintln!("  {} Running bun init…\n", "→".dimmed());

    let bun = BunRunner::new(&project_dir).await
        .map_err(|e| miette::miette!("{e}"))?;

    bun.init().await
        .map_err(|e| miette::miette!("bun init failed: {e}"))?;

    eprintln!("\n  {} Project initialised. Next steps:", "✓".green().bold());
    eprintln!("     vigil install <package>   install your first dependency");
    eprintln!("     vigil verify              verify installed packages against vigil.lock");

    Ok(())
}
