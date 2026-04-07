use owo_colors::OwoColorize;
use vigil_core::{
    policy::{CheckOutcome, CheckResult, TreeCheckReport},
    resolver::ResolvedTree,
};

const CHECK: &str = "✓";
const CROSS: &str = "✗";
const WARN: &str = "⚠";

/// Print the full check results table to stderr, grouped into DIRECT and
/// TRANSITIVE sections. Returns `true` if any blockers are present.
pub fn print_check_report(report: &TreeCheckReport, tree: &ResolvedTree) -> bool {
    let direct_results = collect_section(report, tree, true);
    let trans_results  = collect_section(report, tree, false);

    if !direct_results.is_empty() {
        eprintln!("\n{}", "DIRECT DEPENDENCIES".bold());
        print_section(&direct_results);
    }

    if !trans_results.is_empty() {
        eprintln!("\n{}", "TRANSITIVE DEPENDENCIES".bold());
        print_section(&trans_results);
    }

    // Count unique packages, not CheckResult entries (one package can have
    // multiple failing checks and must only count as one blocked package).
    let n_checked = report.results.iter()
        .map(|r| r.package.to_key())
        .collect::<std::collections::HashSet<_>>()
        .len();
    let n_blocked = report.blocked().iter()
        .map(|r| r.package.to_key())
        .collect::<std::collections::HashSet<_>>()
        .len();
    let n_warned = report.warnings().iter()
        .map(|r| r.package.to_key())
        .collect::<std::collections::HashSet<_>>()
        .len();

    eprintln!();
    if n_blocked > 0 {
        eprintln!(
            "  {} {} packages checked — {} blocked",
            CROSS.red(),
            n_checked,
            n_blocked.to_string().red().bold(),
        );
    } else if n_warned > 0 {
        eprintln!(
            "  {} {} packages checked — {} warnings",
            WARN.yellow(),
            n_checked,
            n_warned,
        );
    } else {
        eprintln!(
            "  {} {} packages checked — all clear",
            CHECK.green(),
            n_checked,
        );
    }

    report.has_blockers()
}

/// Print a single package line (may span multiple lines for multiple checks).
fn print_section(results: &[&CheckResult]) {
    // Group by package key, preserving the sorted order from the report.
    let mut seen: Vec<String> = Vec::new();
    let mut seen_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut grouped: std::collections::HashMap<String, Vec<&CheckResult>> =
        std::collections::HashMap::new();
    for r in results {
        let key = r.package.to_key();
        grouped.entry(key.clone()).or_default().push(r);
        if seen_set.insert(key.clone()) {
            seen.push(key);
        }
    }

    for key in &seen {
        let checks = &grouped[key];
        let has_blocker = checks.iter().any(|r| r.outcome.is_blocked());
        let has_warning = checks.iter().any(|r| r.outcome.is_warning());

        let icon = if has_blocker {
            CROSS.red().to_string()
        } else if has_warning {
            WARN.yellow().to_string()
        } else {
            CHECK.green().to_string()
        };

        eprintln!("  {} {}", icon, key.bold());

        for check in checks {
            match &check.outcome {
                CheckOutcome::Blocked { reason } => {
                    eprintln!("      {} [{}] {}", CROSS.red(), check.check_name, reason);
                }
                CheckOutcome::Warning { reason } => {
                    eprintln!("      {} [{}] {}", WARN.yellow(), check.check_name, reason);
                }
                CheckOutcome::Passed => {
                    // Don't print a line per-check for passing — the green ✓ is enough.
                }
            }
        }
    }
}

/// Collect all check results for packages in a given section (direct or transitive).
fn collect_section<'a>(
    report: &'a TreeCheckReport,
    tree: &ResolvedTree,
    want_direct: bool,
) -> Vec<&'a CheckResult> {
    report
        .results
        .iter()
        .filter(|r| {
            tree.get(&r.package.to_key())
                .map(|n| n.is_direct == want_direct)
                .unwrap_or(false)
        })
        .collect()
}

/// Print a simple success banner after a completed install.
pub fn print_install_success(package_count: usize, dev: bool, optional: bool) {
    let kind = if dev { " as dev dependency" } else if optional { " as optional dependency" } else { "" };
    eprintln!(
        "\n  {} Installed {} package{}{}",
        CHECK.green().bold(),
        package_count,
        if package_count == 1 { "" } else { "s" },
        kind,
    );
}

/// Return a miette error indicating installation was blocked.
///
/// The per-package details were already printed by `print_check_report`; this
/// just adds the final "Installation blocked." header with context-aware hints
/// and the machine-readable error.
pub fn print_blocked_and_fail(report: &TreeCheckReport) -> miette::Error {
    let blocked = report.blocked();
    let n = blocked.iter()
        .map(|r| r.package.to_key())
        .collect::<std::collections::HashSet<_>>()
        .len();

    eprintln!("{}", format!("\nInstallation blocked — {n} package{} failed security checks.", if n == 1 { "" } else { "s" }).red().bold());

    // Collect the distinct check names that caused blocks so hints are relevant.
    let check_names: std::collections::HashSet<&str> =
        blocked.iter().map(|r| r.check_name).collect();

    if check_names.contains("age-gate") {
        eprintln!("  {} Age gate: use --allow-fresh <package> --reason \"<reason>\" to bypass.", "→".dimmed());
    }
    if check_names.contains("velocity") {
        eprintln!("  {} Inactivity: use `vigil trust <package> --allow inactivity` after reviewing the changelog.", "→".dimmed());
    }
    if check_names.contains("postinstall") {
        eprintln!("  {} Postinstall: use `vigil trust <package> --allow postinstall` to approve scripts.", "→".dimmed());
    }
    if check_names.contains("blocked") {
        eprintln!("  {} Blocklist: remove the package from [blocked].packages in vigil.toml to allow.", "→".dimmed());
    }

    miette::miette!("{n} package{} failed security checks", if n == 1 { "" } else { "s" })
}
