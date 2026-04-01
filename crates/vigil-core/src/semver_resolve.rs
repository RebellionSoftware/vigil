use semver::{Version, VersionReq};
use crate::registry::RegistryError;

/// Resolve a semver range to the highest matching version from a list of available versions.
///
/// - Pre-releases are excluded unless `allow_prerelease` is true.
/// - Returns the highest version satisfying the range.
/// - Handles npm-specific range aliases: `latest`, `*`, `""` → highest stable version.
pub fn resolve_version(
    range: &str,
    available: &[&str],
    allow_prerelease: bool,
) -> std::result::Result<String, RegistryError> {
    // npm dist-tag or bare "*" / "" → highest stable version
    if range.is_empty() || range == "*" || range == "latest" {
        return highest_stable(available, allow_prerelease)
            .map(|v| v.to_string())
            .ok_or_else(|| RegistryError::NoMatchingVersion {
                package: String::new(),
                range: range.to_string(),
            });
    }

    // npm treats a bare version string (e.g. "1.1.0") as an exact match, but the Rust
    // semver crate parses it as a caret requirement (^1.1.0). Normalize bare versions
    // to "=1.1.0" so they resolve exactly as npm would.
    let normalized = if looks_like_exact_version(range) {
        format!("={range}")
    } else {
        range.to_string()
    };

    // Parse as a semver requirement. npm uses some shorthand that semver crate handles:
    // ^1.2.3, ~1.2.3, >=1.2.0 <2.0.0, 1.2.x, etc.
    let req = VersionReq::parse(&normalized).map_err(|e| RegistryError::SemverParse {
        input: range.to_string(),
        reason: e.to_string(),
    })?;

    let mut best: Option<Version> = None;

    for v_str in available {
        let v = match Version::parse(v_str) {
            Ok(v) => v,
            Err(_) => continue, // skip malformed version strings
        };

        // Skip pre-releases unless explicitly allowed or the range targets one
        if !allow_prerelease && !v.pre.is_empty() {
            continue;
        }

        if req.matches(&v) {
            match &best {
                None => best = Some(v),
                Some(current) if v > *current => best = Some(v),
                _ => {}
            }
        }
    }

    best.map(|v| v.to_string()).ok_or_else(|| RegistryError::NoMatchingVersion {
        package: String::new(),
        range: range.to_string(),
    })
}

/// Returns true if the string looks like a bare exact version (digits and dots only, no operators).
fn looks_like_exact_version(s: &str) -> bool {
    // Must start with a digit and contain only digits, dots, and pre-release/build metadata chars
    // but no semver operators: ^ ~ > < = space
    let first = s.chars().next();
    matches!(first, Some('0'..='9'))
        && !s.contains('^')
        && !s.contains('~')
        && !s.contains('>')
        && !s.contains('<')
        && !s.contains('=')
        && !s.contains(' ')
        && !s.contains('x')
        && !s.contains('X')
        && !s.contains('*')
}

/// Return the highest stable (non-prerelease) version, or highest overall if allow_prerelease.
fn highest_stable<'a>(available: &[&'a str], allow_prerelease: bool) -> Option<Version> {
    let mut best: Option<Version> = None;
    for v_str in available {
        let v = match Version::parse(v_str) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !allow_prerelease && !v.pre.is_empty() {
            continue;
        }
        match &best {
            None => best = Some(v),
            Some(current) if v > *current => best = Some(v),
            _ => {}
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERSIONS: &[&str] = &[
        "1.0.0", "1.1.0", "1.2.0", "1.2.3", "2.0.0", "2.1.0", "3.0.0-alpha.1", "3.0.0",
    ];

    #[test]
    fn caret_resolves_to_highest_compatible() {
        // ^1.0.0 should give 1.2.3 (highest 1.x.x)
        let v = resolve_version("^1.0.0", VERSIONS, false).unwrap();
        assert_eq!(v, "1.2.3");
    }

    #[test]
    fn caret_major_2() {
        let v = resolve_version("^2.0.0", VERSIONS, false).unwrap();
        assert_eq!(v, "2.1.0");
    }

    #[test]
    fn tilde_resolves_to_highest_patch() {
        // ~1.2.0 → highest 1.2.x
        let v = resolve_version("~1.2.0", VERSIONS, false).unwrap();
        assert_eq!(v, "1.2.3");
    }

    #[test]
    fn exact_version() {
        let v = resolve_version("1.1.0", VERSIONS, false).unwrap();
        assert_eq!(v, "1.1.0");
    }

    #[test]
    fn gte_range() {
        let v = resolve_version(">=2.0.0", VERSIONS, false).unwrap();
        assert_eq!(v, "3.0.0"); // prerelease filtered
    }

    #[test]
    fn star_gives_highest_stable() {
        let v = resolve_version("*", VERSIONS, false).unwrap();
        assert_eq!(v, "3.0.0");
    }

    #[test]
    fn empty_range_gives_highest_stable() {
        let v = resolve_version("", VERSIONS, false).unwrap();
        assert_eq!(v, "3.0.0");
    }

    #[test]
    fn prerelease_excluded_by_default() {
        let v = resolve_version(">=3.0.0-alpha.1", VERSIONS, false).unwrap();
        // With prerelease disabled, only 3.0.0 qualifies
        assert_eq!(v, "3.0.0");
    }

    #[test]
    fn prerelease_included_when_allowed() {
        let v = resolve_version("^3.0.0-alpha.1", VERSIONS, true).unwrap();
        assert_eq!(v, "3.0.0"); // 3.0.0 > 3.0.0-alpha.1, both match ^3.0.0-alpha.1
    }

    #[test]
    fn no_match_errors() {
        let result = resolve_version("^99.0.0", VERSIONS, false);
        assert!(result.is_err());
    }

    #[test]
    fn skips_malformed_versions() {
        let versions = &["1.0.0", "not-a-version", "2.0.0"];
        let v = resolve_version("^1.0.0", versions, false).unwrap();
        assert_eq!(v, "1.0.0");
    }
}
