use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistryError {
    /// Wraps transport errors from the HTTP client.
    #[error("Network error fetching '{package}': {reason}")]
    Network { package: String, reason: String },

    #[error("Package '{0}' not found in registry")]
    PackageNotFound(String),

    #[error("Version '{version}' not found for package '{package}'")]
    VersionNotFound { package: String, version: String },

    #[error("No version matching '{range}' found for package '{package}'")]
    NoMatchingVersion { package: String, range: String },

    #[error("Failed to parse registry response for '{package}': {reason}")]
    ParseError { package: String, reason: String },

    #[error("Semver parse error for '{input}': {reason}")]
    SemverParse { input: String, reason: String },
}
