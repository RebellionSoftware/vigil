use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to parse TOML: {0}")]
    TomlDe(#[from] toml::de::Error),

    #[error("Failed to serialize TOML: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("Lockfile schema version {found} is newer than supported version {supported}. Please upgrade vigil.")]
    LockfileSchemaTooNew { found: u32, supported: u32 },

    #[error("Invalid package name: '{0}'")]
    InvalidPackageName(String),

    #[error("Invalid package spec '{0}': expected 'name@version'")]
    InvalidPackageSpec(String),

    #[error("Failed to parse package.json: {0}")]
    PackageJsonParse(#[from] serde_json::Error),

    #[error("Failed to write package.json: {0}")]
    PackageJsonWrite(String),

    #[error("Policy violation for {package}: {reason}")]
    PolicyViolation { package: String, reason: String },

    #[error("Hash mismatch for {package}: expected {expected}, found {actual}")]
    HashMismatch {
        package: String,
        expected: String,
        actual: String,
    },

    #[error("Bun not found in PATH. Please install Bun: https://bun.sh")]
    BunNotFound,

    #[error("Bun exited with status {status}:\n{output}")]
    BunFailed { status: i32, output: String },
}

pub type Result<T> = std::result::Result<T, Error>;
