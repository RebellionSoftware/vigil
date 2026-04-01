pub mod config;
pub mod error;
pub mod lockfile;
pub mod registry;
pub mod resolver;
pub mod semver_resolve;
pub mod types;

pub use config::VigilConfig;
pub use error::{Error, Result};
pub use lockfile::VigilLockfile;
pub use registry::{RegistryClient, RegistryError, PackageMetadata, VersionMetadata};
pub use resolver::{DependencyResolver, ResolvedNode, ResolvedTree};
pub use types::{ContentHash, ExactVersion, PackageName, PackageSpec};
