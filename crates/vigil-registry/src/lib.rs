// vigil-registry provides the concrete HTTP and mock clients.
// Types (PackageMetadata, VersionMetadata, etc.) and the RegistryClient trait
// live in vigil-core so the resolver can use them without a circular dependency.

pub mod client;
pub mod error;
mod fixture_tests;
pub mod mock;
pub mod semver_resolve;
pub mod types;

// Re-export core registry types for convenience
pub use vigil_core::registry::{DistInfo, Maintainer, PackageMetadata, RegistryClient, VersionMetadata};

pub use client::NpmRegistryClient;
pub use error::RegistryError;
pub use mock::{MockRegistryClient, PackageMetadataBuilder};
pub use semver_resolve::resolve_version;
