use async_trait::async_trait;
use crate::registry::types::PackageMetadata;

/// The result type for registry operations — uses vigil-core's error.
pub type RegistryResult<T> = std::result::Result<T, crate::registry::RegistryError>;

/// Abstraction over the npm registry. Implement this to swap in a mock for tests.
#[async_trait]
pub trait RegistryClient: Send + Sync {
    async fn get_package_metadata(&self, name: &str) -> RegistryResult<PackageMetadata>;
}
