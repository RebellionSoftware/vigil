pub mod client;
pub mod error;
pub mod types;

pub use client::{RegistryClient, RegistryResult};
pub use error::RegistryError;
pub use types::{DistInfo, Maintainer, PackageMetadata, VersionMetadata};
