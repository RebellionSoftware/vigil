// RegistryError now lives in vigil-core::registry::RegistryError.
// Re-export it here for crates that only depend on vigil-registry.
pub use vigil_core::registry::RegistryError;
pub type Result<T> = std::result::Result<T, RegistryError>;
