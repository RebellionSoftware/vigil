// semver resolution now lives in vigil-core::semver_resolve.
// Re-export for crates that only depend on vigil-registry.
pub use vigil_core::semver_resolve::resolve_version;
