use async_trait::async_trait;
use vigil_core::registry::{PackageMetadata, RegistryClient, RegistryError, RegistryResult};

/// HTTP client for the real npm registry.
pub struct NpmRegistryClient {
    client: reqwest::Client,
    base_url: String,
}

impl NpmRegistryClient {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent(concat!("vigil/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build reqwest client");

        NpmRegistryClient {
            client,
            base_url: "https://registry.npmjs.org".to_string(),
        }
    }

    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        let mut c = Self::new();
        c.base_url = base_url.into();
        c
    }
}

impl Default for NpmRegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RegistryClient for NpmRegistryClient {
    async fn get_package_metadata(&self, name: &str) -> RegistryResult<PackageMetadata> {
        let encoded = encode_package_name(name);
        let url = format!("{}/{}", self.base_url, encoded);

        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| RegistryError::Network {
                package: name.to_string(),
                reason: e.to_string(),
            })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::PackageNotFound(name.to_string()));
        }

        resp.error_for_status_ref().map_err(|e| RegistryError::Network {
            package: name.to_string(),
            reason: e.to_string(),
        })?;

        let metadata: PackageMetadata = resp.json().await.map_err(|e| RegistryError::ParseError {
            package: name.to_string(),
            reason: e.to_string(),
        })?;

        Ok(metadata)
    }
}

/// Encode a package name for use in a URL path.
/// Scoped packages need the `@` encoded as `%40`.
pub fn encode_package_name(name: &str) -> String {
    if name.starts_with('@') {
        name.replacen('@', "%40", 1).replace('/', "%2F")
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_unscoped() {
        assert_eq!(encode_package_name("axios"), "axios");
    }

    #[test]
    fn encode_scoped() {
        assert_eq!(encode_package_name("@types/node"), "%40types%2Fnode");
    }
}
