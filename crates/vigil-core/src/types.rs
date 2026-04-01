use std::fmt;
use serde::{Deserialize, Serialize};
use crate::error::{Error, Result};

/// A validated npm package name (e.g. "axios" or "@types/node").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageName(String);

impl PackageName {
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if name.is_empty() {
            return Err(Error::InvalidPackageName(name));
        }
        // Scoped packages: @scope/name
        if name.starts_with('@') {
            let parts: Vec<&str> = name[1..].splitn(2, '/').collect();
            if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
                return Err(Error::InvalidPackageName(name));
            }
        }
        Ok(PackageName(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<PackageName> for String {
    fn from(n: PackageName) -> Self {
        n.0
    }
}

/// An exact semver version string (e.g. "1.7.4").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExactVersion(String);

impl ExactVersion {
    pub fn new(version: impl Into<String>) -> Self {
        ExactVersion(version.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ExactVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<ExactVersion> for String {
    fn from(v: ExactVersion) -> Self {
        v.0
    }
}

/// A package name + exact version pair used as a map key (e.g. "axios@1.7.4").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageSpec {
    pub name: PackageName,
    pub version: ExactVersion,
}

impl PackageSpec {
    pub fn new(name: PackageName, version: ExactVersion) -> Self {
        PackageSpec { name, version }
    }

    /// Parse "name@version" string.
    pub fn parse(s: &str) -> Result<Self> {
        // Handle scoped packages: @scope/name@version
        let (name_part, version_part) = if s.starts_with('@') {
            // Find the second '@' which separates name from version
            match s[1..].find('@') {
                Some(idx) => (&s[..idx + 1], &s[idx + 2..]),
                None => return Err(Error::InvalidPackageSpec(s.to_string())),
            }
        } else {
            match s.rsplit_once('@') {
                Some((name, ver)) => (name, ver),
                None => return Err(Error::InvalidPackageSpec(s.to_string())),
            }
        };

        if version_part.is_empty() {
            return Err(Error::InvalidPackageSpec(s.to_string()));
        }

        Ok(PackageSpec {
            name: PackageName::new(name_part)?,
            version: ExactVersion::new(version_part),
        })
    }

    pub fn to_key(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

impl fmt::Display for PackageSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.version)
    }
}

/// A SHA-512 content hash (hex-encoded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentHash(String);

impl ContentHash {
    pub fn new(hash: impl Into<String>) -> Self {
        ContentHash(hash.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_name_valid_unscoped() {
        assert!(PackageName::new("axios").is_ok());
        assert!(PackageName::new("lodash").is_ok());
    }

    #[test]
    fn package_name_valid_scoped() {
        assert!(PackageName::new("@types/node").is_ok());
        assert!(PackageName::new("@babel/core").is_ok());
    }

    #[test]
    fn package_name_invalid() {
        assert!(PackageName::new("").is_err());
        assert!(PackageName::new("@").is_err());
        assert!(PackageName::new("@/name").is_err());
        assert!(PackageName::new("@scope/").is_err());
    }

    #[test]
    fn package_spec_parse_unscoped() {
        let spec = PackageSpec::parse("axios@1.7.4").unwrap();
        assert_eq!(spec.name.as_str(), "axios");
        assert_eq!(spec.version.as_str(), "1.7.4");
        assert_eq!(spec.to_string(), "axios@1.7.4");
    }

    #[test]
    fn package_spec_parse_scoped() {
        let spec = PackageSpec::parse("@types/node@20.0.0").unwrap();
        assert_eq!(spec.name.as_str(), "@types/node");
        assert_eq!(spec.version.as_str(), "20.0.0");
        assert_eq!(spec.to_string(), "@types/node@20.0.0");
    }

    #[test]
    fn package_spec_parse_invalid() {
        assert!(PackageSpec::parse("axios").is_err());
        assert!(PackageSpec::parse("axios@").is_err());
        assert!(PackageSpec::parse("").is_err());
    }

    #[test]
    fn package_spec_to_key() {
        let spec = PackageSpec::parse("express@4.18.2").unwrap();
        assert_eq!(spec.to_key(), "express@4.18.2");
    }
}
