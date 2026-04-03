use std::path::Path;
use sha2::{Digest, Sha512};
use walkdir::WalkDir;
use crate::error::{Error, Result};

/// Compute a deterministic SHA-512 hash of an installed package directory.
///
/// The hash covers every regular file under `node_modules/<package_name>/`,
/// sorted lexicographically by their relative path. Each file contributes its
/// relative path (UTF-8) and its raw bytes, separated by null bytes so that
/// a path that is a prefix of content (or vice-versa) cannot collide.
///
/// Returns a `"sha512-<lowercase-hex>"` string, e.g.
/// `"sha512-a3f2…"` (128 hex chars).
///
/// # Errors
/// Returns an error if the package directory does not exist or cannot be read.
pub fn hash_package_dir(node_modules: &Path, package_name: &str) -> Result<String> {
    let pkg_dir = node_modules.join(package_name);

    if !pkg_dir.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("package directory not found: {}", pkg_dir.display()),
        )));
    }

    let mut entries: Vec<_> = WalkDir::new(&pkg_dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    // `sort_by_file_name` sorts within each directory but not across depths;
    // sort the full list by path for a fully deterministic order.
    entries.sort_by(|a, b| a.path().cmp(b.path()));

    let mut hasher = Sha512::new();
    for entry in &entries {
        let rel = entry
            .path()
            .strip_prefix(&pkg_dir)
            .expect("entry is always under pkg_dir")
            .to_string_lossy();

        // path component
        hasher.update(rel.as_bytes());
        hasher.update(b"\0");

        // file content
        let content = std::fs::read(entry.path())?;
        hasher.update(&content);
        hasher.update(b"\0");
    }

    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("sha512-{hex}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_pkg(node_modules: &Path, pkg: &str, files: &[(&str, &str)]) {
        let pkg_dir = node_modules.join(pkg);
        fs::create_dir_all(&pkg_dir).unwrap();
        for (name, content) in files {
            let path = pkg_dir.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, content).unwrap();
        }
    }

    #[test]
    fn hash_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        write_pkg(&nm, "ms", &[("index.js", "module.exports = {}"), ("package.json", r#"{"name":"ms"}"#)]);

        let h1 = hash_package_dir(&nm, "ms").unwrap();
        let h2 = hash_package_dir(&nm, "ms").unwrap();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha512-"), "hash should be prefixed: {h1}");
    }

    #[test]
    fn hash_changes_when_content_changes() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        write_pkg(&nm, "ms", &[("index.js", "v1")]);

        let h1 = hash_package_dir(&nm, "ms").unwrap();
        fs::write(nm.join("ms").join("index.js"), "v2").unwrap();
        let h2 = hash_package_dir(&nm, "ms").unwrap();

        assert_ne!(h1, h2, "hash should change when file content changes");
    }

    #[test]
    fn hash_changes_when_file_added() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        write_pkg(&nm, "ms", &[("index.js", "code")]);

        let h1 = hash_package_dir(&nm, "ms").unwrap();
        fs::write(nm.join("ms").join("new-file.js"), "extra").unwrap();
        let h2 = hash_package_dir(&nm, "ms").unwrap();

        assert_ne!(h1, h2, "hash should change when a file is added");
    }

    #[test]
    fn hash_changes_when_filename_changes() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        write_pkg(&nm, "pkg", &[("a.js", "same content")]);
        let h1 = hash_package_dir(&nm, "pkg").unwrap();

        let pkg_dir = nm.join("pkg");
        fs::rename(pkg_dir.join("a.js"), pkg_dir.join("b.js")).unwrap();
        let h2 = hash_package_dir(&nm, "pkg").unwrap();

        assert_ne!(h1, h2, "hash should change when a file is renamed");
    }

    #[test]
    fn hash_is_order_independent_of_creation_order() {
        // Two packages with the same files but created in different orders
        // should hash identically.
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");

        write_pkg(&nm, "pkg-a", &[("a.js", "aaa"), ("b.js", "bbb")]);
        // Create b first, then a in pkg-b
        let pb = nm.join("pkg-b");
        fs::create_dir_all(&pb).unwrap();
        fs::write(pb.join("b.js"), "bbb").unwrap();
        fs::write(pb.join("a.js"), "aaa").unwrap();

        let ha = hash_package_dir(&nm, "pkg-a").unwrap();
        let hb = hash_package_dir(&nm, "pkg-b").unwrap();
        assert_eq!(ha, hb, "hash should not depend on filesystem creation order");
    }

    #[test]
    fn hash_errors_on_missing_package() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        fs::create_dir_all(&nm).unwrap();
        let result = hash_package_dir(&nm, "nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn hash_works_for_scoped_package() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        write_pkg(&nm, "@scope/pkg", &[("index.js", "code")]);

        let h = hash_package_dir(&nm, "@scope/pkg").unwrap();
        assert!(h.starts_with("sha512-"));
    }
}
