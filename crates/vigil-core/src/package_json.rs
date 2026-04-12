use std::path::Path;
use serde_json::Value;
use crate::error::{Error, Result};

const BACKUP_FILENAME: &str = "package.json.vigil-backup";

/// Read `package.json` from `project_dir` as an untyped JSON value.
///
/// We parse as `Value` (not a typed struct) to preserve every field we don't
/// touch — formatting will change because `serde_json::to_string_pretty` re-orders
/// nothing but may reformat whitespace.
pub fn read_package_json(project_dir: &Path) -> Result<Value> {
    let path = project_dir.join("package.json");
    let contents = std::fs::read_to_string(&path)?;
    let value: Value = serde_json::from_str(&contents)?;
    Ok(value)
}

/// Write a JSON value back to `package.json`, creating a `.vigil-backup` first.
///
/// The backup is removed on success. If we crash mid-write the backup survives
/// and can be restored manually.
pub fn write_package_json(project_dir: &Path, value: &Value) -> Result<()> {
    let path = project_dir.join("package.json");
    let backup = project_dir.join(BACKUP_FILENAME);

    // A pre-existing backup means a previous write crashed before cleanup.
    // Do not overwrite it — the user needs to recover from that backup first.
    if backup.exists() {
        return Err(Error::PackageJsonWrite(format!(
            "a stale backup file '{}' already exists from a previous failed write. \
             Restore it manually (`cp {} package.json`) and then retry.",
            backup.display(),
            BACKUP_FILENAME,
        )));
    }

    std::fs::copy(&path, &backup)?;

    let contents = serde_json::to_string_pretty(value)?;
    std::fs::write(&path, format!("{contents}\n"))
        .map_err(|e| Error::PackageJsonWrite(e.to_string()))?;

    // Backup served its purpose — clean it up.
    let _ = std::fs::remove_file(&backup);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write_fixture(dir: &Path, content: &str) {
        std::fs::write(dir.join("package.json"), content).unwrap();
    }

    #[test]
    fn read_parses_package_json() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture(dir.path(), r#"{"name":"my-app","version":"1.0.0","dependencies":{"express":"^4"}}"#);
        let v = read_package_json(dir.path()).unwrap();
        assert_eq!(v["name"], json!("my-app"));
        assert_eq!(v["dependencies"]["express"], json!("^4"));
    }

    #[test]
    fn write_round_trips_preserving_fields() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture(dir.path(), r#"{"name":"app","version":"1.0.0","scripts":{"test":"jest"},"overrides":{}}"#);

        let mut v = read_package_json(dir.path()).unwrap();
        v["//vigil-overrides"] = json!("DO NOT EDIT — managed by vigil");
        v["overrides"] = json!({"ms": "2.1.3"});
        write_package_json(dir.path(), &v).unwrap();

        let v2 = read_package_json(dir.path()).unwrap();
        assert_eq!(v2["name"], json!("app"));
        assert_eq!(v2["scripts"]["test"], json!("jest"));
        assert_eq!(v2["overrides"]["ms"], json!("2.1.3"));
        assert_eq!(v2["//vigil-overrides"], json!("DO NOT EDIT — managed by vigil"));
    }

    #[test]
    fn write_creates_and_removes_backup() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture(dir.path(), r#"{"name":"app"}"#);

        let v = read_package_json(dir.path()).unwrap();
        write_package_json(dir.path(), &v).unwrap();

        // Backup should be cleaned up after a successful write.
        assert!(!dir.path().join("package.json.vigil-backup").exists());
    }

    #[test]
    fn read_errors_on_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture(dir.path(), r#"{ this is not json }"#);
        assert!(read_package_json(dir.path()).is_err());
    }

    #[test]
    fn read_errors_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_package_json(dir.path()).is_err());
    }

    #[test]
    fn write_errors_when_stale_backup_exists() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture(dir.path(), r#"{"name":"app"}"#);
        // Simulate a stale backup from a previous crash
        std::fs::write(dir.path().join("package.json.vigil-backup"), r#"{"name":"old"}"#).unwrap();

        let v = read_package_json(dir.path()).unwrap();
        let result = write_package_json(dir.path(), &v);
        assert!(result.is_err(), "should refuse to overwrite a stale backup");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("stale backup"), "error should mention stale backup: {msg}");
    }
}
