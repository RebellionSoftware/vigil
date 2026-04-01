/// Quick manual test: fetch a real package from npm and print summary.
/// Run with: cargo run -p vigil-registry --example fetch -- <package>
use vigil_registry::{NpmRegistryClient, RegistryClient, resolve_version};

#[tokio::main]
async fn main() {
    let package = std::env::args().nth(1).unwrap_or_else(|| "ms".to_string());

    println!("Fetching '{package}' from npm registry...");
    let client = NpmRegistryClient::new();

    match client.get_package_metadata(&package).await {
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        Ok(meta) => {
            let latest = meta.latest_version().unwrap_or("(none)");
            println!("  name:     {}", meta.name);
            println!("  latest:   {latest}");
            println!("  versions: {}", meta.versions.len());

            if let Some(v) = meta.versions.get(latest) {
                println!("  deps:     {}", v.dependencies.len());
                println!("  postinstall: {}", v.has_postinstall());
                if let Some(pub_time) = meta.time.get(latest) {
                    println!("  published: {pub_time}");
                }
            }

            // Demo semver resolution
            let all: Vec<&str> = meta.all_versions();
            let range = format!("^{latest}");
            match resolve_version(&range, &all, false) {
                Ok(resolved) => println!("  resolve({range}) → {resolved}"),
                Err(e) => println!("  resolve({range}) → error: {e}"),
            }
        }
    }
}
