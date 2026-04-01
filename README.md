# Vigil

> *Keeping watch so your supply chain doesn't have to be an afterthought.*

A hardened package manager wrapper for the JavaScript ecosystem that prioritizes security over convenience.

## Overview

Vigil is a security policy engine and CLI wrapper around [Bun](https://bun.sh) that inverts the traditional package manager model from **trust-by-default** to **deny-by-default, audit-to-allow**. It runs pre-flight security checks on every package before installation and verifies content hashes post-install.

### The Problem

Modern JavaScript package managers (npm, bun, pnpm) are optimized for speed and convenience. Security is reactive — bolt-on audits, after-the-fact advisories, and trust-by-default install behavior. High-profile supply chain attacks (Axios 2025, colors/faker 2022, event-stream 2018) exploit the window between malicious package publication and detection, which is often measured in minutes.

### The Solution

Vigil adds a hardened security gate that every package must pass through before Bun is ever invoked:

1. Resolves exact versions via the npm registry API
2. Runs pre-flight security checks against each package version
3. Either blocks with a clear reason or hands off to Bun with pinned, verified specs
4. Verifies content hashes of installed packages
5. Writes signed entries to an audit log

## Core Security Features

### Version Age Gate
Refuses to install any package version published less than N days ago (default: 7 days). This collapses the attack window that depends on rapid auto-updates.

- Configurable per-project in `vigil.toml`
- Bypassable with `--allow-fresh` + mandatory reason (logged to audit trail)

### Version Velocity Check
Flags packages with suspicious publishing patterns:
- Sudden publish after months of inactivity (account takeover signal)
- Unusual version number jumps
- New maintainer added shortly before publish

### Content Hash Pinning
Every package is pinned by exact SHA-512 content hash in `vigil.lock`, not just version string. On every install or CI run, hashes are re-verified. If the registry ever serves a different tarball for the same version, Vigil hard-errors.

### Postinstall Script Blocking
Postinstall scripts are **off by default**. To allow one:
```bash
vigil trust esbuild --allow postinstall
```

## Architecture

```
User Command
     │
     ▼
┌─────────────────────────────┐
│  Vigil CLI (Rust)           │
│  - Parse intent             │
│  - Load vigil.toml policy   │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│  Pre-flight Checks (Rust)   │
│  - Age gate                 │
│  - Version velocity         │
│  - Typosquat detection      │
│  - Provenance lookup        │
│  - Postinstall audit        │
└────────────┬────────────────┘
             │ Pass / Block
             ▼
┌─────────────────────────────┐
│  Bun (subprocess)           │
│  bun add axios@1.7.4        │  ← always pinned exact version
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│  Post-install Verification  │
│  - Re-hash installed files  │
│  - Compare to vigil.lock    │
│  - Append to audit log      │
└─────────────────────────────┘
```

**Vigil owns:** policy checks, pre-flight, post-install verification, `vigil.lock`, `vigil.toml`, audit log  
**Bun owns:** dependency resolution, downloads, `node_modules` layout, `bun.lockb`

## Project Structure

```
vigil/
├── crates/
│   ├── vigil-core/         # Policy engine, lockfile, hash verification
│   ├── vigil-registry/     # npm registry API client
│   ├── vigil-scan/         # AST diff scanner (planned)
│   └── vigil-cli/          # CLI, UX, audit log
└── tests/
    └── fixtures/           # Registry response fixtures
```

## Usage

```bash
# Install a package
vigil install axios

# Update packages
vigil update

# Remove a package
vigil remove lodash

# Verify installed packages
vigil verify

# View audit log
vigil audit

# Trust a package with postinstall scripts
vigil trust esbuild --allow postinstall
```

## Configuration

Create a `vigil.toml` in your project root:

```toml
[policy]
min_age_days = 7
block_postinstall = true
transitive_age_gate = true

[bypass]
allow_fresh = ["@types/*"]  # Skip age gate for type definitions
```

## License

[To be determined]

## Contributing

[To be determined]
