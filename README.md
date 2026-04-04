# Vigil

> *Keeping watch so your supply chain doesn't have to be an afterthought.*

A hardened package manager wrapper for the JavaScript ecosystem that prioritizes security over convenience.

## Overview

Vigil is a security policy engine and CLI wrapper around [Bun](https://bun.com) that inverts the traditional package manager model from **trust-by-default** to **deny-by-default, audit-to-allow**. It runs pre-flight security checks on every package before installation and verifies content hashes post-install.

### The Problem

Modern JavaScript package managers (npm, bun, pnpm) are optimized for speed and convenience. Security is reactive — bolt-on audits, after-the-fact advisories, and trust-by-default install behavior. Supply chain attacks exploit the window between malicious package publication and detection, which is often measured in minutes.

**Real attacks Vigil would have prevented:**

| Attack | Year | Vector | Vigil Defense |
|--------|------|--------|---------------|
| **event-stream** | 2018 | Malicious maintainer published `flatmap-stream` as a dep containing an encrypted payload targeting Copay bitcoin wallets. Executed via postinstall. | `block_postinstall = true` blocks execution; age gate catches fresh publishes. |
| **ua-parser-js** | 2021 | Attacker hijacked npm account, published a new version that downloaded and ran a cryptominer + credential stealer via postinstall. | `block_postinstall = true` + age gate (new version = fresh publish). |
| **node-ipc** | 2022 | Maintainer deliberately shipped protestware that wiped files on Russian/Belarusian IPs, hidden in a patch release of a popular package. | Age gate blocks the fresh version for `min_age_days`. Community has time to detect before your CI pulls it. |
| **colors / faker** | 2022 | Maintainer sabotaged own packages (infinite loop / junk output), breaking thousands of projects that auto-updated. | Exact version pinning in `vigil.lock` prevents auto-update to the malicious version. |
| **Typosquat campaigns** | ongoing | Packages like `crossenv` and `lodash4` registered to intercept common typos. | Age gate blocks newly-registered packages before they spread. |

### The Solution

Vigil adds a hardened security gate that every package must pass through before Bun is ever invoked:

1. Resolves exact versions via the npm registry API
2. Runs pre-flight security checks against every package in the dependency tree
3. Either blocks with a clear reason, or hands off to Bun with pinned, verified specs
4. Verifies SHA-512 content hashes of installed packages post-install
5. Appends tamper-evident entries to an audit log

## Core Security Features

### Version Age Gate

Refuses to install any package version published less than N days ago (default: 7 days). This collapses the attack window that supply chain attacks depend on — a freshly-published malicious version cannot be installed until the community has had time to notice.

- Applies to both direct and transitive dependencies (configurable)
- Bypassable per-package with `--allow-fresh` + mandatory `--reason` (logged to audit trail)

### Postinstall Script Blocking

Lifecycle scripts (`postinstall`, `preinstall`, `install`) are **blocked by default**. Scripts are a primary vector for supply chain attacks — they run arbitrary code at install time with no review.

To allow a specific package:
```bash
vigil trust esbuild --allow postinstall
vigil install esbuild
```

Trust decisions are recorded in the audit log with the approving user and timestamp.

### Content Hash Pinning

Every installed package is hashed (SHA-512, covering all files and their paths) and stored in `vigil.lock`. On every subsequent `vigil verify` run, the hash is recomputed from disk and compared. Any modification — injected backdoor, replaced binary, added file — produces a different digest and fails verification.

```bash
vigil verify          # re-hash all packages, compare to vigil.lock
vigil verify --ci     # same, but exits 1 if vigil.lock is missing (for CI pipelines)
```

### Hard Blocklist

Ban packages entirely, regardless of version or other policy settings. Useful for removing known-malicious packages or enforcing organizational policy.

```toml
[blocked]
packages = ["malicious-pkg", "abandoned-utility"]
```

### Lockfile Integrity

`vigil.lock` includes a SHA-256 checksum of all package entries. If the file is manually edited or corrupted, `vigil install` and `vigil verify` hard-error rather than silently accepting a tampered state.

`vigil.toml` is also hashed at install time and stored in the lockfile. `vigil verify` detects if the policy configuration has drifted since the last install.

### Overrides Drift Detection

Vigil writes a `overrides` block into `package.json` to pin every transitive dependency to the exact version resolved by Vigil. `vigil verify` checks that this block matches the lockfile — detecting manual edits or out-of-band installs that bypass pinning.

### Audit Log

Every install, update, remove, and trust decision is appended to `vigil-audit.log` as NDJSON, including the package, version, age at install, checks passed, approving user, and any bypass reason. The log is append-only and file-locked against concurrent writes.

```bash
vigil audit log                        # show all entries
vigil audit log --package esbuild      # filter by package
vigil audit log --event install        # filter by event type
vigil audit log --last 20              # show last 20 entries
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
│  - Postinstall audit        │
│  - Hard blocklist           │
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
**Bun owns:** downloads, `node_modules` layout, `bun.lockb`

## Project Structure

```
vigil/
├── crates/
│   ├── vigil-core/         # Policy engine, lockfile, resolver, hash verification
│   ├── vigil-registry/     # npm registry API client
│   ├── vigil-scan/         # AST diff scanner (planned)
│   └── vigil-cli/          # CLI, UX, audit log
└── tests/
    └── fixtures/           # Registry response fixtures
```

## Usage

```bash
# Install a package (runs all security checks first)
vigil install axios

# Install multiple packages
vigil install express typescript

# Update all packages to their latest allowed versions
vigil update

# Remove a package (cleans up orphaned transitives)
vigil remove lodash

# Verify all installed packages against vigil.lock
vigil verify

# Verify in CI (fails if vigil.lock is missing)
vigil verify --ci

# View the audit log
vigil audit log

# Trust a package's postinstall scripts before installing
vigil trust esbuild --allow postinstall

# Bypass the age gate with a mandatory reason
vigil install my-new-dep --allow-fresh my-new-dep --reason "internal package, we own it"
```

## Configuration

Create a `vigil.toml` in your project root:

```toml
[policy]
# Minimum age in days before a package version can be installed.
# Blocks versions published less than N days ago to close the rapid-publish attack window.
# Default: 7
min_age_days = 7

# Block packages that have postinstall/preinstall/install lifecycle scripts.
# Scripts must be explicitly trusted via `vigil trust <pkg> --allow postinstall`.
# Default: true
block_postinstall = true

# Apply the age gate to transitive dependencies, not just direct installs.
# Default: true
transitive_age_gate = true

# Allow prerelease versions (e.g. 1.0.0-beta.1) to be resolved.
# Prereleases pinned explicitly in a dependency's package.json are always allowed.
# Default: false
allow_prerelease = false

[bypass]
# Packages that skip the age gate entirely.
# Use for internal packages or tooling you control.
allow_fresh = ["@my-org/internal-lib"]

# Packages whose postinstall scripts are pre-approved.
# Written automatically by `vigil trust <pkg> --allow postinstall` when the
# package is not yet installed.
allow_postinstall = ["esbuild"]

[blocked]
# Hard blocklist — these packages are always rejected, regardless of other config.
# Useful for banning known-bad packages or enforcing organizational policy.
packages = ["malicious-pkg", "abandoned-utility"]
```

## Requirements

- [Bun](https://bun.com) installed and in `PATH`
- Rust toolchain (to build from source)

## License

MIT — see [LICENSE](LICENSE)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes with tests
4. Ensure all tests pass (`cargo test --workspace`)
5. Open a pull request against `master`

Please keep pull requests focused — one feature or fix per PR. For significant changes, open an issue first to discuss the approach.
