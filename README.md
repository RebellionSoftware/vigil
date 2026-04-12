# Vigil

A security-focused package manager wrapper for Bun that enforces supply chain security policies before any package is installed.

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

- Applies to both direct and transitive dependencies (configurable via `transitive_age_gate`)
- Bypassable per-package with `--allow-fresh <package> --reason "<reason>"` (both flags required; reason is logged to the audit trail)

### Inactivity Detection

Flags packages that were dormant for a long time and then suddenly published a new version. Sudden activity on a long-inactive package is a common indicator of account takeover.

- Controlled by `inactivity_days` (default: 180)
- Applies to transitives when `transitive_velocity_check = true`
- Bypassable per-package via `vigil trust <package> --allow inactivity`

### Postinstall Script Blocking

Lifecycle scripts (`postinstall`, `preinstall`, `install`) are **blocked by default**. Scripts are a primary vector for supply chain attacks — they run arbitrary code at install time with no review.

To allow a specific package's scripts:

```bash
vigil trust esbuild --allow postinstall
vigil install esbuild
```

Trust decisions are recorded in the audit log with the approving user and timestamp.

### Content Hash Pinning

Every installed package is hashed (SHA-512, covering all files and their paths) and stored in `vigil.lock`. On every `vigil verify` run, the hash is recomputed from disk and compared. Any modification — injected backdoor, replaced binary, added file — produces a different digest and fails verification.

### Hard Blocklist

Ban packages entirely, regardless of version or other policy settings. Useful for removing known-malicious packages or enforcing organizational policy.

```toml
[blocked]
packages = ["malicious-pkg", "abandoned-utility"]
```

### Lockfile Integrity

`vigil.lock` includes a SHA-256 checksum of all package entries. If the file is manually edited or corrupted, `vigil install` and `vigil verify` hard-error rather than silently accepting a tampered state.

`vigil.toml` is also hashed at install time and stored in `vigil.lock`. `vigil verify` detects if the policy configuration has drifted since the last install.

### Overrides Drift Detection

Vigil writes an `overrides` block into `package.json` to pin every transitive dependency to the exact version resolved by Vigil. `vigil verify` checks that this block matches the lockfile — detecting manual edits or out-of-band installs that bypass pinning.

The overrides block is protected by a `_vigil` sentinel so Vigil can identify and manage it safely without touching any overrides you manage yourself.

### Audit Log

Every install, update, remove, import, and trust decision is appended to `vigil-audit.log` as NDJSON, including the package, version, age at install, checks passed, approving user, and any bypass reason. The log is append-only and file-locked against concurrent writes.

```bash
vigil audit log                        # show all entries
vigil audit log --package esbuild      # filter by package
vigil audit log --event install        # filter by event type
vigil audit log --last 20              # show last 20 entries
vigil audit verify                     # verify the hash chain integrity
```

Valid event types: `install`, `update`, `remove`, `block`, `import`, `trust`.

`vigil audit verify` walks the log and checks that each entry's `prev_hash` matches the SHA-256 of the previous raw line. A chain break indicates that a log entry was deleted, inserted, or modified. Legacy entries without a `prev_hash` (written before chain support was added) produce a warning but do not fail.

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
│  - Inactivity check         │
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

## Usage

### Starting a new project

```bash
vigil init
```

Creates `vigil.toml` with default policy settings and runs `bun init` to scaffold the project.

### Onboarding an existing project

```bash
vigil import
vigil import --include-dev   # also import devDependencies
```

Reads `package.json`, resolves the full dependency tree, and writes `vigil.lock`. Policy checks run but **never block** during import — existing projects may have packages that predate your policy. Packages that would be blocked on a fresh install are flagged with a warning. Any prior postinstall approvals for currently-blocked packages are revoked.

If `node_modules` exists, Vigil reads exact installed versions from disk rather than resolving from the registry. Direct deps are pinned to their exact resolved versions in `package.json`; transitives are pinned via the `overrides` block.

### Installing packages

```bash
# Install a package (runs all security checks first)
vigil install axios

# Install multiple packages
vigil install express typescript

# Install as a dev dependency
vigil install typescript --dev

# Install as an optional dependency
vigil install fsevents --optional

# Bypass the age gate for a specific package (both flags required)
vigil install my-new-dep --allow-fresh my-new-dep --reason "internal package, we own it"
```

### Trusting a package

```bash
# Pre-approve postinstall scripts (run before vigil install)
vigil trust esbuild --allow postinstall

# Approve an inactivity bypass
vigil trust some-package --allow inactivity

# Approve both at once
vigil trust some-package --allow postinstall --allow inactivity
```

`vigil trust` works in two modes:
- **Pre-install:** if the package is not yet in `vigil.lock`, writes the approval to `vigil.toml` so the subsequent install can proceed.
- **Post-import:** if the package is already in `vigil.lock` (e.g. after `vigil import`), updates the lockfile entry directly.

### Updating a package

```bash
vigil update axios
```

Resolves the latest allowed version, re-runs all policy checks, and updates `vigil.lock` and the `package.json` overrides block.

### Removing a package

```bash
vigil remove lodash
```

Removes the package and cleans up any transitives that are no longer needed by other installed packages.

### Verifying installed packages

```bash
# Re-hash all packages and compare to vigil.lock
vigil verify

# Exit 1 if vigil.lock is missing (for CI pipelines)
vigil verify --ci

# Also warn if vigil.lock has uncommitted local changes
vigil verify --git

# Recommended CI invocation: fail on missing lockfile or uncommitted changes
vigil verify --ci --git
```

`vigil verify` checks three things:
1. SHA-512 content hash of each package in `node_modules` matches `vigil.lock`
2. The `package.json` overrides block matches the pinned versions in `vigil.lock`
3. `vigil.toml` has not been modified since the last install

In `--ci` mode, packages whose disk hash was not yet recorded also cause a failure — every package must have been through a `vigil install` run before CI verify.

`--git` runs `git status --porcelain vigil.lock` and warns if the lockfile has uncommitted local changes. Combined with `--ci`, uncommitted changes are treated as a hard failure. This check is a no-op if `vigil.lock` is listed in `.gitignore`.

## Configuration

`vigil.toml` is created automatically by `vigil init` or `vigil import`. All fields shown below are the defaults.

```toml
[policy]
# Minimum age in days before a package version can be installed.
# Blocks versions published less than N days ago to close the rapid-publish attack window.
min_age_days = 7

# Block packages that have postinstall/preinstall/install lifecycle scripts.
# Scripts must be explicitly trusted via `vigil trust <pkg> --allow postinstall`.
block_postinstall = true

# Apply the age gate to transitive dependencies, not just direct installs.
transitive_age_gate = true

# Flag packages that were dormant for N days and then published a new version.
# Set to 0 to disable.
inactivity_days = 180

# Apply the inactivity check to transitive dependencies.
transitive_velocity_check = true

# Allow prerelease versions (e.g. 1.0.0-beta.1) to be resolved.
# Prereleases pinned explicitly in a dependency's package.json are always allowed.
allow_prerelease = false

[bypass]
# Packages that skip the age gate entirely.
# Use for internal packages or tooling you control.
allow_fresh = ["@my-org/internal-lib"]

# Packages whose postinstall scripts are pre-approved.
# Written automatically by `vigil trust <pkg> --allow postinstall`.
allow_postinstall = ["esbuild"]

# Packages approved despite failing the inactivity check.
# Written automatically by `vigil trust <pkg> --allow inactivity`.
allow_inactivity = []

[blocked]
# Hard blocklist — these packages are always rejected, regardless of other config.
packages = ["malicious-pkg", "abandoned-utility"]
```

## vigil.lock

`vigil.lock` is a TOML file that records the full resolved state of your dependency tree. It is committed to version control.

Each entry in `[packages]` has the following fields:

| Field | Description |
|-------|-------------|
| `content_hash` | SHA-512 hash of the package directory in `node_modules` (computed post-install) |
| `published_at` | Timestamp from the npm registry for this version |
| `age_at_install_days` | Age of the version in days at the time of install |
| `direct` | `true` if this is a direct dependency; `false` if transitive |
| `transitive_of` | Chain of package names that pulled in this transitive dep |
| `postinstall_approved` | `true` if postinstall scripts have been explicitly trusted |
| `installed_at` | Timestamp of when Vigil installed this package |
| `installed_by` | OS username of who ran the install |
| `dev` | `true` if installed as a dev dependency (omitted otherwise) |
| `optional` | `true` if installed as an optional dependency (omitted otherwise) |

The `[meta]` section stores a `packages_checksum` (SHA-256 of all package entries) for tamper detection, and a `config_hash` of `vigil.toml` at the time of the last install.

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

## Security Model & Trust Boundary

Understanding what Vigil guarantees — and what it explicitly does not — is essential for using it correctly in a security-sensitive environment.

### What Vigil guarantees

- **Policy checks run before Bun.** No package reaches `bun add` unless it has passed all configured checks. The age gate, inactivity check, postinstall block, and hard blocklist are enforced before any network download occurs.
- **Content hashes are computed post-install.** After Bun writes to `node_modules`, Vigil computes a SHA-512 hash of every installed package directory and records it in `vigil.lock`. `vigil verify` re-hashes from disk and fails on any mismatch — injected files, replaced binaries, or modified scripts all produce a different digest.
- **The audit log is tamper-evident.** Each entry in `vigil-audit.log` contains a SHA-256 hash of the previous raw log line, forming a hash chain. Deleting, inserting, or modifying any entry breaks the chain, detectable with `vigil audit verify`.

### What Vigil does NOT guarantee

- **Vigil does not sandbox Bun or inspect downloaded tarballs.** It trusts that npm registry metadata (publish timestamp, version, scripts fields) is accurate. A registry under adversary control could serve false metadata.
- **Vigil does not authenticate the npm registry.** TLS to the registry is Bun's responsibility. Vigil reads from the npm registry API over HTTPS but performs no certificate pinning.
- **`vigil.lock` integrity depends on the filesystem.** If an attacker has write access to your project directory, they can also tamper with `vigil.lock`. Vigil's lockfile checksum detects accidental corruption and naive edits, but is not a substitute for filesystem access controls.
- **The audit log is tamper-evident, not tamper-proof.** A local attacker with write access can replace the entire log (defeating the chain). Commit `vigil-audit.log` to version control to make tampering visible in git history.
- **Vigil does not protect against a compromised build host.** If the machine running `vigil install` is already compromised, all bets are off.
- **Running `bun add` directly bypasses all Vigil checks.** Any package installed via Bun outside of `vigil install` skips the age gate, inactivity check, postinstall block, and hard blocklist, and is not recorded in the audit log. Enforce Vigil-only installs through team convention, CI enforcement (`vigil verify --ci` will reject packages not in `vigil.lock`), and optionally shell aliases or wrapper scripts.
- **`vigil import` does not block policy violations — it warns only.** The initial baseline established by `vigil import` may contain packages that would be blocked on a fresh `vigil install`. Review import warnings and use `vigil trust` or `[blocked]` to address them before treating the lockfile as a hardened security baseline.
- **Policy checks are conditional on your configuration.** Setting `min_age_days = 0` and `block_postinstall = false` disables those checks entirely. Vigil enforces whatever policy you configure — it does not warn when the effective configuration provides minimal protection.

### Assumed trust boundary

Vigil assumes:

1. **The local filesystem is trusted** — only authorized developers can write to the project directory.
2. **`vigil.lock` is committed to version control** — git history provides the out-of-band integrity anchor for the lockfile and audit log.
3. **The npm registry is honest** — metadata fields (`time`, `scripts`, `dist.integrity`) reflect reality.

If any of these assumptions do not hold in your threat model, layer additional controls (e.g., Sigstore provenance, hermetic build environments, reproducible builds).

### Recommended CI pipeline

```yaml
# Recommended order in CI — verify before install
- run: vigil verify --ci --git   # fails if lockfile is missing, tampered, or uncommitted
- run: vigil audit verify        # fails if audit log chain is broken
- run: vigil install             # reinstalls from vigil.lock with full policy enforcement
```

> **Do not substitute `bun install` in CI.** Running `bun install` bypasses all Vigil policy checks — no age gate, no postinstall blocking, no audit log entry.

`vigil verify --ci` exits 1 if `vigil.lock` is missing or any hash mismatches. `vigil verify --git` additionally warns (and in `--ci` mode, fails) if `vigil.lock` has uncommitted local changes. Run verification **before** install in CI to catch a tampered lockfile before it can influence the build.

### Files to commit to version control

| File | Commit? | Notes |
|------|---------|-------|
| `vigil.lock` | **Yes** | Contains resolved versions and content hashes — the source of truth |
| `vigil.toml` | **Yes** | Policy configuration — changes here are auditable |
| `vigil-audit.log` | **Yes** | Append-only audit trail — git history anchors the hash chain |
| `bun.lockb` | Yes | Bun's own lockfile — keep in sync |

## What is not yet implemented

The following config options are parsed from `vigil.toml` but have no enforcement logic yet. They will silently do nothing:

- `require_provenance` — Sigstore/provenance attestation (planned)
- `typosquat_check` — typosquat detection (planned)

Other planned features not yet started:

- `vigil diff` — AST-based security diff for package updates
- CI mode strict lockfile enforcement beyond `--ci` hash checking
- Multi-ecosystem support (npm, uv, pip)

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
