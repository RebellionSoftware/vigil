# Implementation Plan: Multi-Package Manager Support (bun / npm)

## Overview

Add a `PackageRunner` trait abstraction to `vigil-core` so that `vigil-cli` commands work with either bun or npm, selected via `package_manager` in `vigil.toml`. The refactor proceeds in dependency order: errors first (everything downstream uses them), then the trait and BunRunner adaptation, then the config field, then NpmRunner, then the 4 CLI callsites.

**Spec:** `.context/specs/multi-package-manager-support.md`

## Architecture Decisions

- `RunnerFactory::create(project_dir, manager_str)` is the single entry point for creating runners — CLI commands never import `BunRunner` or `NpmRunner` directly.
- `package_manager` is validated at config-load time (fail before I/O) AND implicitly by `RunnerFactory::create` (defense in depth).
- `PackageManagerNotFound(String)` carries the manager name so errors say "npm not found" vs "bun not found" rather than a generic message.
- `NpmRunner` uses `npm install --save-exact` for `add` (equivalent to bun's `--exact`) and `npm uninstall` for `remove`. `--ignore-scripts` is fully supported by npm since v6.

---

## Phase 1: Foundation — Error Generalization

### Task 1: Generalize `BunNotFound`/`BunFailed` error variants

**Description:** Rename the two bun-specific error variants to carry the package manager name. This is the foundation for meaningful error messages when npm is configured ("npm not found" not "bun not found"). Updating `bun.rs` at the same time keeps the change atomic — nothing external is broken because `BunNotFound` and `BunFailed` are not re-exported from `lib.rs`.

**Acceptance criteria:**
- [ ] `Error::BunNotFound` → `Error::PackageManagerNotFound(String)` (carries manager name, e.g. `"bun"`)
- [ ] `Error::BunFailed { status, output }` → `Error::PackageManagerFailed { manager: String, status: i32, output: String }`
- [ ] Old variant names removed from `error.rs`
- [ ] All uses in `bun.rs` updated to pass `"bun"` as the manager name
- [ ] Error display messages updated: `"{0} not found in PATH. Please install it."` and `"{manager} exited with status {status}:\n{output}"`
- [ ] `bun.rs` test updated: `run_nonexistent_binary_returns_bun_not_found` → asserts `PackageManagerNotFound`

**Verification:**
- [ ] `cargo test -p vigil-core` — all tests pass
- [ ] `cargo build --workspace` — no warnings

**Dependencies:** None

**Files touched:**
- `crates/vigil-core/src/error.rs`
- `crates/vigil-core/src/bun.rs`

**Scope:** S

---

## Phase 2: Trait and BunRunner Adaptation

### Task 2: Define `PackageRunner` trait, adapt `BunRunner`, create `RunnerFactory`

**Description:** Create `runner.rs` with the `PackageRunner` async trait and `RunnerFactory::create()`. Adapt `BunRunner` to implement the trait (the four methods it already has — `add`, `remove`, `install`, `init` — map directly). Update `lib.rs` to export the new module and remove the direct `BunRunner` re-export (callers should go through the factory). The factory handles only `"bun"` at this stage; `"npm"` returns `Error::Config(...)` until Task 4 adds `NpmRunner`.

**Acceptance criteria:**
- [ ] `runner.rs` exists with `PackageRunner` trait (4 methods: `add`, `remove`, `install`, `init`) and `RunnerFactory::create()`
- [ ] `BunRunner` implements `PackageRunner` via `#[async_trait]`
- [ ] `RunnerFactory::create("bun", ...)` returns `Ok(Box<dyn PackageRunner>)`
- [ ] `RunnerFactory::create("npm", ...)` returns `Err(Error::Config("unknown package_manager 'npm'..."))` (temporary — resolved in Task 4)
- [ ] `RunnerFactory::create("yarn", ...)` returns `Err(Error::Config("unknown package_manager 'yarn'..."))`
- [ ] `lib.rs` exports `runner` module, re-exports `PackageRunner` and `RunnerFactory`
- [ ] `lib.rs` removes `pub use bun::BunRunner` (internal detail)
- [ ] Factory unit test: `create("bun")` succeeds (if bun is in PATH) or gracefully fails with `PackageManagerNotFound`
- [ ] Factory unit test: `create("yarn")` returns `Error::Config`

**Verification:**
- [ ] `cargo test -p vigil-core` — all tests pass
- [ ] `cargo build --workspace` — no warnings (vigil-cli will fail to compile until Task 5, but vigil-core builds clean)

**Dependencies:** Task 1

**Files touched:**
- `crates/vigil-core/src/runner.rs` (new)
- `crates/vigil-core/src/bun.rs`
- `crates/vigil-core/src/lib.rs`

**Scope:** M

---

### Task 3: Add `package_manager` field to `VigilConfig` with config-load validation

**Description:** Add `package_manager: String` at the top level of `VigilConfig` (not under `[policy]`) with a default of `"bun"`. Validate the value in `load_with_hash()` after `policy.validate()` — unknown values produce `Error::Config` before any I/O or runner creation. Add tests for the default, explicit values, and invalid values.

**Acceptance criteria:**
- [ ] `VigilConfig` has `pub package_manager: String` with `#[serde(default = "default_package_manager")]`
- [ ] `default_package_manager()` returns `"bun".to_string()`
- [ ] `load_with_hash()` rejects unknown values with `Error::Config("unknown package_manager '...' — supported values: bun, npm")`
- [ ] Valid values `"bun"` and `"npm"` pass validation
- [ ] `VigilConfig::default()` has `package_manager: "bun"`
- [ ] Tests: default is `"bun"`, explicit `"npm"` parses correctly, `"yarn"` fails at load time

**Verification:**
- [ ] `cargo test -p vigil-core` — all tests pass (126 existing + new config tests)

**Dependencies:** Task 1 (uses `Error::Config` which already exists)

**Files touched:**
- `crates/vigil-core/src/config.rs`

**Scope:** S

---

### Checkpoint: After Tasks 1–3

- [ ] `cargo test --workspace` — all tests pass
- [ ] `cargo build -p vigil-core` — clean
- [ ] The trait is defined, BunRunner implements it, errors are generalized, config field is live
- [ ] vigil-cli does not yet compile (still imports `BunRunner` directly) — expected

---

## Phase 3: NpmRunner and CLI Wiring

### Task 4: Implement `NpmRunner` and complete `RunnerFactory`

**Description:** Create `npm.rs` with `NpmRunner` implementing `PackageRunner`. The binary probe follows the same `spawn_blocking` pattern as `BunRunner::new()`. Wire `"npm"` into `RunnerFactory::create()` so it returns a real runner instead of the temporary error from Task 2. Export `npm` module from `lib.rs`.

**npm flag mapping:**
| Operation | bun | npm |
|-----------|-----|-----|
| add | `bun add --exact [--dev\|--optional] [--ignore-scripts] name@ver` | `npm install --save-exact [--save-dev\|--save-optional] [--ignore-scripts] name@ver` |
| remove | `bun remove name...` | `npm uninstall name...` |
| install | `bun install [--ignore-scripts]` | `npm install [--ignore-scripts]` |
| init | `bun init` | `npm init` |

**Acceptance criteria:**
- [ ] `npm.rs` exists with `NpmRunner` struct and `PackageRunner` implementation
- [ ] `NpmRunner::new()` probes `npm --version`; returns `PackageManagerNotFound("npm")` if absent
- [ ] All 4 trait methods implemented with correct npm flags
- [ ] `RunnerFactory::create("npm", ...)` returns `Ok(Box<NpmRunner>)`
- [ ] `RunnerFactory::create("yarn", ...)` still returns `Error::Config` (unchanged)
- [ ] `lib.rs` adds `pub mod npm`
- [ ] Test: nonexistent binary path returns `PackageManagerNotFound("npm")`

**Verification:**
- [ ] `cargo test -p vigil-core` — all tests pass

**Dependencies:** Task 2

**Files touched:**
- `crates/vigil-core/src/npm.rs` (new)
- `crates/vigil-core/src/runner.rs`
- `crates/vigil-core/src/lib.rs`

**Scope:** M

---

### Task 5: Update 4 CLI commands to use `RunnerFactory`

**Description:** Replace `BunRunner` imports and construction with `RunnerFactory::create()` in all four commands that currently call `BunRunner::new()`. The config is already loaded before the runner is created in each command, so `config.package_manager` is available at the callsite. Fix any hardcoded `"bun"` strings in user-facing output (e.g. `"Running bun init…"` → dynamic based on manager).

**Per-file changes:**
- `install.rs`: `use vigil_core::bun::BunRunner` → `use vigil_core::runner::RunnerFactory`; `BunRunner::new(...)` → `RunnerFactory::create(&project_dir, &config.package_manager)`. Variable `bun` → `runner`.
- `init.rs`: Same import/construction swap. `"Running bun init…"` → `"Running {} init…", config.package_manager`. `"bun init failed: {e}"` → `"{e}"` (error already carries manager name).
- `remove.rs`: Same import/construction swap.
- `update.rs`: Same import/construction swap.

**Acceptance criteria:**
- [ ] No `use vigil_core::bun::BunRunner` in any `vigil-cli` file
- [ ] All 4 commands use `RunnerFactory::create(&project_dir, &config.package_manager)`
- [ ] `init.rs` output says "Running npm init…" when `package_manager = "npm"` is configured
- [ ] No hardcoded `"bun"` strings in user-facing output within the 4 changed files
- [ ] All existing tests pass

**Verification:**
- [ ] `cargo build --workspace` — clean, no warnings
- [ ] `cargo test --workspace` — all tests pass

**Dependencies:** Tasks 2, 3, 4

**Files touched:**
- `crates/vigil-cli/src/commands/install.rs`
- `crates/vigil-cli/src/commands/init.rs`
- `crates/vigil-cli/src/commands/remove.rs`
- `crates/vigil-cli/src/commands/update.rs`

**Scope:** M

---

### Checkpoint: Complete

- [ ] `cargo build --workspace` — clean
- [ ] `cargo test --workspace` — all tests pass
- [ ] `vigil.toml` with `package_manager = "bun"` behaves identically to before the refactor
- [ ] `vigil.toml` with `package_manager = "yarn"` fails at startup with a clear error message
- [ ] All success criteria in the spec are met

---

## Task Order Summary

```
Task 1 (error.rs, bun.rs)        — generalize errors
    │
Task 2 (runner.rs, bun.rs, lib)  — trait + BunRunner impl + factory
Task 3 (config.rs)               ─┘ (independent of Task 2, only needs Task 1's Error::Config)
    │
[Checkpoint: vigil-core tests pass]
    │
Task 4 (npm.rs, runner.rs, lib)  — NpmRunner + complete factory
    │
Task 5 (4 CLI files)             — wire RunnerFactory into commands
    │
[Checkpoint: full build + all tests]
```

Tasks 2 and 3 are independent of each other and can be done in either order or in parallel.

## Deferred Items

- **Install URL in error messages (Task 5):** `PackageManagerNotFound` now says `"{manager} not found in PATH. Please install it."` — the old `BunNotFound` message included `https://bun.sh`. Since bun and npm have different install URLs, the right fix is in the CLI `map_err` wrappers (Task 5), where the manager is known and a URL can be appended per-manager. Do not forget when wiring the CLI commands.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| `BunNotFound`/`BunFailed` renamed — stale match arms elsewhere | Build error | Compiler catches all match arms; fix as part of Task 1 |
| `async_trait` object safety with `Box<dyn PackageRunner>` | Compile error | `async-trait` already in workspace and handles this; test compiles in Task 2 |
| npm not installed in CI — NpmRunner test can't probe real binary | Test skip | Mirror bun.rs pattern: test with fake binary path to verify error variant, not real npm behavior |
| `lib.rs` removes `pub use bun::BunRunner` — breaks external consumers | API break | vigil-core is internal to the workspace; no external consumers |
