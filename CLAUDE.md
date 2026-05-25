# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**mddedupe** is a high-performance duplicate file finder written in Rust. It uses parallel processing with Rayon and SHA-256 hashing to identify duplicate files in directory trees. The tool supports read-only scanning and destructive actions (move/trash/delete).

## Build & Test Commands

### Building
```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Binary location: target/release/mddedupe
```

### Testing
```bash
# Run all tests (unit + integration)
cargo test

# Run only the binary's unit tests (in main.rs)
# NOTE: this is a binary-only crate with no lib target, so `cargo test --lib`
# errors. Use `cargo test --bin mddedupe` instead.
cargo test --bin mddedupe

# Run only integration tests
cargo test --test cli

# Run a specific test
cargo test test_hash_file

# Run tests with output
cargo test -- --nocapture
```

### Linting & Formatting
```bash
# Check for common issues
cargo clippy

# Format code
cargo fmt

# Check formatting without modifying
cargo fmt --check
```

### Running
```bash
# Run in development mode
cargo run -- /path/to/directory

# Scan two or more directories at once (duplicates are found ACROSS them; the
# survivor is kept under the earliest-listed path)
cargo run -- /path/to/first /path/to/second

# Run with debug logging
RUST_LOG=debug cargo run -- /path/to/directory

# Disable progress indicators during development
MDDEDUPE_SCAN_PROGRESS_MS=0 MDDEDUPE_HASH_PROGRESS_MS=0 cargo run -- /path/to/directory
```

### `--follow-symlinks` with multiple roots (caveat)

`--follow-symlinks` across more than one supplied root is **unsupported** for
*count* accuracy. The identity safety net (collapse by `FileId`) guarantees
**safety** — the last physical copy is never deleted even when reachable through
multiple paths — but symlinks that cross between roots create ambiguous ownership
and visit-ordering, and duplicate *counts* in those pathological cross-root
setups are not guaranteed. Overlapping roots are rejected outright; non-overlapping
roots joined by cross-root symlinks are allowed but their counts are best-effort.

## Survivor Selection Feature

The tool ships with a configurable protect-then-fallback survivor selection engine. Key points for contributors:

**Default behavior (no config, no flags):** protects directories whose component name matches `0*` and files whose name matches `00-*` or `00 - *`; falls back to `oldest` for unprotected groups. Constants `DEFAULT_PROTECT_DIR`, `DEFAULT_PROTECT_NAME`, `DEFAULT_FALLBACK` in `src/main.rs` are the single source.

**New CLI flags:** `--protect-dir <GLOB>`, `--protect-name <GLOB>`, `--no-protect`, `--keep <oldest|newest|shortest|lexical>`, `--config <PATH>`.

**Config file:** `.mddedupe.toml` in the process CWD (or explicit `--config`). The `[keep]` table supports `protect-dir`, `protect-name`, `fallback`. An omitted field uses the built-in default; `[]` explicitly empties it. Typos in field names are fatal (`deny_unknown_fields`).

**Engine functions:**
- `resolve_keep_policy` — merges CLI flags + config into a `KeepPolicy`. Called once at startup; a bad glob or unreadable config is fatal before any scan.
- `select_survivors` — partitions a single hash group into survivors + victims using protect rules, then the fallback chain (`root_index → strategy key → path`).
- `build_group_plans` — calls `select_survivors` once per group and stores `GroupPlan` structs. All consumers (display, action, metrics) read these plans so they can never diverge.

**`KeepPolicy::default()`** is the neutral policy (empty GlobSets, `Lexical` fallback) — used by unit tests, not by the CLI. The CLI default is richer; see the constants above. `--no-protect` without `--keep` produces an equivalent result at runtime, but `--no-protect --keep oldest` (or any other `--keep` value) yields empty protect lists with a non-`Lexical` fallback, which is NOT `KeepPolicy::default()`.

**Glob matching** is case-insensitive, applied per single path component (not a full path fragment). `--protect-dir "photos/00*"` does not work; use `--protect-dir "00*"`.

For full behavior documentation see [docs/usage.md](./docs/usage.md#survivor-selection) and [ARCHITECTURE.md](./ARCHITECTURE.md#survivor-selection).

## Code Architecture

For detailed architecture documentation including algorithm details, key functions, testing strategy, error handling, and platform-specific code, see [ARCHITECTURE.md](./ARCHITECTURE.md).
