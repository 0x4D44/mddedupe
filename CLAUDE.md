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

# Run only unit tests in main.rs
cargo test --lib

# Run only integration tests
cargo test --test cli

# Run a specific test
cargo test test_hash_file

# Run tests with output
cargo test -- --nocapture
```

### Running
```bash
# Run in development mode
cargo run -- /path/to/directory

# Run with debug logging
RUST_LOG=debug cargo run -- /path/to/directory

# Disable progress indicators during development
MDDEDUPE_SCAN_PROGRESS_MS=0 MDDEDUPE_HASH_PROGRESS_MS=0 cargo run -- /path/to/directory
```

## Code Architecture

For detailed architecture documentation including algorithm details, key functions, testing strategy, error handling, and platform-specific code, see [ARCHITECTURE.md](./ARCHITECTURE.md).
