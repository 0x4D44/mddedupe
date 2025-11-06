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

### Single-File Design
The entire application is contained in `src/main.rs` (~1800+ lines). There are no modules or separate source files. This design choice keeps related code together but requires careful navigation.

### Core Algorithm (Two-Stage Deduplication)

1. **Stage 1 - Size Grouping** (`find_duplicates_optimized_with_options`, lines 166-339):
   - Walks directory tree using `WalkDir`
   - Groups files by size in `HashMap<u64, Vec<PathBuf>>`
   - Filters groups to only those with 2+ files (candidates for hashing)
   - Shows progress: "Scanning filesystem - found N files..."

2. **Stage 2 - Parallel Hashing**:
   - Uses Rayon's `par_iter()` to hash candidate files in parallel
   - Computes SHA-256 hashes via `hash_file()` (16KB buffer, lines 141-154)
   - Groups files by hash in `HashMap<String, Vec<(PathBuf, u64)>>`
   - Spawns progress thread showing "Hashing files: processed M of N files"
   - Only groups with 2+ identical hashes are kept as duplicates

### Key Functions

- `hash_file(path)` (lines 141-154): Computes SHA-256 using 16KB buffered reads
- `find_duplicates_optimized_with_options()` (lines 166-339): Main scanning logic, returns `(duplicates_map, files_scanned, duplicate_count, wasted_bytes, elapsed)`
- `process_duplicates()` (lines 654-754): Applies move/trash/delete action to all duplicates except first in each group
- `run_app()` (lines 756-1000): Main application flow with argument parsing, confirmation prompts, and summary output
- `relocate_file()` (lines 546-565): Handles `fs::rename` with cross-device fallback via copy+sync+delete
- `get_unique_destination()` (lines 343-370): Generates `file(N).ext` names when destination collides

### Cancellation & Progress Handling

- **Ctrl+C Handling**: Global `AtomicBool CANCEL_REQUESTED` checked throughout scan/hash/process loops
- **Progress Threads**: Separate thread for hash stage updates progress every `MDDEDUPE_HASH_PROGRESS_MS` milliseconds
- **Broken Pipe Handling**: `handle_progress_result()` (lines 529-544) detects broken pipes (e.g., when piped to `head`) and silently disables progress without failing

### Testing Strategy

The codebase has extensive test coverage (~800 lines of tests in `#[cfg(test)] mod tests`):

- **Unit tests**: Individual functions like `human_readable()`, `format_duration()`, `get_unique_destination()`
- **Integration tests**: End-to-end workflows via `run_app()` with mocked stdin (using `Cursor<Vec<u8>>`)
- **CLI tests**: `tests/cli.rs` uses `assert_cmd` for black-box testing of the compiled binary
- **Environment-based test isolation**: Tests use `MDDEDUPE_SCAN_PROGRESS_MS=0` to disable progress threads
- **Mutex locking**: `progress_lock()` (lines 1066-1075) prevents concurrent progress tests from interfering

When running tests, progress is typically disabled via environment variables to avoid flaky tests and cleaner output.

### Error Handling

- **AppError enum** (lines 631-652): Domain-specific errors with `From<io::Error>` conversion
- **Aggregated failures**: `ProcessReport` struct collects per-file failures during actions without stopping execution
- **Cross-device moves**: `relocate_file()` automatically falls back to copy+delete when `fs::rename` fails with EXDEV (errno 18)
- **Graceful cancellation**: Returns `AppError::Cancelled` (exit code 130) when Ctrl+C is pressed

### Platform-Specific Code

- **Unix**: Uses XDG Trash (`~/.local/share/Trash/files`) or `~/.Trash` on macOS
- **Windows**: Uses `trash` crate for native recycle bin integration (conditional compilation)
- **Trash resolution** (lines 567-609): `resolve_trash_destination()` respects `MDD_TRASH_DIR` environment variable

## Important Environment Variables

- `MDD_TRASH_DIR`: Override trash destination for testing or custom workflows
- `MDDEDUPE_SCAN_PROGRESS_MS`: Progress update interval for scan stage (default: 1000ms, set to 0 to disable)
- `MDDEDUPE_HASH_PROGRESS_MS`: Progress update interval for hash stage (default: 500ms, set to 0 to disable)
- `MDDEDUPE_PROGRESS_FAIL`: Internal test hook for simulating progress failures (used in tests only)

## CLI Argument Structure

Uses `clap` with derive macros:
- **Required**: `directory` - Path to scan
- **Actions**: `--action {move|trash|delete}` - Defaults to read-only if omitted
- **Move options**: `--dest DIR`, `--create-dest`
- **Output control**: `--quiet`, `--summary-format {text|json}`, `--summary-path FILE`, `--summary-silent`, `--summary-only`
- **Logging**: `--log-level {info|warn|error|none}`
- **Scanning**: `--follow-symlinks`
- **Safety**: `--force` - Skip confirmation prompt

## Development Workflow

1. **Adding new features**: Most logic lives in `run_app()` or helper functions called from it
2. **Testing**: Always add both unit tests (in `#[cfg(test)]` module) and integration tests (in `tests/cli.rs`)
3. **Progress indicators**: Use `show_progress` flag and respect `quiet` mode
4. **Actions on duplicates**: Always preserve the first file in each group (sorted by path), only process `sorted_files.iter().skip(1)`

## Common Pitfalls

- **Don't forget `file.sync_all()`** after writes in tests to ensure data is flushed before assertions
- **Progress tests need locking**: Use `lock_progress()` guard to prevent concurrent progress tests
- **Set progress env vars in tests**: Always use `set_progress_env()` or manually set `MDDEDUPE_*_PROGRESS_MS=0` in tests
- **Restore permissions in Unix tests**: When modifying permissions to test errors, always restore them in cleanup for `TempDir` to delete successfully
- **Cancellation flag is global**: Call `reset_cancellation_flag()` between tests that simulate Ctrl+C

## Exit Codes

- **0**: Success (may include per-file failures during actions)
- **1**: CLI validation error or domain error (missing dest, unknown action, etc.)
- **130**: User cancellation via Ctrl+C
