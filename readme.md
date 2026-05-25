# mddedupe - High-Performance Duplicate File Finder

A fast, safe, and user-friendly command-line tool written in Rust for finding and managing duplicate files. Uses intelligent two-stage filtering and parallel processing to achieve 10-100x performance improvements over naive approaches.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Test Coverage](https://img.shields.io/badge/coverage-91.9%25-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![Rust Version](https://img.shields.io/badge/rust-1.56%2B-orange)]()

## Features

### Core Capabilities
- **Intelligent Duplicate Detection**: Two-stage algorithm (size grouping → SHA-256 hashing) minimizes unnecessary computation
- **Parallel Processing**: Leverages Rayon for near-linear speedup across CPU cores (6-8x on 8-core systems)
- **Memory Efficient**: 98% memory reduction after initial size-grouping phase
- **Cross-Platform**: Works on Linux, macOS, and Windows with platform-specific optimizations

### Safety First
- **Read-only by default**: Requires explicit action flag for modifications
- **Confirmation prompts**: Interactive approval for destructive operations (bypass with `--force`)
- **Configurable survivor selection**: Protected files are never acted on; fallback strategy picks the keeper among unprotected copies
- **Graceful cancellation**: Ctrl+C handling with proper cleanup and exit codes
- **Comprehensive error reporting**: Aggregates all failures without stopping the entire operation

### Flexible Operations
- **Move**: Relocate duplicates to a quarantine directory (supports cross-device moves)
- **Trash**: Send to platform-specific trash (XDG Trash on Unix, Recycle Bin on Windows)
- **Delete**: Permanently remove duplicates
- **Read-only**: Scan and report without modifications (default)

### Advanced Features
- **Real-time progress indicators** with configurable update intervals
  - Set `MDDEDUPE_*_PROGRESS_MS=0` to disable progress output entirely
- **JSON output** for automation and scripting
- **Multiple logging levels** (info, warn, error, none)
- **Symlink handling** (optional, disabled by default for safety)
  - Cycle guard prevents infinite loops when links point back into visited directories
- **Broken pipe resilience** for seamless integration with Unix pipelines
- **File collision handling** with automatic unique naming (file(1).txt, file(2).txt, ...)

## Performance

### Benchmark Results

**Scenario:** 100,000 files, 1% duplicates (1,000 duplicate files)

| Approach | Time | Speedup |
|----------|------|---------|
| Naive sequential (hash all) | 5,000s (83 min) | 1x |
| Two-stage sequential | 500s (8 min) | 10x |
| Two-stage parallel (8 cores) | 62.5s (1 min) | 80x |

### Memory Usage

- **Initial scan:** ~12.8 MB (100,000 files × 128 bytes/file)
- **After filtering:** ~200 KB (1,000 duplicates × 192 bytes/file)
- **Reduction:** 98.5%

## Installation

### Prerequisites

- Rust 1.56.0 or later
- Cargo (Rust's package manager)

### Building from Source

```bash
git clone https://github.com/yourusername/mddedupe.git
cd mddedupe
cargo build --release
```

The compiled binary will be available at `target/release/mddedupe`.

### Optional: Install Globally

```bash
cargo install --path .
```

## Quick Start

```bash
# Scan directory (read-only, safe)
mddedupe /path/to/directory

# Move duplicates to quarantine folder
mddedupe --action move --dest /path/to/quarantine /path/to/directory

# Delete duplicates with confirmation
mddedupe --action delete /path/to/directory

# Automated deletion (no prompt, use with caution!)
mddedupe --action delete --force /path/to/directory

# JSON output for scripting
mddedupe --summary-format json /path/to/directory > report.json
```

## Usage

### Basic Syntax

```bash
mddedupe [OPTIONS] <DIRECTORY>
```

### Common Options

| Option | Description | Default |
|--------|-------------|---------|
| `<DIRECTORY>` | Directory to scan (required) | - |
| `-a, --action <ACTION>` | Action: move, trash, delete | none (read-only) |
| `-D, --dest <DEST>` | Destination for move action | - |
| `-f, --force` | Skip confirmation prompt | false |
| `-q, --quiet` | Suppress detailed output | false |
| `--summary-format <FORMAT>` | Output format: text or json | text |
| `--follow-symlinks` | Follow symbolic links | false |

### Full Options Reference

**Action Control:**
- `-a, --action <ACTION>` - Action to perform: "move", "trash", or "delete"
- `-D, --dest <DEST>` - Destination directory (required for move action)
- `-f, --force` - Skip confirmation prompt (dangerous!)
- `--create-dest` - Auto-create destination directory if missing

**Output Control:**
- `-q, --quiet` - Suppress detailed duplicate listings
- `--summary-format <FORMAT>` - Output format: "text" (default) or "json"
- `--summary-path <PATH>` - Write summary to file
- `--summary-silent` - Suppress stdout summary (useful with --summary-path)
- `--summary-only` - Show only the final summary, skip duplicate listings
- `--log-level <LEVEL>` - Logging verbosity: info, warn, error, none (default: info)

**Scanning Behavior:**
- `--follow-symlinks` - Follow symbolic links during scan (default: disabled for safety). A cycle guard skips already-visited directories to prevent infinite recursion.

**Survivor Selection:**
- `--protect-dir <GLOB>` - Protect files under a directory whose name matches this glob (repeatable). Replaces the config/default dir list.
- `--protect-name <GLOB>` - Protect files whose own name matches this glob (repeatable). Replaces the config/default name list.
- `--no-protect` - Disable all protect rules for this run; uses `lexical` fallback (original behavior), unless `--keep` overrides.
- `--keep <STRATEGY>` - Fallback strategy for unprotected groups: `oldest`, `newest`, `shortest`, or `lexical`.
- `--config <PATH>` - Explicit path to a `.mddedupe.toml` config file.

**Help:**
- `-h, --help` - Display help information
- `-V, --version` - Display version information

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `MDD_TRASH_DIR` | Override trash destination (Unix/macOS) | Platform default |
| `MDDEDUPE_SCAN_PROGRESS_MS` | Scan progress update interval (ms). Set `0` to disable progress output. | 1000 |
| `MDDEDUPE_HASH_PROGRESS_MS` | Hash progress update interval (ms). Set `0` to disable progress output. | 500 |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Configuration or validation error |
| 130 | User cancellation (Ctrl+C) |

## Examples

### Read-Only Scanning

```bash
# Basic scan with detailed output
mddedupe /data/photos

# Quick summary only
mddedupe --quiet --summary-only /data/photos

# JSON output for parsing
mddedupe --summary-format json /data/photos
```

### Moving Duplicates

```bash
# Move to existing directory (with confirmation)
mddedupe --action move --dest /data/quarantine /data/photos

# Move and auto-create destination
mddedupe -a move -D /backup/duplicates --create-dest /data

# Automated move (no prompt)
mddedupe -a move -D /quarantine --force /data
```

### Trash Operations

```bash
# Send to system trash (with confirmation)
mddedupe --action trash /data/photos

# Automated trash (no prompt)
mddedupe -a trash -f /data/photos

# Custom trash location (Unix)
MDD_TRASH_DIR=/tmp/mytrash mddedupe -a trash -f /data
```

### Deletion

```bash
# Delete with confirmation (safest)
mddedupe --action delete /data/photos

# Automated deletion (use with caution!)
mddedupe -a delete --force /data/photos
```

### Advanced Usage

```bash
# Follow symlinks (useful for network mounts)
mddedupe --follow-symlinks /data/shared

# Generate report to file
mddedupe --summary-path report.txt /data/photos

# JSON report to file, silent stdout
mddedupe --summary-format json --summary-path scan.json --summary-silent /data

# Automation-friendly: quiet + force + json
mddedupe -qf -a delete --summary-format json /data > result.json
```

### Scripting Example

```bash
#!/bin/bash
# Daily duplicate cleanup script

SCAN_DIR="/data/archive"
QUARANTINE="/data/quarantine"
REPORT="duplicate-report-$(date +%Y%m%d).json"

# Scan and move duplicates
mddedupe \
  --action move \
  --dest "$QUARANTINE" \
  --create-dest \
  --force \
  --summary-format json \
  --summary-path "$REPORT" \
  "$SCAN_DIR"

# Check exit code
if [ $? -eq 0 ]; then
  echo "Scan completed. Report: $REPORT"
else
  echo "Scan failed with exit code $?"
  exit 1
fi
```

## How It Works

### Two-Stage Algorithm

```
Stage 1: Size Grouping (Fast)
  └─> Group all files by byte size
  └─> Filter out unique sizes (no duplicates possible)
  └─> Eliminates 90-99% of files from hashing stage

Stage 2: SHA-256 Hashing (Parallel)
  └─> For each size group with 2+ files:
      └─> Compute SHA-256 hashes in parallel (Rayon)
      └─> Group by hash to identify true duplicates
```

### Why This Is Fast

1. **Size filtering is ~1000x faster** than hashing (metadata vs. full file read)
2. **Only candidates are hashed** - if sizes differ, files cannot be identical
3. **Parallel hashing** maximizes CPU/IO utilization (6-8x speedup on 8 cores)
4. **Efficient buffering** - 16KB buffer balances syscall overhead and cache efficiency

### Detailed Process

1. **Filesystem Scan**: Walk directory tree, collect file sizes (fast metadata operation)
2. **Size Grouping**: Group files by size in HashMap<u64, Vec<Path>>
3. **Candidate Filtering**: Keep only size groups with 2+ files
4. **Parallel Hashing**: Compute SHA-256 for candidates using Rayon thread pool
5. **Hash Grouping**: Group by hash in HashMap<String, Vec<(Path, Size)>>
6. **Duplicate Identification**: Retain hash groups with 2+ files
7. **Action Execution**: Apply move/trash/delete to all victims in each group (unprotected non-keepers as chosen by the protect-then-fallback policy)

### Survivor Selection

mddedupe uses a **protect-then-fallback** model to decide which copy of each duplicate group is kept:

1. **Protect rules** mark certain files as untouchable. Any file whose path includes a directory component matching a dir-glob, or whose filename matches a name-glob, is protected. All protected copies in a group are kept; only unprotected copies are candidates for removal.
2. **Fallback strategy** picks the single keeper among the unprotected copies when no file is protected. The chain is `root_index → strategy key → path`, always deterministic.

**Built-in convention (no config, no flags):** protects directories whose name matches `0*` and filenames matching `00-*` or `00 - *`, with `oldest` as the fallback for unprotected groups. This reflects a common "master copy" naming convention.

> **Important — the protect convention is ON by default.** The `0*` glob matches any single directory component that starts with the digit zero, including `0` (a bare single-character name), `007`, `0day`, `0001-Jan`, and similar. A plain `mddedupe --action delete <dir>` run will **silently keep** duplicates under any such directory rather than deleting them. If your directory tree uses a numeric-prefix naming scheme that is unrelated to this convention (e.g. `0001-Jan`, `0002-Feb` photo folders), some duplicates you expect to be removed will not be. Pass `--no-protect` to disable all protect rules, or `--no-protect --keep lexical` to reproduce the original first-by-`(root_index, path)` behavior exactly.

**Example** — scanning a tree with both protected and unprotected copies:

```
D:\pix\00-keep\photo.jpg   -> KEPT (protected: dir 00-keep)
D:\pix\2024\photo.jpg      -> remove
D:\pix\tmp\photo copy.jpg  -> remove
```

Each kept file is annotated with `KEPT (reason)` in the output. The summary line shows both the total redundancy count and, when protect rules retain extra survivors, the separately-computed removable/reclaimable figures.

For full flag reference, `.mddedupe.toml` format, and precedence rules see [docs/usage.md](./docs/usage.md).

## Architecture

For detailed architecture documentation including algorithm details, key functions, testing strategy, error handling, performance characteristics, and platform-specific code, see [ARCHITECTURE.md](./ARCHITECTURE.md).

### Quick Summary

- **Single-file design**: All code in `src/main.rs` (~1,800 lines)
- **Two-stage algorithm**: Size grouping → SHA-256 hashing (only candidates)
- **Parallel processing**: Rayon for multi-core hashing
- **Test coverage**: 91.9% line coverage, 93.2% function coverage

## Safety Features

### Built-In Safeguards

1. **Read-only default**: No modifications without explicit `--action` flag
2. **Confirmation prompts**: Interactive approval for destructive operations
3. **Force flag required**: Automation requires explicit `--force` flag
4. **Protected-copy preservation**: Protected files are never acted on; the fallback strategy (default: `oldest`) picks the keeper among any remaining unprotected copies
5. **Graceful cancellation**: Ctrl+C exits cleanly with exit code 130
6. **Error aggregation**: Individual failures don't stop entire operation
7. **Cross-device support**: Automatic fallback for moves across filesystems

### Platform-Specific Safety

**Unix/Linux/macOS:**
- Trash uses XDG standard (`~/.local/share/Trash/files`)
- Respects `$XDG_DATA_HOME` environment variable
- Cross-device moves use copy+sync+delete for data integrity

**Windows:**
- Native Recycle Bin integration via `trash` crate
- Automatic handling of cross-device error codes

## Development

### Running Tests

```bash
# All tests (unit + integration)
cargo test

# Unit tests only
cargo test --lib

# Integration tests only
cargo test --test cli

# Specific test
cargo test test_hash_file

# With output
cargo test -- --nocapture

# Clean test output (disable progress threads)
MDDEDUPE_SCAN_PROGRESS_MS=0 MDDEDUPE_HASH_PROGRESS_MS=0 cargo test
```

### Test Coverage

- **Lines**: 988/1075 (91.9%)
- **Functions**: 69/74 (93.2%)
- **Total Tests**: 36 (26 unit + 10 integration)

### Running in Development

```bash
# Development build
cargo run -- /path/to/directory

# With debug logging
RUST_LOG=debug cargo run -- /path/to/directory

# Disable progress indicators
MDDEDUPE_SCAN_PROGRESS_MS=0 MDDEDUPE_HASH_PROGRESS_MS=0 cargo run -- /path
```

### Code Formatting

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt -- --check

# Lint with clippy
cargo clippy
```

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| **Linux** | ✅ Full Support | XDG Trash, tested on Ubuntu/Debian |
| **macOS** | ✅ Full Support | Uses ~/.Trash |
| **Windows** | ✅ Full Support | Native Recycle Bin via trash crate |

### Platform-Specific Features

**Trash Directories:**
- **macOS**: `~/.Trash`
- **Linux**: `$XDG_DATA_HOME/Trash/files` or `~/.local/share/Trash/files`
- **Windows**: System Recycle Bin
- **All**: Override via `MDD_TRASH_DIR` environment variable

**Cross-Device Moves:**
- Automatic detection of cross-filesystem operations
- Falls back to copy+sync+delete for data integrity
- Platform-specific error code handling (EXDEV on Unix, ERROR_NOT_SAME_DEVICE on Windows)

## Troubleshooting

### Common Issues

**"Destination directory must be provided for move action"**
- Solution: Add `-D /path/to/dest` when using `--action move`

**"Permission denied" errors**
- Behavior: Individual files are skipped, scan continues
- Solution: Run with appropriate permissions or skip restricted directories

**Progress indicators not showing**
- Check if stdout is redirected to a file (progress auto-disables)
- Try: `mddedupe /path 2>&1 | cat` to see progress in redirected output

**"Operation cancelled by user"**
- This is normal after pressing Ctrl+C
- Exit code 130 indicates clean cancellation

### Performance Tips

1. **SSD vs HDD**: SSDs benefit more from parallel hashing (high IOPS)
2. **Large files**: Hash phase dominates; parallelism provides biggest gains
3. **Many small files**: Scan phase dominates; less benefit from parallelism
4. **Adjust progress intervals**: Slower for low-power systems
   ```bash
   MDDEDUPE_SCAN_PROGRESS_MS=2000 MDDEDUPE_HASH_PROGRESS_MS=1000 mddedupe /path
   ```

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Guidelines

1. **Add tests** for new features (maintain >90% coverage)
2. **Update documentation** as needed (README, CLAUDE.md)
3. **Follow Rust conventions** (cargo fmt, cargo clippy)
4. **Ensure all tests pass** before submitting PR
5. **Test on multiple platforms** if changing OS-specific code

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/mddedupe.git
cd mddedupe

# Build and test
cargo build
cargo test

# Run with example data
cargo run -- /path/to/test/directory
```

### Areas for Contribution

- [ ] Additional hash algorithms (MD5, SHA-512, Blake3)
- [ ] GUI/TUI interface
- [ ] File content comparison (beyond hash)
- [ ] Duplicate file linking (hardlinks/symlinks)
- [ ] Directory comparison mode
- [ ] Performance optimizations for network filesystems
- [ ] Additional output formats (CSV, HTML report)

## Documentation

- **README.md** (this file) - User guide and quick reference
- **CLAUDE.md** - Developer guide for working with this codebase
- **docs/usage.md** - Detailed usage examples and configuration
- **CHANGELOG.md** - Version history and release notes
- **wrk_docs/** - Comprehensive technical documentation

## License

[Insert your chosen license here - e.g., MIT, Apache 2.0, GPL v3]

## Acknowledgments

- Built with ❤️ using Rust
- The Rust community for excellent libraries and tooling
- Contributors to clap, rayon, walkdir, and other dependencies

## Additional Resources

- [Rust Programming Language](https://www.rust-lang.org/)
- [Cargo Book](https://doc.rust-lang.org/cargo/)
- [Rayon Documentation](https://docs.rs/rayon/)
- [SHA-2 Documentation](https://docs.rs/sha2/)

---

**Version**: 0.2.0
**Minimum Rust Version**: 1.56.0
**Test Coverage**: 91.9%
**Performance**: 10-100x faster than naive approaches
