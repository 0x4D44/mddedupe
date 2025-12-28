# mddedupe

## Project Overview

`mddedupe` is a high-performance, safe, and user-friendly command-line tool written in Rust for finding and managing duplicate files. It utilizes a two-stage algorithm (size grouping followed by parallel SHA-256 hashing) to achieve significant speed improvements over naive approaches.

### Key Features
*   **High Performance:** Uses size grouping and parallel processing (via `rayon`) to minimize computation.
*   **Safety:** Read-only by default, requires explicit flags for destructive actions, and includes confirmation prompts.
*   **Flexibility:** Supports moving, trashing, or deleting duplicates, with JSON output options.
*   **Cross-Platform:** Works on Linux, macOS, and Windows with platform-specific optimizations (e.g., native trash integration).

### Architecture
*   **Single-File Design:** The core logic resides entirely in `src/main.rs`.
*   **Two-Stage Algorithm:**
    1.  **Size Grouping:** Rapidly groups files by size to filter out unique files.
    2.  **Parallel Hashing:** Computes SHA-256 hashes for remaining candidates in parallel.
*   **Tech Stack:** Rust, `clap` (CLI), `rayon` (parallelism), `walkdir` (fs traversal), `sha2` (hashing).

## Building and Running

### Prerequisites
*   Rust 1.56.0 or later
*   Cargo

### Build Commands
*   **Build Release:** `cargo build --release`
*   **Install Globally:** `cargo install --path .`

### Running the Application
*   **Basic Scan:** `cargo run -- /path/to/directory`
*   **With Action:** `cargo run -- --action move --dest /path/to/quarantine /path/to/directory`
*   **Help:** `cargo run -- --help`

## Development Conventions

### Code Style
*   **Formatting:** Follow standard Rust formatting using `cargo fmt`.
*   **Linting:** Use `cargo clippy` for catching common mistakes and improving code quality.

### Testing
*   **Run All Tests:** `cargo test`
*   **Unit Tests:** `cargo test --lib`
*   **Integration Tests:** `cargo test --test cli`
*   **Test Environment:** Tests often disable progress bars using environment variables `MDDEDUPE_SCAN_PROGRESS_MS=0` and `MDDEDUPE_HASH_PROGRESS_MS=0` to avoid noise and flakiness.

### Key Files
*   `src/main.rs`: Contains the application entry point and all core logic.
*   `tests/cli.rs`: Integration tests using `assert_cmd`.
*   `ARCHITECTURE.md`: Detailed documentation of the internal design and algorithms.
*   `Cargo.toml`: Dependency and project configuration.
