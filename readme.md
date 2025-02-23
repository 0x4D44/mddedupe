# mddedupe - Duplicate File Finder

A high-performance command-line tool written in Rust for finding and managing duplicate files in a directory tree. The tool uses parallel processing and efficient hashing algorithms to quickly identify duplicates while providing various options for handling them.

## Features

- Fast parallel file scanning and hashing using Rayon
- SHA-256 hash-based file comparison
- Multiple duplicate handling options:
  - Move duplicates to a specified directory
  - Send duplicates to trash (simulation only in current version)
  - Permanently delete duplicates
- Human-readable size formatting
- Progress indicators during scanning and processing
- Detailed or summary reporting options
- Safety confirmations for destructive operations
- Extensive test coverage

## Installation

### Prerequisites

- Rust 1.56.0 or later
- Cargo (Rust's package manager)

### Building from Source

```bash
git clone [repository-url]
cd duplicate-file-finder
cargo build --release
```

The compiled binary will be available in `target/release/`.

## Usage

```bash
duplicate-file-finder [OPTIONS] <DIRECTORY>
```

### Arguments

- `<DIRECTORY>`: The directory to scan for duplicates

### Options

- `-a, --action <ACTION>`: Action to perform on duplicates
  - Valid values: "move", "trash", "delete"
  - If not specified, runs in read-only mode
- `-D, --dest <DEST>`: Destination directory for the move action
  - Required when action is "move"
- `-f, --force`: Force apply the action without confirmation
- `-q, --quiet`: Suppress detailed duplicate groups; show only summary
- `-h, --help`: Display help information
- `-V, --version`: Display version information

### Examples

**Scan directory in read-only mode:**
```bash
duplicate-file-finder /path/to/directory
```

**Move duplicates to a specific directory:**
```bash
duplicate-file-finder -a move -D /path/to/dest /path/to/directory
```

**Delete duplicates (with confirmation):**
```bash
duplicate-file-finder -a delete /path/to/directory
```

**Quick summary scan:**
```bash
duplicate-file-finder -q /path/to/directory
```

## How It Works

1. **Initial Scan**: The tool walks through the directory tree and groups files by size
2. **Hash Computation**: For groups with matching sizes, SHA-256 hashes are computed in parallel
3. **Duplicate Identification**: Files with identical hashes are marked as duplicates
4. **Action Execution**: If specified, the chosen action is performed on duplicate files

The tool uses a two-stage approach to minimize unnecessary hashing:
1. First pass: Group by file size (fast)
2. Second pass: Hash only files with matching sizes (compute-intensive)

## Performance Optimizations

- Parallel processing using Rayon
- 16KB buffer for file reading
- Size-based pre-filtering
- Progress indicators for long operations
- Efficient string and path handling

## Safety Features

- Read-only by default
- Confirmation prompt for destructive actions
- Force flag (-f) required for automated scripts
- First copy of each duplicate group is preserved
- Error handling for filesystem operations

## Build Dependencies

- `ansi_term`: Terminal colors and formatting
- `clap`: Command-line argument parsing
- `rayon`: Parallel computation
- `sha2`: SHA-256 hashing
- `walkdir`: Directory traversal
- `tempfile`: Temporary file handling (tests only)

## Development

### Running Tests

```bash
cargo test
```

### Running with Debug Output

```bash
RUST_LOG=debug cargo run -- /path/to/directory
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Guidelines

1. Add tests for new features
2. Update documentation as needed
3. Follow Rust formatting guidelines
4. Ensure all tests pass

## License

[Insert your chosen license here]

## Author

[Your name or organization]

## Acknowledgments

- The Rust community
- Contributors to the dependent crates