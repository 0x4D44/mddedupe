# mddedupe Architecture Documentation

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

## Technology Stack

| Component | Library | Purpose |
|-----------|---------|---------|
| CLI Parsing | clap 4.x | Argument parsing with derive API |
| Parallel Processing | rayon 1.7 | Data-parallel hashing |
| Hashing | sha2 0.10 | SHA-256 cryptographic hash |
| Directory Traversal | walkdir 2.3 | Recursive filesystem scanning |
| Cancellation | ctrlc 3 | Ctrl+C signal handling |
| Serialization | serde 1.0, serde_json 1.0 | JSON output |
| Trash (Windows) | trash 3 | Recycle bin integration |

## Code Organization

- **Single-file design**: All code in `src/main.rs` (~1,800 lines)
- **Functional decomposition**: Clear separation of concerns despite single-file structure
- **Test coverage**: 91.9% line coverage, 93.2% function coverage
- **Platform abstraction**: Conditional compilation for OS-specific features

## Performance Characteristics

### Why This Is Fast

1. **Size filtering is ~1000x faster** than hashing (metadata vs. full file read)
2. **Only candidates are hashed** - if sizes differ, files cannot be identical
3. **Parallel hashing** maximizes CPU/IO utilization (6-8x speedup on 8 cores)
4. **Efficient buffering** - 16KB buffer balances syscall overhead and cache efficiency

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

## Important Environment Variables

- `MDD_TRASH_DIR`: Override trash destination for testing or custom workflows
- `MDDEDUPE_SCAN_PROGRESS_MS`: Progress update interval for scan stage (default: 1000ms, set to 0 to disable)
- `MDDEDUPE_HASH_PROGRESS_MS`: Progress update interval for hash stage (default: 500ms, set to 0 to disable)
- `MDDEDUPE_PROGRESS_FAIL`: Internal test hook for simulating progress failures (used in tests only)

## Survivor Selection

This subsection covers the protect-then-fallback system added in the configurable survivor selection feature. The engine lives in three functions: `resolve_keep_policy`, `select_survivors`, and `build_group_plans`.

### `KeepPolicy` and `FallbackStrategy`

```rust
struct KeepPolicy {
    protect_dir:  GlobSet,          // matched against each ancestor directory component
    protect_name: GlobSet,          // matched against the file's own name
    fallback:     FallbackStrategy, // oldest | newest | shortest | lexical
}
```

`KeepPolicy::default()` is the **neutral policy**: empty GlobSets and `Lexical` fallback. This reproduces the original `survivor_cmp` behavior exactly (`root_index → path`) and is what `--no-protect` (without `--keep`) activates. When `--no-protect --keep oldest` (or any other `--keep` value) is passed, the result has empty protect lists but a non-`Lexical` fallback — not `KeepPolicy::default()`. Unit tests that need the neutral policy construct it directly via `KeepPolicy::default()`.

The **CLI-resolved default** (no config file, no flags) is different: `protect-dir = ["0*"]`, `protect-name = ["00-*", "00 - *"]`, `fallback = Oldest`. These constants are defined once as `DEFAULT_PROTECT_DIR`, `DEFAULT_PROTECT_NAME`, and `DEFAULT_FALLBACK` so config resolution and any "use default for this field" branch share a single source.

Glob matching is case-insensitive (`GlobBuilder::case_insensitive(true)`) and is applied to individual component strings via `to_string_lossy`, not to full paths. A bad glob pattern causes an `AppError::InvalidGlob` exit before any scan.

### `resolve_keep_policy`

`resolve_keep_policy(args, base_dir)` builds the `KeepPolicy` for a run from CLI flags and the config file. Per-dimension merge rules (flags win):

- **protect lists** — `--no-protect` forces both empty; else a passed `--protect-dir`/`--protect-name` replaces the list; else the config field (when present); else the built-in convention default.
- **fallback** — if `--no-protect`: `--keep` if passed, else `Lexical`. Otherwise: `--keep` if passed, else the config `fallback` if present, else `DEFAULT_FALLBACK` (`Oldest`).

Config is loaded by `load_config`, which honors `--config <path>` as an explicit path (fatal if missing), then auto-discovers `./.mddedupe.toml` (silent if absent), then returns `None`. Any error — unreadable file, TOML parse failure, invalid glob — is fatal and exits non-zero before scanning.

### `select_survivors`

`select_survivors(group, policy)` partitions a single hash group into survivors and victims:

1. Each entry is tested by `protect_reason`, which checks `any_ancestor_dir_matches` (dir rule) then `file_name_matches` (name rule). The dir rule wins the explain label when both match.
2. If any entries are protected, all protected entries are survivors and all unprotected are victims. If every entry is protected, there are no victims.
3. If nothing is protected, mtime keys are read once per entry (only for `Oldest`/`Newest`; `None` for others), the entries are sorted by `fallback_cmp` (`root_index → strategy key → path`), and the first element is the sole survivor.

The function returns `(Vec<(&DuplicateEntry, SurvivorReason)>, Vec<&DuplicateEntry>)`. `SurvivorReason` (`ProtectedDir`, `ProtectedName`, `Fallback`) drives the `KEPT (…)` explain label produced by `survivor_reason_label`.

### `GroupPlan` — single source of truth

```rust
struct GroupPlan<'a> {
    hash:      &'a str,
    survivors: Vec<(&'a DuplicateEntry, SurvivorReason)>,
    victims:   Vec<&'a DuplicateEntry>,
}
```

`build_group_plans` calls `select_survivors` **exactly once per group** and stores the result. All downstream consumers — the read-only display listing, `process_duplicates` (action), and the removable/reclaimable metric computation — read these stored plans. This design guarantee means the displayed `KEPT` file, the file actually acted on, and the removable counts provably reference the same partition. Independent re-evaluations (which for `oldest`/`newest` could read a changed mtime and elect a different survivor) are impossible.

The removable metric is the sum of `GroupPlan::victim_bytes()` across all plans. The redundancy metric (`redundant_files`, `redundant_bytes`) is computed separately in `find_duplicates_in_dirs` as `Σ(group.len()-1)` before the policy is applied, so it always reflects total duplication regardless of how many survivors the policy retains. `format_scan_summary` emits the divergent wording only when `removable_files != redundant_files`.

### Protect-aware identity collapse

`collapse_group_by_identity` (called inside `find_duplicates_in_dirs`) is protect-aware: when two entries share a `FileId` (same physical file reached through multiple paths), the alias that survives the collapse is the one preferred under the current policy — a protected alias is kept over an unprotected one; when both are equal, `survivor_cmp` decides. This ensures that a file both reachable through a protected path and through an unprotected path is counted as protected, and can never be both a survivor and a victim.

## Multi-Path Scanning

`mddedupe` accepts **one or more** directories in a single run and finds
duplicates **across** all of them (e.g. `mddedupe X:\ Y:\`). The single-path
case behaves exactly as before.

- **Origin tracking**: Each file carries a `root_index` (the position of the
  supplied directory it was discovered under, 0 = first listed). Priority is
  assigned at discovery time rather than reconstructed by path-prefix matching.
- **Survivor preference (first-listed path wins)**: Within each duplicate group
  the survivor is chosen by `survivor_cmp` — lowest `root_index` first, then
  alphabetical path. The same comparator drives both the acted-on survivor in
  `process_duplicates` and the read-only display order, so they can never drift.
- **Overlap rejection** (`detect_overlap`): If one supplied path is inside
  another (or the same path is given twice), the run is rejected before any
  scanning with `AppError::OverlappingPaths` (exit 1). Detection compares
  best-effort **canonicalized** paths, so symlink/junction aliases of a root are
  caught, not just lexical nesting.
- **Identity safety net** (`collapse_group_by_identity`): After hashing — and
  **before** the `len > 1` filter and the duplicate-count/wasted-space tally —
  each hash group is collapsed by `FileId` so a single physical file appears at
  most once. Among entries sharing a `FileId`, the one preferred by `survivor_cmp`
  (lowest `root_index`, then path) is kept; an entry whose metadata cannot be
  read is treated as distinct and never dropped. This guarantees a physical file
  reachable through more than one path (symlink/junction, or a real file plus a
  `--follow-symlinks` view of itself) counts once and can never be both the
  survivor and an acted-on duplicate. The collapse touches only already-filtered
  candidate groups (tiny), so there is no hot-loop cost.
- **Hardlinks (intended Unix/Windows asymmetry)**: Because identity is the
  `FileId`, on **Unix** multiple hardlinks to one inode share a `FileId`
  (`dev`+`ino`) and collapse to a single entry — they are counted once and never
  unlinked. This is correct for a space-reclaiming deduper: hardlinks share a
  single physical extent, so deleting one link reclaims no space and removing the
  last link would destroy the only copy, keeping `wasted_bytes` honest. On
  **Windows** identity is the canonical path and each NTFS hardlink canonicalizes
  to its own path, so hardlinks are **not** collapsed and are treated as ordinary
  duplicates. This asymmetry is intentional; Windows hardlink detection
  (`GetFileInformationByHandle`) is out of scope.

## CLI Argument Structure

Uses `clap` with derive macros:
- **Required**: `directories` - One or more paths to scan (variadic positional,
  `num_args = 1..`). Duplicates are found across all supplied directories.
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
4. **Actions on duplicates**: Victims are determined by `build_group_plans` (protect-then-fallback). Iterate `GroupPlan::victims` — never re-derive the partition independently

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
