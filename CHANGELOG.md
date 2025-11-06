# Changelog

## 0.2.0 - 2025-11-05
### Added
- Real trash handling for the `trash` action with configurable `MDD_TRASH_DIR` override.
- New `--create-dest` flag to provision move destinations on demand and `--follow-symlinks` flag to include linked files.
- Detailed action summaries that report successes, failures, and total reclaimed size.
- Additional unit tests covering permission failures, symlink traversal, and CLI argument combinations.
- Standalone usage guide (`docs/usage.md`) and documentation for environment variables.
- Graceful Ctrl+C cancellation that cleans up progress reporting and returns exit code 130.
- Native Windows recycle bin integration for the `trash` action (Unix behaviour unchanged).
- Optional JSON summary output via `--summary-format json` for automation workflows (suppresses progress and action logs).
- `--summary-path` flag to persist either text or JSON summaries to disk (auto-creates parent directories).
- `--summary-silent` flag to suppress stdout summaries when using file-based outputs or automation pipelines.
- `--summary-only` flag to hide duplicate listings and action logs, emitting only the final summary.
- `--log-level` flag (`info`/`warn`/`error`/`none`) to control duplicate/action logging granularity.

### Changed
- Progress rendering is now resilient to broken pipes and respects quiet mode.
- Duplicate hashing skips singleton hash groups to reduce memory usage.
- Colorized output no longer depends on `ansi_term`; ANSI sequences are generated inline.

### Fixed
- Move operations now fall back to copy-and-delete across filesystems.
- Duplicate processing aggregates per-file errors instead of aborting on the first failure.
