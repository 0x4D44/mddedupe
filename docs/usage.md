# mddedupe Usage Guide

This guide complements the main README by walking through common workflows, configuration knobs, and safety practices for `mddedupe` version 0.2.0.

## Basic Scans

```bash
# Read-only duplicate scan with detailed groups
mddedupe /data/archive

# Quiet summary-only output (progress suppressed)
mddedupe --quiet /data/archive
```

## Acting on Duplicates

```bash
# Move duplicates into a quarantine directory, auto-creating it if missing
mddedupe --action move --dest /data/quarantine --create-dest /data/archive

# Delete duplicates without an interactive prompt (dangerous!)
mddedupe --action delete --force /data/archive

# Send duplicates to the trash, honouring MDD_TRASH_DIR when set
MDD_TRASH_DIR=/data/trash mddedupe --action trash --force /data/archive
```

When performing destructive actions without `--force`, the tool pauses for confirmation. Only files beyond the first entry in each duplicate group are touched.

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `MDD_TRASH_DIR` | Overrides the trash destination for the `trash` action. Useful in tests or locked-down environments. | On Unix: XDG Trash (`~/.local/share/Trash/files`) or `~/.Trash`. Windows builds always use the OS recycle bin. |
| `MDDEDUPE_SCAN_PROGRESS_MS` | Controls scan-stage progress cadence in milliseconds. Set to `0` to disable periodic updates. | `1000` |
| `MDDEDUPE_HASH_PROGRESS_MS` | Controls hash-stage progress cadence in milliseconds. Set to `0` to disable periodic updates. | `500` |
| `MDDEDUPE_PROGRESS_FAIL` | Internal test hook that forces progress writers to emit simulated errors. Leave unset during normal use. | unset |

## Handling Symlinks

By default the scanner ignores symbolic links. Pass `--follow-symlinks` to hash the linked targets too:

```bash
mddedupe --follow-symlinks /data/archive
```

Be aware that following links can cross filesystem boundaries and may re-traverse already-visited content.

## Progress Output & Piping

Progress bars are written to stdout and automatically downgrade when stdout is piped to programs such as `head`. If you need clean machine-readable output, combine `--quiet` with `--force` for non-interactive runs and parse the final summary line.

Pressing `Ctrl+C` requests cancellation: the scanner stops as soon as the current file/hash operation completes, progress threads shut down, and the process exits with code `130`.

## JSON Summary Output

For automation-friendly output, request a JSON summary:

```bash
mddedupe --summary-format json --quiet /data/archive
```

The JSON document contains the scanned directory, counts, elapsed seconds, and (when an action runs) the per-file results. Non-essential text (progress, move/delete logs) is suppressed automatically in JSON mode so the output remains machine-friendly.

## Writing Summaries to Disk

Use `--summary-path <FILE>` to persist the final summary (text or JSON) to disk. Parent directories are created as needed, and the output ends with a newline for easier scripting.

```bash
# Text summary written to file (still printed to stdout)
mddedupe --summary-path reports/2025-11-05.txt /data/archive

# JSON summary written to file (quiet mode keeps stdout clean)
mddedupe --summary-format json --quiet \
  --summary-path reports/2025-11-05.json /data/archive

# Suppress stdout summary entirely while still writing to disk
mddedupe --summary-path reports/2025-11-05.txt --summary-silent /data/archive

# Show only the final summary (no duplicate listings)
mddedupe --summary-only /data/archive

# Reduce logging without hiding the summary
mddedupe --log-level warn /data/archive

# Turn off all duplicate/action logs (summary still shown unless --summary-silent)
mddedupe --log-level none --summary-path reports/latest.txt /data/archive
```

## Error Reporting

During move/delete/trash actions the tool aggregates per-file outcomes. On completion it prints a summary of successes plus any failures (path, size, error). This allows the run to continue even if individual files are locked or permission-restricted.

## Exit Codes

- `0`: Completed successfully (possibly with reported per-file failures during action phase).
- `1`: CLI validation error (e.g., missing destination for `--action move`).
- `2`: Unhandled I/O or runtime failure.

## Best Practices

1. **Start in read-only mode.** Review the duplicate groups before enabling destructive actions.
2. **Quarantine before delete.** Prefer `--action move` to a dedicated directory; review contents, then purge.
3. **Leverage tests.** Use temporary directories (`tempfile` in Rust or `mktemp` in shell) when experimenting with scripts.
4. **Monitor progress.** Adjust `MDDEDUPE_*_PROGRESS_MS` variables to balance console noise and responsiveness on large trees.

## Further Topics

- See `CHANGELOG.md` for release notes.
- File an issue or PR for platform-specific enhancements (e.g., Windows recycle bin integration).
