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

When performing destructive actions without `--force`, the tool pauses for confirmation. Only the victim files (unprotected non-keepers as determined by the protect-then-fallback policy) in each duplicate group are touched.

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `MDD_TRASH_DIR` | Overrides the trash destination for the `trash` action. Useful in tests or locked-down environments. | On Unix: XDG Trash (`~/.local/share/Trash/files`) or `~/.Trash`. Windows builds always use the OS recycle bin. |
| `MDDEDUPE_SCAN_PROGRESS_MS` | Controls scan-stage progress cadence in milliseconds. Set to `0` to disable periodic updates. | `1000` |
| `MDDEDUPE_HASH_PROGRESS_MS` | Controls hash-stage progress cadence in milliseconds. Set to `0` to disable periodic updates. | `500` |
| `MDDEDUPE_PROGRESS_FAIL` | Internal test hook that forces progress writers to emit simulated errors. Leave unset during normal use. | unset |

## Handling Symlinks

By default the scanner ignores symbolic links. Pass `--follow-symlinks` to hash the linked targets too. A cycle guard is in place to prevent infinite loops when links point back into previously visited directories:

```bash
mddedupe --follow-symlinks /data/archive
```

Be aware that following links can cross filesystem boundaries; cycles are detected and skipped, but deep trees can still expand traversal scope.

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

# Turn off all duplicate/action logs (summary still shown unless --summary-silent).
# Per-file action failures still emit a one-line summary to stderr so issues are not silent; add --fail-on-error to make failures non-zero exit.
mddedupe --log-level none --summary-path reports/latest.txt /data/archive

# Treat per-file failures as fatal (exit code 2)
mddedupe --action move --dest /quarantine --force --fail-on-error /data/archive
```

## Error Reporting

During move/delete/trash actions the tool aggregates per-file outcomes. On completion it prints a summary of successes plus any failures (path, size, error). Even with `--log-level none`, a concise failure line is emitted to stderr so issues are not silent. This allows the run to continue even if individual files are locked or permission-restricted.

## Exit Codes

- `0`: Completed successfully (possibly with reported per-file failures during action phase).
- `1`: CLI validation error (e.g., missing destination for `--action move`).
- `2`: Unhandled I/O or runtime failure.

## Best Practices

1. **Start in read-only mode.** Review the duplicate groups before enabling destructive actions.
2. **Quarantine before delete.** Prefer `--action move` to a dedicated directory; review contents, then purge.
3. **Leverage tests.** Use temporary directories (`tempfile` in Rust or `mktemp` in shell) when experimenting with scripts.
4. **Monitor progress.** Adjust `MDDEDUPE_*_PROGRESS_MS` variables to balance console noise and responsiveness on large trees.

## Survivor Selection

By default, mddedupe uses a **protect-then-fallback** model to decide which copy in each duplicate group is kept and which copies are acted on. This section documents every related flag, the config file format, and the resolution rules.

### Built-in convention (no config, no flags)

When you run `mddedupe <dir>` with no config file and none of the flags below, the active policy is:

- **Protect dirs:** `0*` — any directory component whose name starts with `0`
- **Protect names:** `00-*` and `00 - *` — files whose own name starts with `00-` or `00 - `
- **Fallback:** `oldest` — when no copy is protected, keep the one with the earliest modification time

This reflects the convention of naming master-copy directories `00-…` or `00 ` to signal priority.

> **Important — the protect convention is ON by default.** The `0*` glob matches any single directory component that starts with the digit zero, including `0` (a bare single-character name), `007`, `0day`, `0001-Jan`, and similar. A plain `mddedupe --action delete <dir>` run will **silently keep** duplicates under any such directory rather than deleting them. If your directory tree uses a numeric-prefix naming scheme unrelated to this convention (e.g. `0001-Jan`, `0002-Feb` photo folders), some duplicates you expect to be removed will not be. Pass `--no-protect` to disable all protect rules, or `--no-protect --keep lexical` to reproduce the original first-by-`(root_index, path)` behavior exactly.

### Selection model

For each SHA-256 hash group:

1. Every file whose path contains a directory component matching a protect-dir glob, or whose filename matches a protect-name glob, is **protected**.
2. If any file is protected: all protected copies survive; all unprotected copies are victims.
3. If every copy is protected: the group is left completely untouched — zero victims.
4. If nothing is protected: the **fallback chain** picks a single keeper (`root_index → strategy key → path`); the rest are victims.

Glob matching is **case-insensitive** and is performed against a **single path-component string**, not a multi-level path fragment. This means `--protect-dir "photos/00*"` does not work — use `--protect-dir "00*"` to match any directory component named `00-anything`, regardless of its position in the path.

### CLI flags

| Flag | Description |
|------|-------------|
| `--protect-dir <GLOB>` | Protect files under any directory whose **component name** matches this glob. Repeatable; each use adds a pattern. Passing this flag replaces the entire config/default dir list for the run. |
| `--protect-name <GLOB>` | Protect files whose **own filename** matches this glob. Repeatable; replaces the config/default name list. |
| `--no-protect` | Disable all protect rules. Uses `lexical` fallback (reproduces the original behavior). Conflicts with `--protect-dir` / `--protect-name`. An explicit `--keep` still overrides the fallback when combined with `--no-protect`. |
| `--keep <STRATEGY>` | Fallback strategy for unprotected groups. Values: `oldest`, `newest`, `shortest`, `lexical`. |
| `--config <PATH>` | Explicit path to a `.mddedupe.toml` config file. Fatal if the file is missing, unreadable, or malformed. |

`--keep` strategy meanings:

- `oldest` — keep the copy with the earliest modification time (default fallback under the built-in convention)
- `newest` — keep the copy with the latest modification time
- `shortest` — keep the copy with the fewest path components
- `lexical` — no additional key; `root_index` then `path` decide (original behavior)

### `.mddedupe.toml` config file

Place a `.mddedupe.toml` in the directory from which you invoke `mddedupe` (the process current directory) to set a standing policy. The file is auto-discovered; pass `--config <path>` to specify an explicit location.

```toml
[keep]
protect-dir  = ["0*", "originals"]   # any directory component matching these globs
protect-name = ["00-*", "00 - *"]    # any filename matching these globs
fallback     = "oldest"              # oldest | newest | shortest | lexical
```

All three fields are optional. When a field is omitted the built-in convention default applies for that field. To explicitly clear a list (disable protect for that dimension), set it to an empty array:

```toml
[keep]
protect-dir  = []          # disable dir protection; name protection uses default
fallback     = "newest"    # keep the most recently modified copy
```

An empty `[keep]` table (no fields) is valid; all three dimensions fall back to the built-in defaults. A completely absent `[keep]` table is also valid and has the same effect.

Typos in field names are fatal (`deny_unknown_fields`). A bad glob pattern is also fatal and exits non-zero, naming the offending pattern.

### Precedence / resolution order

Flags override config; config overrides the built-in convention. Each of the three dimensions (protect-dir list, protect-name list, fallback strategy) is resolved independently:

| Source checked (first wins) | protect-dir / protect-name lists | fallback strategy |
|-----------------------------|----------------------------------|-------------------|
| CLI flag (`--protect-dir` / `--protect-name`) | yes | — |
| `--keep` | — | yes (overrides all lower sources, including the `lexical` default set by `--no-protect`) |
| `--no-protect` | forces both empty | forces `lexical` (when `--keep` is not also passed) |
| `--config` or `./.mddedupe.toml` `[keep]` field | when field is present | when field is present |
| Built-in convention | `["0*"]` / `["00-*","00 - *"]` | `oldest` |

Config loading priority: `--config <path>` > `./.mddedupe.toml` (auto-discovered) > no config (built-in convention).

A missing `--config` target, a malformed TOML file, or an invalid glob pattern all cause a non-zero exit before any scanning begins.

### `KEPT (reason)` explain output

Every survivor in the duplicate listing is annotated with a reason tag:

```
/data/pix/00-keep/photo.jpg  (1.2 MB) -> KEPT (protected: dir 00-keep)
/data/pix/00-master.jpg      (1.2 MB) -> KEPT (protected: name 00-master.jpg)
/data/pix/archive/photo.jpg  (1.2 MB) -> KEPT (oldest)
/data/pix/tmp/photo.jpg      (1.2 MB) -> remove
```

- `KEPT (protected: dir <name>)` — the nearest ancestor directory component that matched the protect-dir rule
- `KEPT (protected: name <filename>)` — the filename that matched the protect-name rule
- `KEPT (oldest)` / `KEPT (newest)` / `KEPT (shortest)` / `KEPT (lexical)` — chosen by the fallback strategy

When a file matches both a dir rule and a name rule, the dir rule label is shown.

### Summary metrics (redundancy vs. removable)

The scan summary line shows two metric pairs when protect rules cause extra survivors:

```
4 files scanned, 3 duplicate files (39 bytes); 2 removable (26 bytes reclaimable), 1 protected and kept, in 0 sec.
```

- **Duplicate files / bytes** — total redundancy: `(group_size - 1)` per group, independent of policy.
- **Removable / reclaimable** — what this run would actually act on: only the victim set after protect rules are applied.

In the common case (at most one protected copy per group), the two metrics coincide and the shorter wording is used:

```
2 files scanned, 1 duplicate files (13 bytes wasted) in 0 sec.
```

## Further Topics

- See `CHANGELOG.md` for release notes.
- File an issue or PR for platform-specific enhancements (e.g., Windows recycle bin integration).
