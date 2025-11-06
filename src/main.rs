use clap::{Parser, ValueEnum};
use ctrlc;
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Once, OnceLock};
use std::time::{Duration, Instant};
use walkdir::WalkDir;

static CANCEL_REQUESTED: AtomicBool = AtomicBool::new(false);
static CTRL_C_ONCE: Once = Once::new();
static CTRL_C_ERROR: OnceLock<String> = OnceLock::new();

/// A tool to scan a directory tree and identify duplicate files.
/// By default the tool runs in read‑only mode.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory to scan
    directory: PathBuf,

    /// Action to perform on duplicates: "move", "trash" or "delete". If not specified the tool is read‑only.
    #[arg(short = 'a', long)]
    action: Option<String>,

    /// Destination directory for the move action (required if action is "move")
    #[arg(short = 'D', long)]
    dest: Option<PathBuf>,

    /// Force apply the action without confirmation (dangerous!)
    #[arg(short = 'f', long)]
    force: bool,

    /// Suppress displaying detailed duplicate groups; only show summary information.
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Create the destination directory if it does not exist (only valid with --action move).
    #[arg(long, requires = "action")]
    create_dest: bool,

    /// Follow symbolic links when scanning directories.
    #[arg(long)]
    follow_symlinks: bool,

    /// Summary format to emit after processing.
    #[arg(long, value_enum, default_value = "text")]
    summary_format: SummaryFormat,

    /// Optional path to write the final summary output.
    #[arg(long)]
    summary_path: Option<PathBuf>,

    /// Suppress printing the final summary lines to stdout (file/JSON output still generated).
    #[arg(long)]
    summary_silent: bool,

    /// Suppress detailed duplicate listings and action logs, leaving only the final summary output.
    #[arg(long)]
    summary_only: bool,

    /// Logging verbosity for duplicate listings and action progress.
    #[arg(long, value_enum, default_value = "info")]
    log_level: LogLevel,
}

/// Converts a file size in bytes to a human‐readable string with appropriate units.
fn human_readable(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Formats a Duration into a human‐readable string.
fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let mins = secs / 60;
    let secs = secs % 60;
    if mins > 0 {
        format!("{} min {} sec", mins, secs)
    } else {
        format!("{} sec", secs)
    }
}

fn ansi_fixed(code: u8, text: impl AsRef<str>) -> String {
    format!("\x1b[38;5;{}m{}\x1b[0m", code, text.as_ref())
}

fn ansi_rgb(r: u8, g: u8, b: u8, text: impl AsRef<str>) -> String {
    format!("\x1b[38;2;{};{};{}m{}\x1b[0m", r, g, b, text.as_ref())
}

fn cancellation_requested() -> bool {
    CANCEL_REQUESTED.load(Ordering::SeqCst)
}

fn reset_cancellation_flag() {
    CANCEL_REQUESTED.store(false, Ordering::SeqCst);
}

const DEFAULT_SCAN_PROGRESS_MS: u64 = 1_000;
const DEFAULT_HASH_PROGRESS_MS: u64 = 500;

fn read_duration_from_env(var: &str, default_ms: u64) -> Duration {
    env::var(var)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(default_ms))
}

fn scan_progress_interval() -> Duration {
    read_duration_from_env("MDDEDUPE_SCAN_PROGRESS_MS", DEFAULT_SCAN_PROGRESS_MS)
}

fn hash_progress_sleep() -> Duration {
    read_duration_from_env("MDDEDUPE_HASH_PROGRESS_MS", DEFAULT_HASH_PROGRESS_MS)
}

/// Computes the SHA‑256 hash of a file by reading it in chunks.
/// Uses a 16‑KB buffer for improved I/O performance.
fn hash_file(path: &Path) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::with_capacity(16 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Scans the directory tree, groups files by size, and then for each group with more than one file,
/// computes the file hash in parallel. While hashing, a progress indicator shows how many candidate
/// files have been processed (on a single line in-place).
///
/// Returns:
/// - A map from hash to a vector of (file path, file size)
/// - The total number of files scanned
/// - The duplicate count (excluding the first file in each duplicate group)
/// - The total wasted space (sum of sizes for duplicate files)
/// - The elapsed time
fn find_duplicates_optimized_with_options(
    dir: &Path,
    emit_text: bool,
    show_progress: bool,
    follow_symlinks: bool,
) -> io::Result<(
    HashMap<String, Vec<(PathBuf, u64)>>,
    usize,
    usize,
    u64,
    Duration,
)> {
    let start = Instant::now();
    let mut size_map: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    let mut scanned_files = 0usize;
    let mut last_update = Instant::now();
    let scan_interval = scan_progress_interval();
    let progress_allowed = Arc::new(AtomicBool::new(show_progress));

    // Stage 1: Walk the directory and group files by their size.
    for entry in WalkDir::new(dir).follow_links(follow_symlinks) {
        if cancellation_requested() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "filesystem scan cancelled",
            ));
        }
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("Error reading entry: {}", e);
                continue;
            }
        };
        if entry.file_type().is_file() {
            scanned_files += 1;
            if let Ok(metadata) = entry.metadata() {
                size_map
                    .entry(metadata.len())
                    .or_default()
                    .push(entry.path().to_path_buf());
            }
        }
        if show_progress
            && progress_allowed.load(Ordering::SeqCst)
            && last_update.elapsed() >= scan_interval
        {
            let message = format!("\rScanning filesystem - found {} files...", scanned_files);
            handle_progress_result(write_progress_line(&message), &progress_allowed)?;
            last_update = Instant::now();
        }
    }

    if emit_text {
        if show_progress {
            let prefix = if progress_allowed.load(Ordering::SeqCst) {
                "\r"
            } else {
                ""
            };
            let message = format!(
                "{}Filesystem scan complete - found {} files.\n",
                prefix, scanned_files
            );
            handle_progress_result(write_progress_line(&message), &progress_allowed)?;
        } else {
            let message = format!(
                "Filesystem scan complete - found {} files.\n",
                scanned_files
            );
            handle_progress_result(write_progress_line(&message), &progress_allowed)?;
        }
    }

    // Stage 2: Process candidate groups.
    let candidate_groups: Vec<(u64, Vec<PathBuf>)> = size_map
        .into_iter()
        .filter(|(_, files)| files.len() > 1)
        .collect();
    let candidate_total: usize = candidate_groups.iter().map(|(_, files)| files.len()).sum();

    let candidate_processed = Arc::new(AtomicUsize::new(0));
    let hash_sleep = hash_progress_sleep();

    let progress_handle = if show_progress && candidate_total > 0 {
        let candidate_processed_clone = candidate_processed.clone();
        let progress_allowed_clone = progress_allowed.clone();
        Some(std::thread::spawn(move || {
            loop {
                if !progress_allowed_clone.load(Ordering::SeqCst) {
                    break;
                }
                if cancellation_requested() {
                    break;
                }
                let processed = candidate_processed_clone.load(Ordering::Relaxed);
                let message = format!(
                    "\rHashing files: processed {} of {} files",
                    processed, candidate_total
                );
                if let Err(err) =
                    handle_progress_result(write_progress_line(&message), &progress_allowed_clone)
                {
                    eprintln!("Error writing hashing progress: {}", err);
                    break;
                }
                if processed >= candidate_total {
                    break;
                }
                std::thread::sleep(hash_sleep);
            }
            if progress_allowed_clone.load(Ordering::SeqCst) {
                let _ = write_progress_line("\n");
            }
        }))
    } else {
        None
    };

    let mut duplicates: HashMap<String, Vec<(PathBuf, u64)>> = HashMap::new();
    for (size, files) in candidate_groups {
        if cancellation_requested() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "hashing cancelled",
            ));
        }
        let hash_results: Vec<(PathBuf, String)> = files
            .into_par_iter()
            .filter_map(|path| {
                if cancellation_requested() {
                    return None;
                }
                candidate_processed.fetch_add(1, Ordering::Relaxed);
                match hash_file(&path) {
                    Ok(hash) => Some((path, hash)),
                    Err(e) => {
                        eprintln!("Error hashing {}: {}", path.display(), e);
                        None
                    }
                }
            })
            .collect();

        for (path, hash) in hash_results {
            duplicates.entry(hash).or_default().push((path, size));
        }
    }

    if let Some(handle) = progress_handle {
        let _ = handle.join();
    }

    if cancellation_requested() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "scan cancelled"));
    }

    duplicates.retain(|_, group| group.len() > 1);

    let mut duplicate_count = 0;
    let mut wasted_space = 0;
    for group in duplicates.values() {
        duplicate_count += group.len() - 1;
        wasted_space += group.iter().skip(1).map(|(_, size)| *size).sum::<u64>();
    }
    let elapsed = start.elapsed();
    Ok((
        duplicates,
        scanned_files,
        duplicate_count,
        wasted_space,
        elapsed,
    ))
}

/// Returns a unique destination path for moving a file. If a file with the given name
/// exists in the destination directory, this function appends a counter to the filename.
fn get_unique_destination(dest: &Path, file_name: &OsStr) -> PathBuf {
    let initial_dest = dest.join(file_name);
    if !initial_dest.exists() {
        return initial_dest;
    }
    let stem = Path::new(file_name)
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let ext = Path::new(file_name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let mut counter = 1;
    loop {
        let new_name = if ext.is_empty() {
            format!("{}({})", stem, counter)
        } else {
            format!("{}({}).{}", stem, counter, ext)
        };
        let new_dest = dest.join(new_name);
        if !new_dest.exists() {
            return new_dest;
        }
        counter += 1;
    }
}

/// Specifies the action to be performed on duplicates.
enum DuplicateAction {
    Move(PathBuf),
    Trash,
    Delete,
}

#[derive(Copy, Clone, Debug, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum SummaryFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum LogLevel {
    Info,
    Warn,
    Error,
    None,
}

#[derive(Clone, Serialize)]
struct FileActionFailure {
    path: PathBuf,
    size: u64,
    error: String,
}

#[derive(Clone, Serialize)]
struct ProcessReport {
    total_candidates: usize,
    successes: usize,
    total_size_processed: u64,
    failures: Vec<FileActionFailure>,
}

impl ProcessReport {
    fn new(total_candidates: usize) -> Self {
        Self {
            total_candidates,
            successes: 0,
            total_size_processed: 0,
            failures: Vec::new(),
        }
    }

    fn record_success(&mut self, size: u64) {
        self.successes += 1;
        self.total_size_processed += size;
    }

    fn record_failure(&mut self, path: &Path, size: u64, err: impl ToString) {
        self.failures.push(FileActionFailure {
            path: path.to_path_buf(),
            size,
            error: err.to_string(),
        });
    }
}

#[derive(Serialize)]
struct JsonSummary {
    directory: String,
    scanned_files: usize,
    duplicate_files: usize,
    duplicate_wasted_bytes: u64,
    elapsed_seconds: f64,
    follow_symlinks: bool,
    quiet: bool,
    summary_format: SummaryFormat,
    action: Option<JsonActionSummary>,
}

#[derive(Serialize)]
struct JsonActionSummary {
    action: String,
    total_candidates: usize,
    successes: usize,
    total_size_processed_bytes: u64,
    failures: Vec<FileActionFailure>,
}

fn is_cross_device_error(err: &io::Error) -> bool {
    match err.raw_os_error() {
        Some(code) if code == 18 => true, // POSIX EXDEV
        Some(code) if code == 17 => true, // Windows ERROR_NOT_SAME_DEVICE
        _ => false,
    }
}

fn is_broken_pipe(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::BrokenPipe {
        return true;
    }
    matches!(err.raw_os_error(), Some(32) | Some(109))
}

fn write_progress_line(message: &str) -> io::Result<()> {
    if let Ok(mode) = env::var("MDDEDUPE_PROGRESS_FAIL") {
        match mode.as_str() {
            "broken_pipe" => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "simulated broken pipe",
                ))
            }
            "io_error" => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "simulated progress failure",
                ))
            }
            "cancel" => {
                CANCEL_REQUESTED.store(true, Ordering::SeqCst);
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "simulated cancellation",
                ));
            }
            _ => {}
        }
    }
    let mut stdout = io::stdout();
    stdout.write_all(message.as_bytes())?;
    stdout.flush()
}

fn write_summary_to_path(path: &Path, contents: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut data = contents.to_string();
    if !data.ends_with('\n') {
        data.push('\n');
    }
    fs::write(path, data)
}

fn install_ctrlc_handler() -> Result<(), AppError> {
    CTRL_C_ONCE.call_once(|| {
        if let Err(err) = ctrlc::set_handler(|| {
            CANCEL_REQUESTED.store(true, Ordering::SeqCst);
        }) {
            let _ = CTRL_C_ERROR.set(err.to_string());
        }
    });

    if let Some(err) = CTRL_C_ERROR.get() {
        return Err(AppError::CtrlCSetup(err.clone()));
    }

    Ok(())
}

fn handle_progress_result(
    result: io::Result<()>,
    progress_allowed: &Arc<AtomicBool>,
) -> Result<(), io::Error> {
    match result {
        Ok(()) => Ok(()),
        Err(err) => {
            if is_broken_pipe(&err) {
                progress_allowed.store(false, Ordering::SeqCst);
                Ok(())
            } else {
                Err(err)
            }
        }
    }
}

fn relocate_file(src: &Path, dest: &Path) -> io::Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::rename(src, dest) {
        Ok(_) => Ok(()),
        Err(err) if is_cross_device_error(&err) => match fs::copy(src, dest) {
            Ok(_) => {
                let file = fs::File::open(dest)?;
                file.sync_all()?;
                fs::remove_file(src)
            }
            Err(copy_err) => {
                let _ = fs::remove_file(dest);
                Err(copy_err)
            }
        },
        Err(err) => Err(err),
    }
}

fn resolve_trash_destination() -> io::Result<PathBuf> {
    if let Ok(custom) = env::var("MDD_TRASH_DIR") {
        let dir = PathBuf::from(custom);
        fs::create_dir_all(&dir)?;
        return Ok(dir);
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = env::var("HOME") {
            let dir = PathBuf::from(home).join(".Trash");
            fs::create_dir_all(&dir)?;
            return Ok(dir);
        }
    }

    #[cfg(target_family = "unix")]
    {
        if let Ok(xdg) = env::var("XDG_DATA_HOME") {
            let dir = PathBuf::from(xdg).join("Trash").join("files");
            fs::create_dir_all(&dir)?;
            return Ok(dir);
        }
        if let Ok(home) = env::var("HOME") {
            let dir = PathBuf::from(home).join(".local/share/Trash/files");
            fs::create_dir_all(&dir)?;
            return Ok(dir);
        }
    }

    #[cfg(target_os = "windows")]
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Trash action is not supported on Windows in this build",
        ));
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Unable to determine trash destination",
    ))
}

fn send_to_trash(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        trash::delete(path).map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    }

    #[cfg(not(windows))]
    {
        let file_name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid file name"))?;
        let trash_dir = resolve_trash_destination()?;
        let mut dest_path = trash_dir.join(file_name);
        if dest_path.exists() {
            dest_path = get_unique_destination(&trash_dir, file_name);
        }
        relocate_file(path, &dest_path)
    }
}

#[derive(Debug)]
enum AppError {
    Io(io::Error),
    MissingMoveDestination,
    CreateDestRequiresMove,
    MoveDestinationNotDirectory(PathBuf),
    MoveDestinationMissing(PathBuf),
    MoveDestinationCreateFailed(PathBuf, io::Error),
    CtrlCSetup(String),
    Cancelled,
    UnknownAction(String),
}

impl From<io::Error> for AppError {
    fn from(err: io::Error) -> Self {
        if err.kind() == io::ErrorKind::Interrupted {
            AppError::Cancelled
        } else {
            AppError::Io(err)
        }
    }
}

/// Processes duplicates by applying the selected action to every file in each duplicate group except the first.
/// For each file processed, updated status information is printed and aggregated into a report.
fn process_duplicates(
    duplicates: &HashMap<String, Vec<(PathBuf, u64)>>,
    action: &DuplicateAction,
    info_logs: bool,
    error_logs: bool,
) -> ProcessReport {
    // Compute the overall number of duplicate files (excluding the first copy in each group)
    let overall_total: usize = duplicates
        .values()
        .filter(|v| v.len() > 1)
        .map(|v| v.len() - 1)
        .sum();
    let mut report = ProcessReport::new(overall_total);

    for (hash, files) in duplicates {
        if files.len() <= 1 {
            continue;
        }
        let mut sorted_files = files.clone();
        sorted_files.sort_by(|(path_a, _), (path_b, _)| path_a.cmp(path_b));
        if info_logs {
            println!(
                "{}",
                ansi_fixed(8, format!("Duplicate group (hash: {}):", hash))
            );
            for (i, (path, size)) in sorted_files.iter().enumerate() {
                println!(
                    "  {}: {} ({})",
                    i + 1,
                    path.display(),
                    human_readable(*size)
                );
            }
        }

        // Process duplicate group: skip the first file.
        for (path, size) in sorted_files.iter().skip(1) {
            if cancellation_requested() {
                return report;
            }
            let outcome = match action {
                DuplicateAction::Move(dest) => {
                    let file_name = match path.file_name() {
                        Some(name) => name,
                        None => {
                            let err = "Invalid file name";
                            if error_logs {
                                eprintln!("Error processing {}: {}", path.display(), err);
                            }
                            report.record_failure(path, *size, err);
                            continue;
                        }
                    };
                    let mut dest_path = dest.join(file_name);
                    if dest_path.exists() {
                        dest_path = get_unique_destination(dest, file_name);
                    }
                    if info_logs {
                        println!("Moving {} to {}", path.display(), dest_path.display());
                    }
                    relocate_file(path, &dest_path)
                }
                DuplicateAction::Trash => {
                    if info_logs {
                        println!("Sending {} to trash", path.display());
                    }
                    send_to_trash(path)
                }
                DuplicateAction::Delete => {
                    if info_logs {
                        println!("Permanently deleting {}", path.display());
                    }
                    fs::remove_file(path)
                }
            };

            match outcome {
                Ok(()) => {
                    report.record_success(*size);
                    if info_logs {
                        println!(
                            "Status: Processed {} of {} duplicate files (total size processed: {})",
                            report.successes,
                            report.total_candidates,
                            human_readable(report.total_size_processed)
                        );
                    }
                }
                Err(err) => {
                    if error_logs {
                        eprintln!("Error processing {}: {}", path.display(), err);
                    }
                    report.record_failure(path, *size, err);
                }
            }
        }
    }
    report
}

fn run_app<R: BufRead>(args: Args, mut input: R) -> Result<(), AppError> {
    install_ctrlc_handler()?;
    reset_cancellation_flag();

    let summary_stdout = args.summary_format == SummaryFormat::Text && !args.summary_silent;
    let log_output = !args.summary_only && !args.quiet && matches!(args.log_level, LogLevel::Info);
    let warn_logs = !args.summary_only
        && !args.quiet
        && matches!(args.log_level, LogLevel::Info | LogLevel::Warn);
    let error_logs = matches!(
        args.log_level,
        LogLevel::Info | LogLevel::Warn | LogLevel::Error
    );
    let show_progress = log_output && !args.quiet;
    let mut summary_lines: Vec<String> = Vec::new();

    if args.create_dest
        && !matches!(args.action.as_deref(), Some(action) if action.eq_ignore_ascii_case("move"))
    {
        return Err(AppError::CreateDestRequiresMove);
    }

    let mut move_destination: Option<PathBuf> = None;
    let mut json_action_report: Option<ProcessReport> = None;
    let mut json_summary_output: Option<String> = None;
    if let Some(action_str) = args.action.as_deref() {
        if action_str.eq_ignore_ascii_case("move") {
            let dest_path = args.dest.clone().ok_or(AppError::MissingMoveDestination)?;

            if dest_path.exists() {
                if !dest_path.is_dir() {
                    return Err(AppError::MoveDestinationNotDirectory(dest_path));
                }
            } else if args.create_dest {
                fs::create_dir_all(&dest_path)
                    .map_err(|err| AppError::MoveDestinationCreateFailed(dest_path.clone(), err))?;
            } else {
                return Err(AppError::MoveDestinationMissing(dest_path));
            }

            move_destination = Some(dest_path);
        }
    } else if args.create_dest {
        return Err(AppError::CreateDestRequiresMove);
    }

    if summary_stdout {
        println!(
            "Starting duplicate scan in directory: {}",
            args.directory.display()
        );
    }

    let (duplicates, scanned, duplicate_count, wasted, elapsed) =
        find_duplicates_optimized_with_options(
            &args.directory,
            summary_stdout,
            show_progress,
            args.follow_symlinks,
        )?;
    if summary_stdout {
        println!(
            "Duplicate scan completed in {}. {} files scanned, {} duplicates found ({} wasted).",
            format_duration(elapsed),
            scanned,
            duplicate_count,
            human_readable(wasted)
        );
    }

    if log_output {
        let mut groups: Vec<(&String, &Vec<(PathBuf, u64)>)> = duplicates
            .iter()
            .filter(|(_, group)| group.len() > 1)
            .collect();
        groups.sort_by_key(|(_, group)| group.iter().skip(1).map(|(_, size)| *size).sum::<u64>());
        for (hash, group) in groups {
            println!(
                "{}",
                ansi_fixed(8, format!("Duplicate group (hash: {}):", hash))
            );
            for (path, size) in group {
                println!("  {} ({})", path.display(), human_readable(*size));
            }
        }
        println!();
    }

    let summary_plain = format!(
        "Duplicate scan summary: {} files scanned, {} duplicates found ({} wasted) in {}.",
        scanned,
        duplicate_count,
        human_readable(wasted),
        format_duration(elapsed)
    );
    summary_lines.push(summary_plain.clone());
    if summary_stdout {
        println!(
            "{} {}",
            ansi_rgb(173, 216, 230, "Duplicate scan summary:"),
            ansi_rgb(
                255,
                255,
                224,
                format!(
                    "{} files scanned, {} duplicates found ({} wasted) in {}.",
                    scanned,
                    duplicate_count,
                    human_readable(wasted),
                    format_duration(elapsed)
                )
            )
        );
    }

    let selected_action = args.action.as_ref().map(|value| value.to_lowercase());
    let action_kind = if args.summary_format == SummaryFormat::Json {
        selected_action.clone()
    } else {
        None
    };

    if let Some(action_str) = selected_action {
        let action = match action_str.as_str() {
            "move" => {
                let dest = move_destination
                    .clone()
                    .ok_or(AppError::MissingMoveDestination)?;
                DuplicateAction::Move(dest)
            }
            "trash" => DuplicateAction::Trash,
            "delete" => DuplicateAction::Delete,
            other => return Err(AppError::UnknownAction(other.to_string())),
        };

        if !args.force {
            print!(
                "WARNING: This action will modify the filesystem. Do you wish to proceed? (y/N): "
            );
            io::stdout().flush()?;
            let mut confirmation = String::new();
            input.read_line(&mut confirmation)?;
            if !confirmation.trim().eq_ignore_ascii_case("y") {
                println!("Operation cancelled.");
                return Ok(());
            }
        }

        let report = process_duplicates(&duplicates, &action, log_output, error_logs);

        if cancellation_requested() {
            return Err(AppError::Cancelled);
        }

        if args.summary_format == SummaryFormat::Json {
            json_action_report = Some(report.clone());
        }

        if summary_stdout {
            println!(
                "Operation complete. Successes: {} / {}, total size processed: {}.",
                report.successes,
                report.total_candidates,
                human_readable(report.total_size_processed)
            );
        }
        summary_lines.push(format!(
            "Operation complete. Successes: {} / {}, total size processed: {}.",
            report.successes,
            report.total_candidates,
            human_readable(report.total_size_processed)
        ));
        if !report.failures.is_empty() {
            if warn_logs {
                eprintln!("The following files could not be processed:");
                for failure in &report.failures {
                    eprintln!(
                        "  {} ({}): {}",
                        failure.path.display(),
                        human_readable(failure.size),
                        failure.error
                    );
                }
            }
            for failure in &report.failures {
                summary_lines.push(format!(
                    "Failure: {} ({}): {}",
                    failure.path.display(),
                    human_readable(failure.size),
                    failure.error
                ));
            }
        }
    } else {
        if summary_stdout {
            println!("No action specified; running in read-only mode.");
        }
        summary_lines.push("No action specified; running in read-only mode.".to_string());
    }

    if args.summary_format == SummaryFormat::Json {
        let action_summary = action_kind.as_ref().and_then(|kind| {
            json_action_report.take().map(|report| JsonActionSummary {
                action: kind.clone(),
                total_candidates: report.total_candidates,
                successes: report.successes,
                total_size_processed_bytes: report.total_size_processed,
                failures: report.failures,
            })
        });

        let json_summary = JsonSummary {
            directory: args.directory.display().to_string(),
            scanned_files: scanned,
            duplicate_files: duplicate_count,
            duplicate_wasted_bytes: wasted,
            elapsed_seconds: elapsed.as_secs_f64(),
            follow_symlinks: args.follow_symlinks,
            quiet: args.quiet,
            summary_format: args.summary_format,
            action: action_summary,
        };

        let json_output = serde_json::to_string_pretty(&json_summary)
            .map_err(|err| AppError::Io(io::Error::new(io::ErrorKind::Other, err.to_string())))?;
        json_summary_output = Some(json_output.clone());
        println!("{}", json_output);
    }

    if cancellation_requested() {
        return Err(AppError::Cancelled);
    }

    if let Some(path) = &args.summary_path {
        let contents = match args.summary_format {
            SummaryFormat::Json => json_summary_output
                .clone()
                .unwrap_or_else(|| String::from("{}")),
            SummaryFormat::Text => summary_lines.join("\n"),
        };
        write_summary_to_path(path, &contents).map_err(AppError::Io)?;
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let stdin = io::stdin();
    let stdin_lock = stdin.lock();
    match run_app(args, stdin_lock) {
        Ok(()) => Ok(()),
        Err(AppError::Io(err)) => Err(err),
        Err(AppError::MissingMoveDestination) => {
            eprintln!("Destination directory must be provided for move action.");
            process::exit(1);
        }
        Err(AppError::CreateDestRequiresMove) => {
            eprintln!("--create-dest can only be used together with --action move.");
            process::exit(1);
        }
        Err(AppError::MoveDestinationNotDirectory(path)) => {
            eprintln!("Destination path must be a directory: {}", path.display());
            process::exit(1);
        }
        Err(AppError::MoveDestinationMissing(path)) => {
            eprintln!(
                "Destination directory {} does not exist (use --create-dest to create it).",
                path.display()
            );
            process::exit(1);
        }
        Err(AppError::MoveDestinationCreateFailed(path, err)) => {
            eprintln!(
                "Failed to create destination directory {}: {}",
                path.display(),
                err
            );
            process::exit(1);
        }
        Err(AppError::CtrlCSetup(err)) => {
            eprintln!("Failed to install Ctrl+C handler: {}", err);
            process::exit(1);
        }
        Err(AppError::Cancelled) => {
            eprintln!("Operation cancelled by user.");
            process::exit(130);
        }
        Err(AppError::UnknownAction(action)) => {
            eprintln!(
                "Unknown action: {}. Valid options are move, trash or delete.",
                action
            );
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::ffi::OsStr;
    use std::fs;
    use std::io::{Cursor, Write};
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::{Mutex, OnceLock};
    use tempfile::TempDir;

    fn progress_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn lock_progress() -> std::sync::MutexGuard<'static, ()> {
        progress_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn set_progress_env() {
        env::set_var("MDDEDUPE_SCAN_PROGRESS_MS", "0");
        env::set_var("MDDEDUPE_HASH_PROGRESS_MS", "0");
    }

    #[test]
    fn test_human_readable_units() {
        assert_eq!(human_readable(999), "999 bytes");
        assert_eq!(human_readable(1024), "1.00 KB");
        assert_eq!(human_readable(1024 * 1024), "1.00 MB");
        assert_eq!(human_readable(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_format_duration_outputs_minutes_and_seconds() {
        let seconds = Duration::from_secs(42);
        let minutes = Duration::from_secs(125);
        assert_eq!(format_duration(seconds), "42 sec");
        assert_eq!(format_duration(minutes), "2 min 5 sec");
    }

    #[test]
    fn test_get_unique_destination_generates_incremented_names() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dest = temp_dir.path();
        let file_name = OsStr::new("example.txt");
        // Occupy the original name and the first candidate.
        fs::File::create(dest.join(file_name)).expect("Failed to create base file");
        fs::File::create(dest.join("example(1).txt")).expect("Failed to create collision file");

        let unique = get_unique_destination(dest, file_name);
        assert_eq!(
            unique.file_name().expect("missing file name"),
            OsStr::new("example(2).txt")
        );
    }

    #[test]
    fn test_process_duplicates_skips_invalid_file_names() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dest_dir = temp_dir.path().join("dest");
        fs::create_dir(&dest_dir).expect("Failed to create destination directory");

        let mut duplicates: HashMap<String, Vec<(PathBuf, u64)>> = HashMap::new();
        duplicates.insert(
            "hash".into(),
            vec![
                (temp_dir.path().join("original.txt"), 5),
                (PathBuf::new(), 5),
            ],
        );

        let report = process_duplicates(
            &duplicates,
            &DuplicateAction::Move(dest_dir.clone()),
            true,
            true,
        );
        assert_eq!(report.successes, 0);
        assert_eq!(report.failures.len(), 1);

        assert!(fs::read_dir(dest_dir)
            .expect("Failed to read destination directory")
            .next()
            .is_none());
    }

    #[test]
    fn test_handle_progress_result_handles_broken_pipe() {
        let flag = Arc::new(AtomicBool::new(true));
        let err = io::Error::new(io::ErrorKind::BrokenPipe, "fail");
        let result = handle_progress_result(Err(err), &flag);
        assert!(result.is_ok());
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_handle_progress_result_propagates_other_errors() {
        let flag = Arc::new(AtomicBool::new(true));
        let err = io::Error::new(io::ErrorKind::Other, "fail");
        let result = handle_progress_result(Err(err), &flag);
        assert!(result.is_err());
        assert!(flag.load(Ordering::SeqCst));
    }

    #[cfg(unix)]
    #[test]
    fn test_find_duplicates_handles_permission_errors_and_progress() {
        let _guard = lock_progress();
        set_progress_env();
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let restricted = temp_dir.path().join("restricted");
        fs::create_dir(&restricted).expect("Failed to create restricted directory");
        fs::write(restricted.join("file.txt"), b"data").expect("Failed to seed restricted file");
        let metadata = fs::metadata(&restricted).expect("Failed to read metadata");
        let original_mode = metadata.permissions().mode();

        let mut perms = metadata.permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&restricted, perms).expect("Failed to tighten permissions");

        let result = find_duplicates_optimized_with_options(temp_dir.path(), true, false, false);
        assert!(result.is_ok());

        // Restore permissions for cleanup.
        let mut restore = fs::metadata(&restricted)
            .expect("Failed to read metadata for restore")
            .permissions();
        restore.set_mode(original_mode);
        fs::set_permissions(&restricted, restore).expect("Failed to restore permissions");
    }

    #[test]
    fn test_find_duplicates_progress_broken_pipe_does_not_fail() {
        let _guard = lock_progress();
        set_progress_env();
        env::set_var("MDDEDUPE_PROGRESS_FAIL", "broken_pipe");

        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir = temp_dir.path();
        let file1 = dir.join("file1.txt");
        let file2 = dir.join("file2.txt");
        fs::write(&file1, b"duplicate").expect("Failed to write file1");
        fs::write(&file2, b"duplicate").expect("Failed to write file2");

        let result = find_duplicates_optimized_with_options(dir, true, true, false)
            .expect("Progress broken pipe should be handled");
        assert_eq!(result.2, 1);

        env::remove_var("MDDEDUPE_PROGRESS_FAIL");
    }

    #[test]
    fn test_find_duplicates_progress_other_error_propagates() {
        let _guard = lock_progress();
        set_progress_env();
        env::set_var("MDDEDUPE_PROGRESS_FAIL", "io_error");

        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let result = find_duplicates_optimized_with_options(temp_dir.path(), true, true, false);
        let err = result.expect_err("Expected IO error to propagate");
        assert_eq!(err.kind(), io::ErrorKind::Other);

        env::remove_var("MDDEDUPE_PROGRESS_FAIL");
    }

    #[test]
    fn test_run_app_cancelled_during_scan() {
        let _guard = lock_progress();
        set_progress_env();
        env::set_var("MDDEDUPE_PROGRESS_FAIL", "cancel");

        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir = temp_dir.path();
        let file1 = dir.join("file1.txt");
        let file2 = dir.join("file2.txt");
        fs::write(&file1, b"duplicate").expect("Failed to write file1");
        fs::write(&file2, b"duplicate").expect("Failed to write file2");

        let args = Args {
            directory: dir.to_path_buf(),
            action: None,
            dest: None,
            force: true,
            quiet: false,
            create_dest: false,
            follow_symlinks: false,
            summary_path: None,
            summary_silent: false,
            summary_only: false,
            log_level: LogLevel::Info,
            summary_format: SummaryFormat::Text,
        };

        let result = run_app(args, Cursor::new(Vec::new()));
        env::remove_var("MDDEDUPE_PROGRESS_FAIL");
        reset_cancellation_flag();
        assert!(matches!(result, Err(AppError::Cancelled)));
    }

    #[test]
    fn test_find_duplicates_progress_success_path() {
        let _guard = lock_progress();
        set_progress_env();
        env::remove_var("MDDEDUPE_PROGRESS_FAIL");

        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir = temp_dir.path();
        let file1 = dir.join("file1.txt");
        let file2 = dir.join("file2.txt");
        fs::write(&file1, b"duplicate").expect("Failed to write file1");
        fs::write(&file2, b"duplicate").expect("Failed to write file2");

        let result = find_duplicates_optimized_with_options(dir, true, true, false)
            .expect("Progress should succeed");
        assert_eq!(result.2, 1);
    }

    #[test]
    fn test_run_app_prompt_cancel_keeps_files() {
        let _guard = lock_progress();
        set_progress_env();
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir = temp_dir.path();
        let file1 = dir.join("file1.txt");
        let file2 = dir.join("file2.txt");
        fs::write(&file1, b"duplicate").expect("Failed to write file1");
        fs::write(&file2, b"duplicate").expect("Failed to write file2");

        let args = Args {
            directory: dir.to_path_buf(),
            action: Some("delete".to_string()),
            dest: None,
            force: false,
            quiet: false,
            create_dest: false,
            follow_symlinks: false,
            summary_path: None,
            summary_silent: false,
            summary_only: false,
            log_level: LogLevel::Info,
            summary_format: SummaryFormat::Text,
        };

        let result = run_app(args, Cursor::new(b"n\n".to_vec()));
        assert!(result.is_ok());
        assert!(file1.exists());
        assert!(file2.exists());
    }

    #[test]
    fn test_run_app_delete_with_force_removes_duplicates() {
        let _guard = lock_progress();
        set_progress_env();
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir = temp_dir.path();
        let file1 = dir.join("file1.txt");
        let file2 = dir.join("file2.txt");
        fs::write(&file1, b"duplicate").expect("Failed to write file1");
        fs::write(&file2, b"duplicate").expect("Failed to write file2");

        let args = Args {
            directory: dir.to_path_buf(),
            action: Some("delete".to_string()),
            dest: None,
            force: true,
            quiet: true,
            create_dest: false,
            follow_symlinks: false,
            summary_path: None,
            summary_silent: false,
            summary_only: false,
            log_level: LogLevel::Info,
            summary_format: SummaryFormat::Text,
        };

        let result = run_app(args, Cursor::new(Vec::new()));
        assert!(result.is_ok());
        let remaining: Vec<_> = fs::read_dir(dir)
            .expect("failed to read directory after delete")
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to collect entries");
        assert_eq!(remaining.len(), 1);
        let remaining_path = remaining[0].path();
        let content =
            fs::read_to_string(&remaining_path).expect("failed to read remaining file content");
        assert_eq!(content, "duplicate");
    }

    #[test]
    fn test_run_app_move_action_generates_unique_destination() {
        let _guard = lock_progress();
        set_progress_env();
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir = temp_dir.path();
        let file1 = dir.join("file1.txt");
        let file2 = dir.join("file2.txt");
        fs::write(&file1, b"duplicate").expect("Failed to write file1");
        fs::write(&file2, b"duplicate").expect("Failed to write file2");

        let dest_dir = TempDir::new().expect("Failed to create move destination");
        let dest_path = dest_dir.path().to_path_buf();
        fs::write(dest_path.join("file2.txt"), b"existing").expect("Failed to create collision");

        let args = Args {
            directory: dir.to_path_buf(),
            action: Some("move".to_string()),
            dest: Some(dest_path.clone()),
            force: true,
            quiet: true,
            create_dest: false,
            follow_symlinks: false,
            summary_path: None,
            summary_silent: false,
            summary_only: false,
            log_level: LogLevel::Info,
            summary_format: SummaryFormat::Text,
        };

        let result = run_app(args, Cursor::new(Vec::new()));
        assert!(result.is_ok());
        let remaining_files: Vec<_> = fs::read_dir(dir)
            .expect("failed to read directory after move")
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to collect entries")
            .into_iter()
            .filter(|entry| entry.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .collect();
        assert_eq!(remaining_files.len(), 1);

        let moved_entries: Vec<_> = fs::read_dir(&dest_path)
            .expect("failed to read move destination")
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to collect destination entries");
        assert_eq!(moved_entries.len(), 2);
        let duplicate_moved = moved_entries.iter().any(|entry| {
            entry.file_name() != OsStr::new("file2.txt")
                && fs::read_to_string(entry.path()).expect("failed to read moved file content")
                    == "duplicate"
        });
        assert!(
            duplicate_moved,
            "expected move destination to contain duplicate payload"
        );
    }

    #[test]
    fn test_run_app_create_dest_creates_directory() {
        let _guard = lock_progress();
        set_progress_env();
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir = temp_dir.path();
        let file1 = dir.join("file1.txt");
        let file2 = dir.join("file2.txt");
        fs::write(&file1, b"duplicate").expect("Failed to write file1");
        fs::write(&file2, b"duplicate").expect("Failed to write file2");

        let dest_path = temp_dir.path().join("new_dest");
        assert!(!dest_path.exists());

        let args = Args {
            directory: dir.to_path_buf(),
            action: Some("move".to_string()),
            dest: Some(dest_path.clone()),
            force: true,
            quiet: true,
            create_dest: true,
            follow_symlinks: false,
            summary_path: None,
            summary_silent: false,
            summary_only: false,
            log_level: LogLevel::Info,
            summary_format: SummaryFormat::Text,
        };

        let result = run_app(args, Cursor::new(Vec::new()));
        assert!(result.is_ok());
        assert!(dest_path.exists());

        assert!(file1.exists());
        assert!(!file2.exists());
    }

    #[test]
    fn test_run_app_create_dest_requires_move_action() {
        let _guard = lock_progress();
        set_progress_env();
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir = temp_dir.path();
        fs::write(dir.join("file.txt"), b"data").expect("Failed to write file");

        let args = Args {
            directory: dir.to_path_buf(),
            action: None,
            dest: None,
            force: true,
            quiet: true,
            create_dest: true,
            follow_symlinks: false,
            summary_path: None,
            summary_silent: false,
            summary_only: false,
            log_level: LogLevel::Info,
            summary_format: SummaryFormat::Text,
        };

        let result = run_app(args, Cursor::new(Vec::new()));
        assert!(matches!(result, Err(AppError::CreateDestRequiresMove)));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_run_app_trash_action_moves_duplicates() {
        let _guard = lock_progress();
        set_progress_env();
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir = temp_dir.path();
        let file1 = dir.join("file1.txt");
        let file2 = dir.join("file2.txt");
        fs::write(&file1, b"duplicate").expect("Failed to write file1");
        fs::write(&file2, b"duplicate").expect("Failed to write file2");

        let args = Args {
            directory: dir.to_path_buf(),
            action: Some("trash".to_string()),
            dest: None,
            force: true,
            quiet: true,
            create_dest: false,
            follow_symlinks: false,
            summary_path: None,
            summary_silent: false,
            summary_only: false,
            log_level: LogLevel::Info,
            summary_format: SummaryFormat::Text,
        };

        let trash_dir = TempDir::new().expect("Failed to create trash directory");
        let trash_path = trash_dir.path().join("files");
        env::set_var("MDD_TRASH_DIR", &trash_path);

        let result = run_app(args, Cursor::new(Vec::new()));
        assert!(result.is_ok());
        assert!(file1.exists());
        assert!(!file2.exists());
        let expected = trash_path.join(file2.file_name().expect("invalid file name"));
        assert!(
            expected.exists(),
            "Expected trashed file at {}",
            expected.display()
        );

        env::remove_var("MDD_TRASH_DIR");
    }

    #[test]
    fn test_run_app_missing_move_destination_error() {
        let _guard = lock_progress();
        set_progress_env();
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir = temp_dir.path();
        fs::write(dir.join("file1.txt"), b"duplicate").expect("Failed to write file1");
        fs::write(dir.join("file2.txt"), b"duplicate").expect("Failed to write file2");

        let args = Args {
            directory: dir.to_path_buf(),
            action: Some("move".to_string()),
            dest: None,
            force: true,
            quiet: true,
            create_dest: false,
            follow_symlinks: false,
            summary_path: None,
            summary_silent: false,
            summary_only: false,
            log_level: LogLevel::Info,
            summary_format: SummaryFormat::Text,
        };

        let result = run_app(args, Cursor::new(Vec::new()));
        assert!(matches!(result, Err(AppError::MissingMoveDestination)));
    }

    #[test]
    fn test_run_app_unknown_action_error() {
        let _guard = lock_progress();
        set_progress_env();
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir = temp_dir.path();
        fs::write(dir.join("file1.txt"), b"duplicate").expect("Failed to write file1");
        fs::write(dir.join("file2.txt"), b"duplicate").expect("Failed to write file2");

        let args = Args {
            directory: dir.to_path_buf(),
            action: Some("compress".to_string()),
            dest: None,
            force: true,
            quiet: true,
            create_dest: false,
            follow_symlinks: false,
            summary_path: None,
            summary_silent: false,
            summary_only: false,
            log_level: LogLevel::Info,
            summary_format: SummaryFormat::Text,
        };

        let result = run_app(args, Cursor::new(Vec::new()));
        assert!(matches!(
            result,
            Err(AppError::UnknownAction(action)) if action == "compress"
        ));
    }

    #[test]
    fn test_hash_file() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let file_path = temp_dir.path().join("test.txt");
        let content = "The quick brown fox jumps over the lazy dog";
        {
            let mut file = fs::File::create(&file_path).expect("Failed to create file");
            write!(file, "{}", content).expect("Failed to write content");
            file.sync_all().expect("Failed to sync file");
        }
        let hash1 = hash_file(&file_path).expect("Failed to hash file");
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let hash2 = format!("{:x}", hasher.finalize());
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_find_duplicates_optimized() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir_path = temp_dir.path();

        // Create two files with identical content.
        let file1_path = dir_path.join("file1.txt");
        let content = "duplicate content";
        {
            let mut file1 = fs::File::create(&file1_path).expect("Failed to create file1");
            write!(file1, "{}", content).expect("Failed to write file1");
            file1.sync_all().expect("Failed to sync file1");
        }
        let file2_path = dir_path.join("file2.txt");
        {
            let mut file2 = fs::File::create(&file2_path).expect("Failed to create file2");
            write!(file2, "{}", content).expect("Failed to write file2");
            file2.sync_all().expect("Failed to sync file2");
        }
        // Create a third file with unique content.
        let file3_path = dir_path.join("file3.txt");
        {
            let mut file3 = fs::File::create(&file3_path).expect("Failed to create file3");
            write!(file3, "unique content").expect("Failed to write file3");
            file3.sync_all().expect("Failed to sync file3");
        }

        let (duplicates, scanned, _dup_count, wasted_space, elapsed) =
            find_duplicates_optimized_with_options(dir_path, true, false, false)
                .expect("Failed to find duplicates");

        // All three files should be scanned.
        assert_eq!(scanned, 3);

        // There should be one duplicate group.
        let mut dup_group_found = false;
        for (_hash, group) in duplicates.iter() {
            if group.len() > 1 {
                dup_group_found = true;
                assert_eq!(group.len(), 2);
            }
        }
        assert!(dup_group_found, "Expected a duplicate group but none found");

        let expected_size = fs::metadata(&file1_path)
            .expect("Failed to get metadata")
            .len();
        assert_eq!(wasted_space, expected_size);
        assert!(elapsed > Duration::from_secs(0));
    }

    #[test]
    fn test_process_duplicates_delete() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir_path = temp_dir.path();

        // Create two files with identical content.
        let content = "duplicate";
        let file1_path = dir_path.join("file1.txt");
        {
            let mut file1 = fs::File::create(&file1_path).expect("Failed to create file1");
            write!(file1, "{}", content).expect("Failed to write file1");
            file1.sync_all().expect("Failed to sync file1");
        }
        let file2_path = dir_path.join("file2.txt");
        {
            let mut file2 = fs::File::create(&file2_path).expect("Failed to create file2");
            write!(file2, "{}", content).expect("Failed to write file2");
            file2.sync_all().expect("Failed to sync file2");
        }

        let hash = hash_file(&file1_path).expect("Failed to hash file1");
        let mut duplicates = HashMap::new();
        let size1 = fs::metadata(&file1_path)
            .expect("Failed to get metadata")
            .len();
        let size2 = fs::metadata(&file2_path)
            .expect("Failed to get metadata")
            .len();
        duplicates.insert(
            hash,
            vec![(file1_path.clone(), size1), (file2_path.clone(), size2)],
        );

        let report = process_duplicates(&duplicates, &DuplicateAction::Delete, true, true);
        assert_eq!(report.successes, 1);
        assert!(report.failures.is_empty());
        // The first file remains, the duplicate is deleted.
        assert!(file1_path.exists());
        assert!(!file2_path.exists());
    }

    #[test]
    fn test_process_duplicates_move() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir_path = temp_dir.path();
        let move_dest = TempDir::new().expect("Failed to create destination directory");
        let move_dest_path = move_dest.path().to_path_buf();
        fs::File::create(move_dest_path.join("file2.txt"))
            .expect("Failed to seed destination collision");

        // Create two files with identical content.
        let content = "duplicate move";
        let file1_path = dir_path.join("file1.txt");
        {
            let mut file1 = fs::File::create(&file1_path).expect("Failed to create file1");
            write!(file1, "{}", content).expect("Failed to write file1");
            file1.sync_all().expect("Failed to sync file1");
        }
        let file2_path = dir_path.join("file2.txt");
        {
            let mut file2 = fs::File::create(&file2_path).expect("Failed to create file2");
            write!(file2, "{}", content).expect("Failed to write file2");
            file2.sync_all().expect("Failed to sync file2");
        }

        let hash = hash_file(&file1_path).expect("Failed to hash file1");
        let mut duplicates = HashMap::new();
        let size1 = fs::metadata(&file1_path)
            .expect("Failed to get metadata")
            .len();
        let size2 = fs::metadata(&file2_path)
            .expect("Failed to get metadata")
            .len();
        duplicates.insert(
            hash,
            vec![(file1_path.clone(), size1), (file2_path.clone(), size2)],
        );

        let report = process_duplicates(
            &duplicates,
            &DuplicateAction::Move(move_dest_path.clone()),
            true,
            true,
        );
        assert_eq!(report.successes, 1);
        assert!(report.failures.is_empty());

        // The first file remains; the second should be moved.
        assert!(file1_path.exists());
        assert!(!file2_path.exists());
        let new_file2_path = move_dest_path.join("file2(1).txt");
        assert!(new_file2_path.exists());
    }

    #[test]
    fn test_process_duplicates_trash() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir_path = temp_dir.path();

        // Create two files with identical content.
        let content = "duplicate trash";
        let file1_path = dir_path.join("file1.txt");
        {
            let mut file1 = fs::File::create(&file1_path).expect("Failed to create file1");
            write!(file1, "{}", content).expect("Failed to write file1");
            file1.sync_all().expect("Failed to sync file1");
        }
        let file2_path = dir_path.join("file2.txt");
        {
            let mut file2 = fs::File::create(&file2_path).expect("Failed to create file2");
            write!(file2, "{}", content).expect("Failed to write file2");
            file2.sync_all().expect("Failed to sync file2");
        }

        let hash = hash_file(&file1_path).expect("Failed to hash file1");
        let mut duplicates = HashMap::new();
        let size1 = fs::metadata(&file1_path)
            .expect("Failed to get metadata")
            .len();
        let size2 = fs::metadata(&file2_path)
            .expect("Failed to get metadata")
            .len();
        duplicates.insert(
            hash,
            vec![(file1_path.clone(), size1), (file2_path.clone(), size2)],
        );

        let trash_dir = TempDir::new().expect("Failed to create trash directory");
        let trash_path = trash_dir.path().join("files");
        env::set_var("MDD_TRASH_DIR", &trash_path);

        let report = process_duplicates(&duplicates, &DuplicateAction::Trash, true, true);
        assert_eq!(report.successes, 1);
        assert!(report.failures.is_empty());

        // The first file remains; the duplicate is moved to trash.
        assert!(file1_path.exists());
        assert!(!file2_path.exists());
        let file2_name = file2_path.file_name().expect("Invalid file name");
        let expected_trash_path = trash_path.join(file2_name);
        assert!(
            expected_trash_path.exists(),
            "Expected trashed file at {}",
            expected_trash_path.display()
        );

        env::remove_var("MDD_TRASH_DIR");
    }

    #[cfg(unix)]
    #[test]
    fn test_process_duplicates_reports_permission_errors() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir_path = temp_dir.path();

        let file1_path = dir_path.join("file1.txt");
        let file2_path = dir_path.join("file2.txt");
        fs::write(&file1_path, b"dup").expect("Failed to write file1");
        fs::write(&file2_path, b"dup").expect("Failed to write file2");

        let hash = hash_file(&file1_path).expect("Failed to hash file1");
        let mut duplicates = HashMap::new();
        let size1 = fs::metadata(&file1_path)
            .expect("Failed to get metadata")
            .len();
        let size2 = fs::metadata(&file2_path)
            .expect("Failed to get metadata")
            .len();
        duplicates.insert(
            hash,
            vec![(file1_path.clone(), size1), (file2_path.clone(), size2)],
        );

        let dest_dir = TempDir::new().expect("Failed to create destination directory");
        let dest_path = dest_dir.path();
        let mut perms = fs::metadata(dest_path)
            .expect("Failed to read destination permissions")
            .permissions();
        perms.set_mode(0o555);
        fs::set_permissions(dest_path, perms).expect("Failed to restrict destination permissions");

        let report = process_duplicates(
            &duplicates,
            &DuplicateAction::Move(dest_path.to_path_buf()),
            true,
            true,
        );
        assert_eq!(report.successes, 0);
        assert_eq!(report.failures.len(), 1);

        // Restore permissions for TempDir cleanup.
        let restore_perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(dest_path, restore_perms).expect("Failed to restore permissions");
    }

    #[cfg(unix)]
    #[test]
    fn test_find_duplicates_respects_follow_symlinks_flag() {
        let _guard = lock_progress();
        set_progress_env();
        env::remove_var("MDDEDUPE_PROGRESS_FAIL");
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let dir = temp_dir.path();
        let real_file = dir.join("original.txt");
        fs::write(&real_file, b"dup").expect("Failed to write original file");

        let external = TempDir::new().expect("Failed to create external directory");
        let external_dir = external.path();
        let external_file = external_dir.join("external.txt");
        fs::write(&external_file, b"dup").expect("Failed to write external file");

        let symlink_path = dir.join("link_external");
        symlink(external_dir, &symlink_path).expect("Failed to create symlink");

        let (_, _, dup_count_no_links, _, _) =
            find_duplicates_optimized_with_options(dir, true, false, false)
                .expect("Failed to scan without symlinks");
        assert_eq!(dup_count_no_links, 0);

        let (_, _, dup_count_with_links, _, _) =
            find_duplicates_optimized_with_options(dir, true, false, true)
                .expect("Failed to scan with symlinks");
        assert_eq!(dup_count_with_links, 1);
    }
}
