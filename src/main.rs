use ansi_term::Colour;
use clap::Parser;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

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
fn find_duplicates_optimized(
    dir: &Path,
) -> io::Result<(HashMap<String, Vec<(PathBuf, u64)>>, usize, usize, u64, Duration)> {
    let start = Instant::now();
    let mut size_map: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    let mut scanned_files = 0;
    let mut last_update = Instant::now();

    // Stage 1: Walk the directory and group files by their size.
    for entry in WalkDir::new(dir) {
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
                size_map.entry(metadata.len()).or_default().push(entry.path().to_path_buf());
            }
        }
        if last_update.elapsed() >= Duration::from_secs(1) {
            print!("\rScanning filesystem - found {} files...", scanned_files);
            io::stdout().flush()?;
            last_update = Instant::now();
        }
    }
    println!("\rFilesystem scan complete - found {} files.", scanned_files);

    // Stage 2: Process candidate groups.
    // Only consider file-size groups that contain more than one file.
    let candidate_groups: Vec<(u64, Vec<PathBuf>)> = size_map
        .into_iter()
        .filter(|(_, files)| files.len() > 1)
        .collect();
    let candidate_total: usize = candidate_groups.iter().map(|(_, files)| files.len()).sum();

    // Create an atomic counter to track progress of the hashing stage.
    let candidate_processed = Arc::new(AtomicUsize::new(0));

    // Spawn a progress thread that periodically prints the hashing progress.
    let candidate_processed_clone = candidate_processed.clone();
    let progress_handle = std::thread::spawn(move || {
        loop {
            let processed = candidate_processed_clone.load(Ordering::SeqCst);
            print!("\rHashing files: processed {} of {} files", processed, candidate_total);
            io::stdout().flush().unwrap();
            if processed >= candidate_total {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        // Finish the progress line.
        println!();
    });

    let mut duplicates: HashMap<String, Vec<(PathBuf, u64)>> = HashMap::new();
    // For each candidate group, compute file hashes in parallel.
    for (size, files) in candidate_groups {
        let hash_results: Vec<(PathBuf, String)> = files
            .into_par_iter()
            .filter_map(|path| {
                // Update the atomic counter.
                candidate_processed.fetch_add(1, Ordering::SeqCst);
                match hash_file(&path) {
                    Ok(hash) => Some((path, hash)),
                    Err(e) => {
                        eprintln!("Error hashing {}: {}", path.display(), e);
                        None
                    }
                }
            })
            .collect();

        // Group files by hash.
        for (path, hash) in hash_results {
            duplicates.entry(hash).or_default().push((path, size));
        }
    }

    // Wait for the progress thread to finish.
    progress_handle.join().unwrap();

    // Calculate duplicate count and wasted space.
    let mut duplicate_count = 0;
    let mut wasted_space = 0;
    for (_, group) in duplicates.iter() {
        if group.len() > 1 {
            duplicate_count += group.len() - 1;
            wasted_space += group.iter().skip(1).map(|(_, size)| *size).sum::<u64>();
        }
    }
    let elapsed = start.elapsed();
    Ok((duplicates, scanned_files, duplicate_count, wasted_space, elapsed))
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

/// Processes duplicates by applying the selected action to every file in each duplicate group except the first.
/// For each file processed, updated status information is printed.
fn process_duplicates(
    duplicates: &HashMap<String, Vec<(PathBuf, u64)>>,
    action: DuplicateAction,
) -> io::Result<()> {
    // Compute the overall number of duplicate files (excluding the first copy in each group)
    let overall_total: usize = duplicates
        .values()
        .filter(|v| v.len() > 1)
        .map(|v| v.len() - 1)
        .sum();
    let mut overall_processed = 0;
    let mut overall_size = 0;

    for (hash, files) in duplicates {
        if files.len() > 1 {
            println!(
                "{}",
                Colour::Fixed(8).paint(format!("Duplicate group (hash: {}):", hash))
            );
            for (i, (path, size)) in files.iter().enumerate() {
                println!("  {}: {} ({})", i + 1, path.display(), human_readable(*size));
            }
            // Process duplicate group: skip the first file.
            for (path, size) in files.iter().skip(1) {
                match &action {
                    DuplicateAction::Move(dest) => {
                        let file_name = match path.file_name() {
                            Some(name) => name,
                            None => {
                                eprintln!("Invalid file name for {}", path.display());
                                continue;
                            }
                        };
                        let mut dest_path = dest.join(file_name);
                        if dest_path.exists() {
                            dest_path = get_unique_destination(dest, file_name);
                        }
                        println!("Moving {} to {}", path.display(), dest_path.display());
                        fs::rename(path, &dest_path)?;
                    }
                    DuplicateAction::Trash => {
                        println!("Sending {} to recycle bin (simulated)", path.display());
                        // In production, integrate with a crate that sends files to the recycle bin.
                    }
                    DuplicateAction::Delete => {
                        println!("Permanently deleting {}", path.display());
                        fs::remove_file(path)?;
                    }
                }
                overall_processed += 1;
                overall_size += size;
                println!(
                    "Status: Processed {} of {} duplicate files (total size processed: {})",
                    overall_processed,
                    overall_total,
                    human_readable(overall_size)
                );
            }
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    println!(
        "Starting duplicate scan in directory: {}",
        args.directory.display()
    );

    // Run the optimized duplicate finder.
    let (duplicates, scanned, duplicate_count, wasted, elapsed) =
        find_duplicates_optimized(&args.directory)?;
    println!(
        "Duplicate scan completed in {}. {} files scanned, {} duplicates found ({} wasted).",
        format_duration(elapsed),
        scanned,
        duplicate_count,
        human_readable(wasted)
    );

    // If not running in quiet mode, list detailed duplicate groups.
    if !args.quiet {
        let mut groups: Vec<(&String, &Vec<(PathBuf, u64)>)> = duplicates
            .iter()
            .filter(|(_, group)| group.len() > 1)
            .collect();
        groups.sort_by_key(|(_, group)| group.iter().skip(1).map(|(_, size)| *size).sum::<u64>());
        for (hash, group) in groups {
            println!(
                "{}",
                Colour::Fixed(8).paint(format!("Duplicate group (hash: {}):", hash))
            );
            for (path, size) in group {
                println!("  {} ({})", path.display(), human_readable(*size));
            }
        }
        println!();
    }

    // Print the summary with colored text.
    println!(
        "{} {}",
        Colour::RGB(173, 216, 230).paint("Duplicate scan summary:"),
        Colour::RGB(255, 255, 224).paint(format!(
            "{} files scanned, {} duplicates found ({} wasted) in {}.",
            scanned,
            duplicate_count,
            human_readable(wasted),
            format_duration(elapsed)
        ))
    );

    // Process duplicates if an action was specified.
    if let Some(action_str) = args.action {
        let action = match action_str.to_lowercase().as_str() {
            "move" => {
                let dest = args.dest.clone().unwrap_or_else(|| {
                    eprintln!("Destination directory must be provided for move action.");
                    std::process::exit(1);
                });
                DuplicateAction::Move(dest)
            }
            "trash" => DuplicateAction::Trash,
            "delete" => DuplicateAction::Delete,
            _ => {
                eprintln!(
                    "Unknown action: {}. Valid options are move, trash or delete.",
                    action_str
                );
                std::process::exit(1);
            }
        };

        if !args.force {
            print!("WARNING: This action will modify the filesystem. Do you wish to proceed? (y/N): ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Operation cancelled.");
                return Ok(());
            }
        }

        process_duplicates(&duplicates, action)?;
        println!("Operation complete.");
    } else {
        println!("No action specified; running in read‑only mode.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

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
            find_duplicates_optimized(dir_path).expect("Failed to find duplicates");

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
        let size1 = fs::metadata(&file1_path).expect("Failed to get metadata").len();
        let size2 = fs::metadata(&file2_path).expect("Failed to get metadata").len();
        duplicates.insert(hash, vec![(file1_path.clone(), size1), (file2_path.clone(), size2)]);

        process_duplicates(&duplicates, DuplicateAction::Delete)
            .expect("Failed to process duplicates");
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
        let size1 = fs::metadata(&file1_path).expect("Failed to get metadata").len();
        let size2 = fs::metadata(&file2_path).expect("Failed to get metadata").len();
        duplicates.insert(hash, vec![(file1_path.clone(), size1), (file2_path.clone(), size2)]);

        process_duplicates(
            &duplicates,
            DuplicateAction::Move(move_dest_path.clone()),
        )
        .expect("Failed to process duplicates");

        // The first file remains; the second should be moved.
        assert!(file1_path.exists());
        let file2_name = file2_path.file_name().expect("Invalid file name");
        let new_file2_path = move_dest_path.join(file2_name);
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
        let size1 = fs::metadata(&file1_path).expect("Failed to get metadata").len();
        let size2 = fs::metadata(&file2_path).expect("Failed to get metadata").len();
        duplicates.insert(hash, vec![(file1_path.clone(), size1), (file2_path.clone(), size2)]);

        process_duplicates(&duplicates, DuplicateAction::Trash)
            .expect("Failed to process duplicates");

        // Since the Trash action is simulated, both files should still exist.
        assert!(file1_path.exists());
        assert!(file2_path.exists());
    }
}
