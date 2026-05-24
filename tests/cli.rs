use assert_cmd::cargo::cargo_bin_cmd;
use assert_fs::{prelude::*, NamedTempFile};
use serde_json::Value;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
fn create_duplicate_fixture() -> assert_fs::TempDir {
    let temp = assert_fs::TempDir::new().expect("Failed to create temp dir");
    temp.child("file1.txt")
        .write_str("duplicate")
        .expect("Failed to write file1");
    temp.child("file2.txt")
        .write_str("duplicate")
        .expect("Failed to write file2");
    temp
}

#[test]
fn cli_read_only_outputs_summary() {
    let temp = create_duplicate_fixture();
    let dir = temp.path();

    cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .arg(dir)
        .assert()
        .success()
        .stdout(predicates::str::contains("Duplicate scan summary"))
        .stdout(predicates::str::contains("duplicates found"));
}

#[test]
fn cli_action_delete_force_removes_duplicate() {
    let temp = create_duplicate_fixture();
    let dir = temp.path();
    let duplicate_file = dir.join("file2.txt");
    assert!(duplicate_file.exists());

    cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([dir.to_str().unwrap(), "--action", "delete", "--force"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Operation complete."));

    assert!(!duplicate_file.exists());
}

#[test]
fn cli_prompt_cancel_preserves_files() {
    let temp = create_duplicate_fixture();
    let dir = temp.path();
    let duplicate_file = dir.join("file2.txt");

    cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([dir.to_str().unwrap(), "--action", "delete"])
        .write_stdin("n\n")
        .assert()
        .success()
        .stdout(predicates::str::contains("Operation cancelled."));

    assert!(duplicate_file.exists());
}

#[test]
fn cli_move_requires_destination() {
    let temp = create_duplicate_fixture();
    let dir = temp.path();

    cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([dir.to_str().unwrap(), "--action", "move"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Destination directory must be provided for move action.",
        ));
}

#[test]
fn cli_unknown_action_errors() {
    let temp = create_duplicate_fixture();
    let dir = temp.path();

    cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([dir.to_str().unwrap(), "--action", "compress"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("Unknown action: compress"));
}

#[test]
fn cli_json_summary_outputs_valid_json() {
    let temp = create_duplicate_fixture();
    let dir = temp.path();
    let summary_file = NamedTempFile::new("summary.json").expect("create summary file");

    let assert = cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            "--summary-format",
            "json",
            "--quiet",
            "--summary-path",
            summary_file.path().to_str().unwrap(),
            dir.to_str().unwrap(),
        ])
        .assert()
        .success();

    let output = String::from_utf8(assert.get_output().stdout.clone())
        .expect("stdout should be valid UTF-8");
    let json_start = output
        .find('{')
        .expect("JSON output should contain an object");
    let summary: Value =
        serde_json::from_str(&output[json_start..]).expect("expected JSON summary output");
    assert_eq!(
        summary["duplicate_files"].as_u64().unwrap(),
        1,
        "duplicate count should match"
    );
    assert_eq!(
        summary["summary_format"].as_str().unwrap(),
        "json",
        "summary format should reflect json"
    );

    let file_contents =
        fs::read_to_string(summary_file.path()).expect("summary file should be readable");
    let file_json: Value =
        serde_json::from_str(file_contents.trim()).expect("summary file should contain JSON");
    assert_eq!(file_json["duplicate_files"].as_u64().unwrap(), 1);
}

#[test]
fn cli_text_summary_writes_file() {
    let temp = create_duplicate_fixture();
    let dir = temp.path();
    let summary_file = NamedTempFile::new("summary.txt").expect("create summary file");

    cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            "--summary-path",
            summary_file.path().to_str().unwrap(),
            dir.to_str().unwrap(),
        ])
        .assert()
        .success();

    let contents =
        fs::read_to_string(summary_file.path()).expect("summary file should be readable");
    assert!(contents.contains("Duplicate scan summary:"));
}

#[test]
fn cli_summary_silent_suppresses_stdout() {
    let temp = create_duplicate_fixture();
    let dir = temp.path();
    let summary_file = NamedTempFile::new("summary.txt").expect("create summary file");

    let assert = cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            "--summary-path",
            summary_file.path().to_str().unwrap(),
            "--summary-silent",
            "--quiet",
            dir.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone())
        .expect("stdout should be valid UTF-8");
    assert!(
        stdout.trim().is_empty(),
        "stdout should be empty when summary is silent"
    );

    let contents =
        fs::read_to_string(summary_file.path()).expect("summary file should be readable");
    assert!(contents.contains("Duplicate scan summary:"));
}

#[test]
fn cli_summary_only_hides_duplicate_listings() {
    let temp = create_duplicate_fixture();
    let dir = temp.path();

    let output = cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args(["--summary-only", dir.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("stdout should be valid UTF-8");
    assert!(stdout.contains("Duplicate scan summary:"));
    assert!(!stdout.contains("Duplicate group"));
}

#[test]
fn cli_log_level_warn_suppresses_info_logs() {
    let temp = create_duplicate_fixture();
    let dir = temp.path();

    let output = cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args(["--log-level", "warn", dir.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("stdout should be valid UTF-8");
    assert!(stdout.contains("Duplicate scan summary:"));
    assert!(!stdout.contains("Duplicate group"));
}

#[test]
fn cli_multi_path_startup_line_lists_all_dirs() {
    let dir_a = assert_fs::TempDir::new().expect("create dir a");
    let dir_b = assert_fs::TempDir::new().expect("create dir b");
    dir_a.child("a.txt").write_str("content").expect("write a");
    dir_b.child("b.txt").write_str("content").expect("write b");

    let output = cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            dir_a.path().to_str().unwrap(),
            dir_b.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("stdout should be valid UTF-8");
    let start_line = stdout
        .lines()
        .find(|line| line.starts_with("Starting duplicate scan in:"))
        .expect("startup line should be present");
    assert!(
        start_line.contains(dir_a.path().to_str().unwrap()),
        "startup line should list first dir, got: {}",
        start_line
    );
    assert!(
        start_line.contains(dir_b.path().to_str().unwrap()),
        "startup line should list second dir, got: {}",
        start_line
    );
}

#[cfg(unix)]
#[test]
fn cli_log_level_none_reports_failures() {
    let temp = create_duplicate_fixture();
    let dir = temp.path();

    // Destination is present but unwritable to force move failure.
    let dest = assert_fs::TempDir::new().expect("create dest");
    let dest_path = dest.path();
    let mut perms = fs::metadata(dest_path)
        .expect("dest metadata")
        .permissions();
    perms.set_mode(0o555);
    fs::set_permissions(dest_path, perms).expect("set dest perms");

    let assert = cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "1")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "1")
        .args([
            dir.to_str().unwrap(),
            "--action",
            "move",
            "--dest",
            dest_path.to_str().unwrap(),
            "--force",
            "--log-level",
            "none",
            "--summary-silent",
        ])
        .assert()
        .success();

    let stderr =
        String::from_utf8(assert.get_output().stderr.clone()).expect("stderr should be utf-8");
    assert!(
        stderr.contains("failures"),
        "expected failure summary in stderr, got: {}",
        stderr
    );
}

#[test]
fn cli_read_only_lists_survivor_first() {
    // Two sibling dirs under one parent with controlled names so the choice is
    // provably driven by listing order (root_index), not alphabetical luck of
    // random temp paths. The first-LISTED dir ("zzz_dir") sorts AFTER the
    // second ("aaa_dir"); a path-only sort would list aaa first, but the
    // (root_index, path) survivor sort must list the zzz copy first.
    let parent = assert_fs::TempDir::new().expect("create parent");
    let dir_zzz = parent.child("zzz_dir");
    let dir_aaa = parent.child("aaa_dir");
    dir_zzz.create_dir_all().expect("create zzz_dir");
    dir_aaa.create_dir_all().expect("create aaa_dir");
    dir_zzz
        .child("copy.txt")
        .write_str("shared content")
        .expect("write zzz copy");
    dir_aaa
        .child("copy.txt")
        .write_str("shared content")
        .expect("write aaa copy");

    let output = cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            dir_zzz.path().to_str().unwrap(),
            dir_aaa.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("stdout should be valid UTF-8");

    // Restrict the search to the duplicate-group listing block. The startup
    // line ("Starting duplicate scan in:") echoes the supplied dirs in order
    // and would otherwise mask the group's ordering, so we slice from the
    // "Duplicate group" header onward.
    let group_start = stdout
        .find("Duplicate group")
        .expect("read-only listing should print a duplicate group");
    let group_block = &stdout[group_start..];

    let zzz_marker = dir_zzz.path().to_str().unwrap();
    let aaa_marker = dir_aaa.path().to_str().unwrap();
    let zzz_pos = group_block
        .find(zzz_marker)
        .expect("zzz_dir copy should appear in the duplicate-group block");
    let aaa_pos = group_block
        .find(aaa_marker)
        .expect("aaa_dir copy should appear in the duplicate-group block");
    assert!(
        zzz_pos < aaa_pos,
        "survivor under first-listed dir (zzz_dir) should be listed before \
         the aaa_dir copy; zzz at {} aaa at {}, group block:\n{}",
        zzz_pos,
        aaa_pos,
        group_block
    );
}

#[test]
fn cli_json_summary_directories_match_order() {
    let dir_a = assert_fs::TempDir::new().expect("create dir a");
    let dir_b = assert_fs::TempDir::new().expect("create dir b");
    dir_a.child("a.txt").write_str("content").expect("write a");
    dir_b.child("b.txt").write_str("content").expect("write b");

    let assert = cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            "--summary-format",
            "json",
            "--quiet",
            dir_a.path().to_str().unwrap(),
            dir_b.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let output = String::from_utf8(assert.get_output().stdout.clone())
        .expect("stdout should be valid UTF-8");
    let json_start = output
        .find('{')
        .expect("JSON output should contain an object");
    let summary: Value =
        serde_json::from_str(&output[json_start..]).expect("expected JSON summary output");

    let directories = summary["directories"]
        .as_array()
        .expect("directories should be a JSON array");
    assert_eq!(
        directories.len(),
        2,
        "directories array should contain both supplied paths, got: {:?}",
        directories
    );

    let expected_a = std::path::Path::new(dir_a.path().to_str().unwrap())
        .display()
        .to_string();
    let expected_b = std::path::Path::new(dir_b.path().to_str().unwrap())
        .display()
        .to_string();
    assert_eq!(
        directories[0].as_str().unwrap(),
        expected_a,
        "first directory entry should match first supplied path in order"
    );
    assert_eq!(
        directories[1].as_str().unwrap(),
        expected_b,
        "second directory entry should match second supplied path in order"
    );
}

#[test]
fn cli_nested_paths_rejected() {
    // A parent directory and one of its subdirectories passed together must be
    // rejected before any scan, with the overlap message on stderr.
    let parent = assert_fs::TempDir::new().expect("create parent");
    let child = parent.child("child");
    child.create_dir_all().expect("create child");

    cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            parent.path().to_str().unwrap(),
            child.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("is inside"))
        .stderr(predicates::str::contains("non-overlapping paths"));
}

#[cfg(unix)]
#[test]
fn cli_fail_on_error_sets_exit_status() {
    let temp = create_duplicate_fixture();
    let dir = temp.path();

    let dest = assert_fs::TempDir::new().expect("create dest");
    let dest_path = dest.path();
    let mut perms = fs::metadata(dest_path)
        .expect("dest metadata")
        .permissions();
    perms.set_mode(0o555);
    fs::set_permissions(dest_path, perms).expect("set dest perms");

    let assert = cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "1")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "1")
        .args([
            dir.to_str().unwrap(),
            "--action",
            "move",
            "--dest",
            dest_path.to_str().unwrap(),
            "--force",
            "--log-level",
            "none",
            "--summary-silent",
            "--fail-on-error",
        ])
        .assert()
        .failure();

    let stderr =
        String::from_utf8(assert.get_output().stderr.clone()).expect("stderr should be utf-8");
    assert!(stderr.contains("failures"));
}
