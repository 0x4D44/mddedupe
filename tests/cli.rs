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
