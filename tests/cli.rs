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
        .stdout(predicates::str::contains("duplicate files"));
}

#[test]
fn cli_action_delete_force_removes_duplicate() {
    let temp = create_duplicate_fixture();
    let dir = temp.path();
    let duplicate_file = dir.join("file2.txt");
    assert!(duplicate_file.exists());

    // Pin the neutral policy so the survivor is (root_index, path) and file2.txt
    // is the deterministic victim. Bare `--no-protect` is today's neutral policy
    // (empty protects + `lexical`); under the default convention `oldest` would
    // otherwise decide between two files written back-to-back, which is timing-
    // dependent on coarse-granularity filesystems.
    cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            dir.to_str().unwrap(),
            "--action",
            "delete",
            "--force",
            "--no-protect",
        ])
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
    // Two-metric accounting (HLD §3.5): this bare run uses the CONVENTION default
    // (protect `0*`/`00-*`, `oldest` fallback), not the neutral default — but the
    // `file*.txt` fixture matches no marker, so each group still has exactly one
    // survivor and the removable metric equals the redundancy metric. Both new
    // fields are present and mirror duplicate_files / duplicate_wasted_bytes.
    assert_eq!(
        summary["removable_files"].as_u64().unwrap(),
        1,
        "removable_files should equal duplicate_files (no marker matches under the convention default)"
    );
    assert_eq!(
        summary["reclaimable_bytes"].as_u64().unwrap(),
        summary["duplicate_wasted_bytes"].as_u64().unwrap(),
        "reclaimable_bytes should equal duplicate_wasted_bytes (one survivor per group)"
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
    assert_eq!(file_json["removable_files"].as_u64().unwrap(), 1);
    assert_eq!(
        file_json["reclaimable_bytes"].as_u64().unwrap(),
        file_json["duplicate_wasted_bytes"].as_u64().unwrap()
    );
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

#[test]
fn cli_variadic_positional_parses_when_interleaved_with_options() {
    // The `directories` positional is variadic (num_args = 1..). Verify clap
    // parses it correctly in three interleaving shapes against options. Each run
    // must succeed and scan exactly the directories supplied — confirmed via the
    // "Starting duplicate scan in:" startup line which echoes all supplied paths.

    // (a) single dir followed by options: `dir --action delete --force`
    {
        let temp = create_duplicate_fixture();
        let dir = temp.path();
        let duplicate = dir.join("file2.txt");
        // Neutral policy pinned so file2.txt is the deterministic victim (see
        // cli_action_delete_force_removes_duplicate). Bare `--no-protect` is the
        // neutral (lexical) policy.
        cargo_bin_cmd!("mddedupe")
            .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
            .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
            .args([
                dir.to_str().unwrap(),
                "--action",
                "delete",
                "--force",
                "--no-protect",
            ])
            .assert()
            .success()
            .stdout(predicates::str::contains(dir.to_str().unwrap()));
        assert!(
            !duplicate.exists(),
            "duplicate should be deleted in case (a)"
        );
    }

    // (b) two dirs first, then options.
    {
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
                "--quiet",
                "--log-level",
                "none",
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
            .expect("startup line should be present in case (b)");
        assert!(
            start_line.contains(dir_a.path().to_str().unwrap())
                && start_line.contains(dir_b.path().to_str().unwrap()),
            "both dirs should be scanned in case (b), got: {}",
            start_line
        );
    }

    // (c) options before two dirs: `--quiet dir1 dir2`.
    {
        let dir_a = assert_fs::TempDir::new().expect("create dir a");
        let dir_b = assert_fs::TempDir::new().expect("create dir b");
        dir_a.child("a.txt").write_str("content").expect("write a");
        dir_b.child("b.txt").write_str("content").expect("write b");

        let output = cargo_bin_cmd!("mddedupe")
            .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
            .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
            .args([
                "--log-level",
                "none",
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
            .expect("startup line should be present in case (c)");
        assert!(
            start_line.contains(dir_a.path().to_str().unwrap())
                && start_line.contains(dir_b.path().to_str().unwrap()),
            "both dirs should be scanned in case (c), got: {}",
            start_line
        );
    }
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

// --- Stage 3: configurable survivor selection (via the binary) -------------

/// Builds a fixture with a `00-*` master copy and a plain duplicate under a
/// single scan root, both byte-identical. Returns the temp dir, the master path
/// and the plain copy path. Used to exercise the protect rules end to end.
fn create_protect_fixture() -> (assert_fs::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let temp = assert_fs::TempDir::new().expect("create temp dir");
    let master = temp.child("00-master.txt");
    let plain = temp.child("copy.txt");
    master.write_str("shared content").expect("write master");
    plain.write_str("shared content").expect("write plain");
    (
        temp,
        master.path().to_path_buf(),
        plain.path().to_path_buf(),
    )
}

#[test]
fn cli_default_convention_protects_master_copy() {
    // A bare run (no config, no flags) uses the built-in convention default, so
    // the `00-*` master is kept and the plain copy is the victim. Set the cwd to
    // the (config-less) temp dir so the `./.mddedupe.toml` lookup is hermetic.
    let (temp, master, plain) = create_protect_fixture();

    cargo_bin_cmd!("mddedupe")
        .current_dir(temp.path())
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            temp.path().to_str().unwrap(),
            "--action",
            "delete",
            "--force",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "KEPT (protected: name 00-master.txt)",
        ));

    assert!(master.exists(), "00-* master must be protected and kept");
    assert!(!plain.exists(), "plain copy must be deleted");
}

#[test]
fn cli_default_oldest_keeps_oldest_over_lexical() {
    // Pin survivor identity under the LIVE `oldest` default (no flags). The kept
    // copy is the OLDEST but would NOT be chosen by `(root_index, path)`: the older
    // file (`zzz.txt`) sorts LATER alphabetically than the newer (`aaa.txt`). A
    // lexical/historical keeper would be `aaa.txt`; the convention default must keep
    // the oldest, `zzz.txt`. mtimes are set explicitly so the strategy is
    // deterministic on coarse-granularity filesystems. No fixture name matches the
    // `0*`/`00-*` markers, so the fallback (`oldest`) genuinely decides.
    let temp = assert_fs::TempDir::new().expect("create temp dir");
    let newer = temp.child("aaa.txt");
    let older = temp.child("zzz.txt");
    newer.write_str("shared content").expect("write newer");
    older.write_str("shared content").expect("write older");
    filetime::set_file_mtime(older.path(), filetime::FileTime::from_unix_time(1_000, 0))
        .expect("set older mtime");
    filetime::set_file_mtime(newer.path(), filetime::FileTime::from_unix_time(2_000, 0))
        .expect("set newer mtime");

    cargo_bin_cmd!("mddedupe")
        .current_dir(temp.path())
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            temp.path().to_str().unwrap(),
            "--action",
            "delete",
            "--force",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("KEPT (oldest)"));

    assert!(
        older.path().exists(),
        "the oldest copy (zzz.txt) must survive under the live oldest default"
    );
    assert!(
        !newer.path().exists(),
        "the newer copy (aaa.txt) must be removed even though it sorts first lexically"
    );
}

#[test]
fn cli_no_protect_lexical_reverts_to_root_index() {
    // Bare `--no-protect` IS today's exact neutral policy (HLD §3.3/§4.1): empty
    // protects AND a `lexical` fallback — no `--keep lexical` needed. The survivor
    // is the copy under the first-listed root, ties broken by path. The first root
    // ("zzz_dir") sorts AFTER the second ("aaa_dir"), so a path-only sort would
    // list aaa first; the (root_index, path) sort must list zzz first.
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
            "--no-protect",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("stdout should be valid UTF-8");
    let group_start = stdout
        .find("Duplicate group")
        .expect("read-only listing should print a duplicate group");
    let group_block = &stdout[group_start..];
    // The neutral fallback survivor is labelled `KEPT (lexical)`.
    assert!(
        group_block.contains("KEPT (lexical)"),
        "neutral fallback should be labelled lexical, got:\n{}",
        group_block
    );
    let zzz_pos = group_block
        .find(dir_zzz.path().to_str().unwrap())
        .expect("zzz copy should appear");
    let aaa_pos = group_block
        .find(dir_aaa.path().to_str().unwrap())
        .expect("aaa copy should appear");
    assert!(
        zzz_pos < aaa_pos,
        "survivor under first-listed root (zzz_dir) should be listed first; \
         group block:\n{}",
        group_block
    );
}

#[test]
fn cli_protect_dir_via_flag_keeps_matching_dir() {
    // `--protect-dir keepme*` protects the copy under a `keepme/` directory; the
    // sibling plain copy is removed. `--no-protect` is NOT set, so the convention
    // would also fire — but the flag replaces only the dir list, and neither
    // copy name matches the default name globs, so the dir flag is what protects.
    let parent = assert_fs::TempDir::new().expect("create parent");
    let keepme = parent.child("keepme");
    let plain = parent.child("plain");
    keepme.create_dir_all().expect("create keepme");
    plain.create_dir_all().expect("create plain");
    let kept = keepme.child("x.txt");
    let victim = plain.child("x.txt");
    kept.write_str("shared content").expect("write kept");
    victim.write_str("shared content").expect("write victim");

    cargo_bin_cmd!("mddedupe")
        .current_dir(parent.path())
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            parent.path().to_str().unwrap(),
            "--protect-dir",
            "keepme*",
            "--keep",
            "lexical",
            "--action",
            "delete",
            "--force",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("KEPT (protected: dir keepme)"));

    assert!(kept.path().exists(), "copy under keepme/ must be kept");
    assert!(!victim.path().exists(), "plain copy must be deleted");
}

#[test]
fn cli_protect_name_via_flag_keeps_matching_name() {
    // `--protect-name master.*` protects the file named master.txt; the plain
    // sibling is removed.
    let temp = assert_fs::TempDir::new().expect("create temp dir");
    let master = temp.child("master.txt");
    let plain = temp.child("copy.txt");
    master.write_str("shared content").expect("write master");
    plain.write_str("shared content").expect("write plain");

    cargo_bin_cmd!("mddedupe")
        .current_dir(temp.path())
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            temp.path().to_str().unwrap(),
            "--protect-name",
            "master.*",
            "--keep",
            "lexical",
            "--action",
            "delete",
            "--force",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "KEPT (protected: name master.txt)",
        ));

    assert!(master.path().exists(), "master.txt must be kept");
    assert!(!plain.path().exists(), "plain copy must be deleted");
}

#[test]
fn cli_divergent_two_metric_summary() {
    // Two protected copies (under `0*` dirs) + one plain copy in the SAME hash
    // group: redundancy = 2 (len-1), removable = 1 (a single victim). The summary
    // must report both metrics and the "protected and kept" count (HLD §3.5).
    let parent = assert_fs::TempDir::new().expect("create parent");
    let a = parent.child("00-a");
    let b = parent.child("00-b");
    let c = parent.child("plain");
    a.create_dir_all().expect("create 00-a");
    b.create_dir_all().expect("create 00-b");
    c.create_dir_all().expect("create plain");
    a.child("x.txt").write_str("shared").expect("write a");
    b.child("x.txt").write_str("shared").expect("write b");
    c.child("x.txt").write_str("shared").expect("write c");

    cargo_bin_cmd!("mddedupe")
        .current_dir(parent.path())
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .arg(parent.path().to_str().unwrap())
        .assert()
        .success()
        .stdout(predicates::str::contains("2 duplicate files"))
        .stdout(predicates::str::contains("1 removable"))
        .stdout(predicates::str::contains("1 protected and kept"));
}

#[test]
fn cli_bad_config_path_exits_non_zero() {
    let temp = create_duplicate_fixture();
    cargo_bin_cmd!("mddedupe")
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            temp.path().to_str().unwrap(),
            "--config",
            "definitely-not-a-real-config-xyz.toml",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("Failed to read config file"));
}

#[test]
fn cli_bad_protect_glob_exits_non_zero() {
    let temp = create_duplicate_fixture();
    cargo_bin_cmd!("mddedupe")
        .current_dir(temp.path())
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([temp.path().to_str().unwrap(), "--protect-dir", "["])
        .assert()
        .failure()
        .stderr(predicates::str::contains("Invalid protect glob"));
}

// --- Coverage gaps: policy exercised through the real binary --------------

#[test]
fn cli_config_cwd_discovery_protects_named_copy() {
    // Exercise the binary's REAL `./.mddedupe.toml` auto-discovery (resolved
    // against the process current directory, HLD §4.2), not `resolve_keep_policy`
    // with an injected base. We write a config whose ONLY protect rule keeps files
    // named `keepme.*`, and we set `protect-dir = []` + `fallback = "lexical"` so
    // the built-in convention (`0*` dirs, `00-*` names, `oldest`) cannot interfere.
    //
    // Under that config the survivor is provably driven by the config: the kept
    // copy `keepme.txt` sorts AFTER the victim `aaa.txt` lexically, so a neutral
    // `lexical` fallback alone would keep `aaa.txt`. The fact that `keepme.txt`
    // survives proves the config's protect-name rule loaded and took effect.
    let temp = assert_fs::TempDir::new().expect("create temp dir");
    temp.child(".mddedupe.toml")
        .write_str(
            "[keep]\nprotect-dir = []\nprotect-name = [\"keepme.*\"]\nfallback = \"lexical\"\n",
        )
        .expect("write config");
    let kept = temp.child("keepme.txt");
    let victim = temp.child("aaa.txt");
    kept.write_str("shared content").expect("write kept");
    victim.write_str("shared content").expect("write victim");

    cargo_bin_cmd!("mddedupe")
        // CWD is the temp dir, so `./.mddedupe.toml` discovery finds OUR config.
        .current_dir(temp.path())
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            temp.path().to_str().unwrap(),
            "--action",
            "delete",
            "--force",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "KEPT (protected: name keepme.txt)",
        ));

    assert!(
        kept.path().exists(),
        "keepme.txt must be protected by the discovered config and kept"
    );
    assert!(
        !victim.path().exists(),
        "aaa.txt must be deleted (config protected only keepme.*; lexical fallback \
         would otherwise have kept the alphabetically-first aaa.txt)"
    );
}

#[test]
fn cli_malformed_config_unknown_field_rejected() {
    // A `.mddedupe.toml` with a typo'd key must be rejected end to end by
    // `deny_unknown_fields`. The existing CLI config-error test only covers a
    // MISSING file; this covers a present-but-malformed one supplied via
    // `--config`. The binary must exit non-zero with the parse-error wording and
    // name the offending field so the user can fix the typo.
    let temp = create_duplicate_fixture();
    let config = NamedTempFile::new("bad.mddedupe.toml").expect("create config file");
    config
        .write_str("[keep]\nprotct-dir = [\"x\"]\n")
        .expect("write malformed config");

    cargo_bin_cmd!("mddedupe")
        .current_dir(temp.path())
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            temp.path().to_str().unwrap(),
            "--config",
            config.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("Failed to parse config file"))
        .stderr(predicates::str::contains("protct-dir"));
}

#[test]
fn cli_delete_all_protected_group_is_noop() {
    // Every copy in the hash group is protected by the convention default (all
    // live under `0*` directories), so there is no victim. A `--action delete
    // --force` run must succeed, delete NOTHING, and report zero work
    // ("Successes: 0 / 0"). No flags / no config => the live convention default.
    let parent = assert_fs::TempDir::new().expect("create parent");
    let a = parent.child("00-a");
    let b = parent.child("00-b");
    a.create_dir_all().expect("create 00-a");
    b.create_dir_all().expect("create 00-b");
    let copy_a = a.child("x.txt");
    let copy_b = b.child("x.txt");
    copy_a.write_str("shared content").expect("write a");
    copy_b.write_str("shared content").expect("write b");

    cargo_bin_cmd!("mddedupe")
        .current_dir(parent.path())
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            parent.path().to_str().unwrap(),
            "--action",
            "delete",
            "--force",
        ])
        .assert()
        .success()
        // Every copy protected => redundancy 1, removable 0; the divergent
        // summary line reports the removable figure explicitly.
        .stdout(predicates::str::contains("0 removable"))
        // No victims => no work performed.
        .stdout(predicates::str::contains(
            "Operation complete. Successes: 0 / 0",
        ));

    assert!(
        copy_a.path().exists() && copy_b.path().exists(),
        "every copy is protected; nothing may be deleted"
    );
}

#[test]
fn cli_move_action_relocates_only_unprotected_victims() {
    // The action path (not just `delete`) is policy-driven. With the convention
    // default a `00-*` master is protected; the plain duplicate is the lone victim.
    // `--action move --dest <dir> --force` must leave the master in place and
    // relocate only the victim into the destination directory.
    let (temp, master, plain) = create_protect_fixture();
    let dest = assert_fs::TempDir::new().expect("create dest");

    cargo_bin_cmd!("mddedupe")
        .current_dir(temp.path())
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            temp.path().to_str().unwrap(),
            "--action",
            "move",
            "--dest",
            dest.path().to_str().unwrap(),
            "--force",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "KEPT (protected: name 00-master.txt)",
        ))
        .stdout(predicates::str::contains(
            "Operation complete. Successes: 1 / 1",
        ));

    assert!(
        master.exists(),
        "the 00-* protected master must stay in place during a move action"
    );
    assert!(
        !plain.exists(),
        "the unprotected plain copy must be moved out of the scan tree"
    );
    let moved = dest.path().join("copy.txt");
    assert!(
        moved.exists(),
        "the victim should have been relocated into the destination directory"
    );
}

#[test]
fn cli_divergent_two_metric_summary_json() {
    // With a group that retains TWO protected survivors plus one plain victim, the
    // removable metric must be strictly less than the redundancy metric, and that
    // divergence must surface in the JSON summary (not only the text line). Two
    // copies live under `0*` dirs (protected by the convention default) and one is
    // plain: redundancy = 2 (len - 1), removable = 1 (the single victim).
    let parent = assert_fs::TempDir::new().expect("create parent");
    let a = parent.child("00-a");
    let b = parent.child("00-b");
    let c = parent.child("plain");
    a.create_dir_all().expect("create 00-a");
    b.create_dir_all().expect("create 00-b");
    c.create_dir_all().expect("create plain");
    a.child("x.txt").write_str("shared").expect("write a");
    b.child("x.txt").write_str("shared").expect("write b");
    c.child("x.txt").write_str("shared").expect("write c");

    let assert = cargo_bin_cmd!("mddedupe")
        .current_dir(parent.path())
        .env("MDDEDUPE_SCAN_PROGRESS_MS", "0")
        .env("MDDEDUPE_HASH_PROGRESS_MS", "0")
        .args([
            "--summary-format",
            "json",
            "--quiet",
            parent.path().to_str().unwrap(),
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

    let duplicate_files = summary["duplicate_files"].as_u64().unwrap();
    let removable_files = summary["removable_files"].as_u64().unwrap();
    let duplicate_wasted = summary["duplicate_wasted_bytes"].as_u64().unwrap();
    let reclaimable = summary["reclaimable_bytes"].as_u64().unwrap();

    assert_eq!(
        duplicate_files, 2,
        "redundancy is len-1 = 2 for a three-copy group"
    );
    assert_eq!(
        removable_files, 1,
        "only the single unprotected copy is removable"
    );
    assert!(
        removable_files < duplicate_files,
        "the two metrics must diverge in JSON: removable_files ({}) < duplicate_files ({})",
        removable_files,
        duplicate_files
    );
    assert!(
        reclaimable < duplicate_wasted,
        "reclaimable_bytes ({}) must be < duplicate_wasted_bytes ({}) when extra \
         protected survivors are retained",
        reclaimable,
        duplicate_wasted
    );
}
