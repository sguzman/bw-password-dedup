//! End-to-end CLI tests use fictional credentials only.
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_folder(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let folder = std::env::temp_dir().join(format!(
        "bw-dedup-cli-{label}-{}-{stamp}", std::process::id()
    ));
    fs::create_dir(&folder).unwrap();
    folder
}

fn binary(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bw-passport-dedup"))
        .args(args)
        .output()
        .unwrap()
}

fn synthetic_input(path: &Path) {
    let base = json!({
        "type": 1,
        "name": "Synthetic Example",
        "login": {
            "username": "fictional-user",
            "password": "CANARY_SecretABC",
            "totp": "CANARY_OtpSeed",
            "uris": [{"uri": "https://example.test/login"}]
        }
    });
    let mut distinct = base.clone();
    distinct["login"]["password"] = json!("CANARY_secretabc");
    let mut notes = base.clone();
    notes["notes"] = json!("CANARY_PrivateNotes");
    let document = json!({
        "encrypted": false,
        "folders": [],
        "items": [base.clone(), base, distinct, notes]
    });
    fs::write(path, serde_json::to_vec(&document).unwrap()).unwrap();
}

#[test]
fn dry_run_does_not_create_export_or_report() {
    let folder = temp_folder("dry");
    let input = folder.join("original.json");
    let output = folder.join("clean.json");
    synthetic_input(&input);
    let original = fs::read(&input).unwrap();
    let run = binary(&["--input", input.to_str().unwrap(), "--output",
        output.to_str().unwrap(), "--dry-run"]);
    assert!(run.status.success(), "dry-run failed: {:?}", run.status);
    assert!(!output.exists());
    assert_eq!(fs::read(&input).unwrap(), original);
    let disallowed = binary(&["--input", input.to_str().unwrap(), "--output",
        output.to_str().unwrap(), "--dry-run", "--report",
        folder.join("report.json").to_str().unwrap()]);
    assert!(!disallowed.status.success());
    assert!(!folder.join("report.json").exists());
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn end_to_end_export_preserves_distinct_records_and_redacts_report() {
    let folder = temp_folder("merge");
    let input = folder.join("original.json");
    let output = folder.join("clean.json");
    let report = folder.join("report.json");
    synthetic_input(&input);
    let run = binary(&["--input", input.to_str().unwrap(), "--output",
        output.to_str().unwrap(), "--report", report.to_str().unwrap()]);
    assert!(run.status.success(), "export failed: {:?}", run.status);
    let parsed: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let records = parsed["items"].as_array().unwrap();
    assert_eq!(records.len(), 3, "only one byte-identical entry may disappear");
    assert_eq!(records[1]["login"]["password"], "CANARY_secretabc");
    assert_eq!(records[2]["notes"], "CANARY_PrivateNotes");

    let report_bytes = fs::read(&report).unwrap();
    let report_text = String::from_utf8(report_bytes).unwrap();
    for canary in ["CANARY_SecretABC", "CANARY_secretabc", "CANARY_OtpSeed",
        "CANARY_PrivateNotes", "fictional-user", "example.test"] {
        assert!(!report_text.contains(canary), "report leaked synthetic private material");
    }
    let report_json: Value = serde_json::from_str(&report_text).unwrap();
    assert_eq!(report_json["removed"], 1);
    assert_eq!(fs::metadata(&output).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(&report).unwrap().permissions().mode() & 0o777, 0o600);
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn existing_report_aborts_before_creating_export() {
    let folder = temp_folder("collision");
    let input = folder.join("original.json");
    let output = folder.join("clean.json");
    let report = folder.join("existing-report.json");
    synthetic_input(&input);
    fs::write(&report, b"existing report must stay intact").unwrap();
    let run = binary(&["--input", input.to_str().unwrap(), "--output",
        output.to_str().unwrap(), "--report", report.to_str().unwrap()]);
    assert!(!run.status.success());
    assert!(!output.exists());
    assert_eq!(fs::read(&report).unwrap(), b"existing report must stay intact");
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn force_replacement_creates_private_backup() {
    let folder = temp_folder("forced");
    let input = folder.join("original.json");
    let output = folder.join("clean.json");
    synthetic_input(&input);
    fs::write(&output, b"prior export").unwrap();
    let old_input = fs::read(&input).unwrap();
    let run = binary(&["--input", input.to_str().unwrap(), "--output",
        output.to_str().unwrap(), "--force"]);
    assert!(run.status.success(), "forced export failed: {:?}", run.status);
    assert_eq!(fs::read(&input).unwrap(), old_input);
    let backups: Vec<_> = fs::read_dir(&folder).unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".backup."))
        .collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(backups[0].path()).unwrap(), b"prior export");
    assert_eq!(fs::metadata(backups[0].path()).unwrap().permissions().mode() & 0o777, 0o600);
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn destructive_keep_mode_fails_closed() {
    let folder = temp_folder("keep");
    let input = folder.join("original.json");
    let output = folder.join("clean.json");
    synthetic_input(&input);
    let run = binary(&["--input", input.to_str().unwrap(),
        "--output", output.to_str().unwrap(), "--keep", "newest"]);
    assert!(!run.status.success());
    assert!(!output.exists());
    fs::remove_dir_all(folder).unwrap();
}
