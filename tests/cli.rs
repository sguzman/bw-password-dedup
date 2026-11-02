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

#[test]
fn four_browser_exports_combine_without_losing_provider_fields() {
    let folder = temp_folder("four-providers");
    let edge = folder.join("edge.csv");
    let chrome = folder.join("chrome.csv");
    let firefox = folder.join("firefox.csv");
    let apple = folder.join("apple.csv");
    let output = folder.join("consolidated.json");
    fs::write(&edge, b"name,url,username,password\nEdge,https://edge.test,e,EPass\n").unwrap();
    fs::write(&chrome, b"name,url,username,password,unknownColumn\nChrome,https://chrome.test,c,CPass,extra\n").unwrap();
    fs::write(&firefox, b"url,username,password,httpRealm,guid,timeCreated\nhttps://firefox.test,f,FPass,realm,id,123\n").unwrap();
    fs::write(&apple, b"Title,URL,Username,Password,Notes,OTPAuth\nApple,https://apple.test,a,APass,private note,otpauth://totp/EXAMPLE?secret=AA\n").unwrap();
    let edge_arg = format!("edge={}", edge.display());
    let chrome_arg = format!("chrome={}", chrome.display());
    let ff_arg = format!("firefox={}", firefox.display());
    let apple_arg = format!("apple={}", apple.display());
    let run = binary(&["--source", &edge_arg, "--source", &chrome_arg,
        "--source", &ff_arg, "--source", &apple_arg, "--output",
        output.to_str().unwrap()]);
    assert!(run.status.success(),
        "multi-provider import failed: {}", String::from_utf8_lossy(&run.stderr));
    let parsed: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let items = parsed["items"].as_array().unwrap();
    assert_eq!(items.len(), 4);
    assert_eq!(items[0]["login"]["password"], "EPass");
    assert_eq!(items[1]["login"]["password"], "CPass");
    assert_eq!(items[2]["login"]["password"], "FPass");
    assert_eq!(items[3]["notes"], "private note");
    assert_eq!(items[3]["login"]["totp"], "otpauth://totp/EXAMPLE?secret=AA");
    assert!(items[1]["fields"].as_array().unwrap().iter()
        .any(|field| field["name"] == "source.chrome.unknownColumn"
            && field["value"] == "extra"));
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn browser_and_bitwarden_inputs_preserve_original_items() {
    let folder = temp_folder("mixed");
    let input = folder.join("original.json");
    let edge = folder.join("edge.csv");
    let output = folder.join("merged.json");
    let secure_note = json!({"type": 2, "name": "fictional secure note", "notes": "synthetic"});
    fs::write(&input, serde_json::to_vec(&json!({
        "encrypted": false, "folders": [], "items": [secure_note]
    })).unwrap()).unwrap();
    fs::write(&edge, b"name,url,username,password\nEdge,https://edge.test,e,EPass\n").unwrap();
    let edge_arg = format!("edge={}", edge.display());
    let run = binary(&["--input", input.to_str().unwrap(),
        "--source", &edge_arg, "--output", output.to_str().unwrap()]);
    assert!(run.status.success(), "mixed import failed: {:?}", run.status);
    let parsed: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let records = parsed["items"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["type"], 2);
    assert_eq!(records[0]["notes"], "synthetic");
    assert_eq!(records[1]["login"]["password"], "EPass");
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn repeated_source_file_is_rejected_before_export() {
    let folder = temp_folder("source-alias");
    let input = folder.join("browser.csv");
    let output = folder.join("consolidated.json");
    fs::write(&input, b"name,url,username,password\nExample,https://example.test,u,p\n").unwrap();
    let edge_arg = format!("edge={}", input.display());
    let chrome_arg = format!("chrome={}", input.display());
    let run = binary(&["--source", &edge_arg, "--source", &chrome_arg,
        "--output", output.to_str().unwrap()]);
    assert!(!run.status.success());
    assert!(!output.exists());
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn bad_provider_export_prevents_partial_consolidation() {
    let folder = temp_folder("bad-provider");
    let edge = folder.join("edge.csv");
    let apple = folder.join("apple.csv");
    let output = folder.join("clean.json");
    fs::write(&edge, b"name,url,username,password\nExample,https://example.test,u,p\n").unwrap();
    fs::write(&apple, b"URL,Username,Password\nhttps://example.test,u,p\n").unwrap();
    let edge_arg = format!("edge={}", edge.display());
    let apple_arg = format!("apple={}", apple.display());
    let run = binary(&["--source", &edge_arg, "--source", &apple_arg,
        "--output", output.to_str().unwrap()]);
    assert!(!run.status.success());
    assert!(!output.exists());
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn browser_import_order_changes_order_not_content() {
    let folder = temp_folder("order");
    let edge = folder.join("edge.csv");
    let apple = folder.join("apple.csv");
    let first = folder.join("first.json");
    let second = folder.join("second.json");
    fs::write(&edge, b"name,url,username,password\nEdge,https://edge.test,e,EPass\n").unwrap();
    fs::write(&apple, b"Title,URL,Username,Password,Notes,OTPAuth\nApple,https://apple.test,a,APass,note,otpauth://totp/EXAMPLE?secret=AA\n").unwrap();
    let edge_arg = format!("edge={}", edge.display());
    let apple_arg = format!("apple={}", apple.display());
    let run_a = binary(&["--source", &edge_arg, "--source", &apple_arg,
        "--output", first.to_str().unwrap()]);
    let run_b = binary(&["--source", &apple_arg, "--source", &edge_arg,
        "--output", second.to_str().unwrap()]);
    assert!(run_a.status.success());
    assert!(run_b.status.success());
    let mut items_a: Vec<Value> = serde_json::from_slice::<Value>(&fs::read(&first).unwrap())
        .unwrap()["items"].as_array().unwrap().clone();
    let mut items_b: Vec<Value> = serde_json::from_slice::<Value>(&fs::read(&second).unwrap())
        .unwrap()["items"].as_array().unwrap().clone();
    items_a.sort_by_key(|item| item["name"].as_str().unwrap().to_string());
    items_b.sort_by_key(|item| item["name"].as_str().unwrap().to_string());
    assert_eq!(items_a, items_b);
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn encrypted_bitwarden_json_fails_without_creating_output() {
    let folder = temp_folder("encrypted");
    let input = folder.join("encrypted.json");
    let output = folder.join("output.json");
    fs::write(&input, serde_json::to_vec(&json!({
        "encrypted": true, "folders": [], "items": []
    })).unwrap()).unwrap();
    let run = binary(&["--input", input.to_str().unwrap(),
        "--output", output.to_str().unwrap()]);
    assert!(!run.status.success());
    assert!(!output.exists());
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn typed_bitwarden_items_and_folders_roundtrip_unchanged() {
    let folder = temp_folder("typed-roundtrip");
    let input = folder.join("vault.json");
    let output = folder.join("clean.json");
    let original = json!({
        "encrypted": false,
        "folders": [{"id": "folder-123", "name": "Fictional archive"}],
        "items": [
            {"type":1, "name":"login", "folderId":"folder-123",
             "notes":"not secret", "fields":[{"name":"custom", "value":"example", "type":0}],
             "login":{"username":"f", "password":"synthetic", "totp":"otpauth://test",
                      "uris":[{"uri":"https://example.test","match":null}]}},
            {"type":2, "name":"secure note", "notes":"fictional note"},
            {"type":3, "name":"card", "card":{"number":"NOT-A-REAL-CARD"}},
            {"type":4, "name":"identity", "identity":{"firstName":"Synthetic"}},
            {"type":99, "name":"unknown future item", "futureField":{"a":[1,2,3]}}
        ]
    });
    fs::write(&input, serde_json::to_vec(&original).unwrap()).unwrap();
    let run = binary(&["--input", input.to_str().unwrap(),
        "--output", output.to_str().unwrap()]);
    assert!(run.status.success());
    let roundtrip: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(roundtrip, original);
    fs::remove_dir_all(folder).unwrap();
}
