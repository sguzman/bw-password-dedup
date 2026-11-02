//! End-to-end CLI tests use fictional credentials only.
use serde_json::{Value, json};
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
        "bw-dedup-cli-{label}-{}-{stamp}",
        std::process::id()
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
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--dry-run",
    ]);
    assert!(run.status.success(), "dry-run failed: {:?}", run.status);
    assert!(!output.exists());
    assert_eq!(fs::read(&input).unwrap(), original);
    let disallowed = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--dry-run",
        "--report",
        folder.join("report.json").to_str().unwrap(),
    ]);
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
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
    ]);
    assert!(run.status.success(), "export failed: {:?}", run.status);
    let parsed: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let records = parsed["items"].as_array().unwrap();
    assert_eq!(
        records.len(),
        3,
        "only one byte-identical entry may disappear"
    );
    assert_eq!(records[1]["login"]["password"], "CANARY_secretabc");
    assert_eq!(records[2]["notes"], "CANARY_PrivateNotes");

    let report_bytes = fs::read(&report).unwrap();
    let report_text = String::from_utf8(report_bytes).unwrap();
    for canary in [
        "CANARY_SecretABC",
        "CANARY_secretabc",
        "CANARY_OtpSeed",
        "CANARY_PrivateNotes",
        "fictional-user",
        "example.test",
    ] {
        assert!(
            !report_text.contains(canary),
            "report leaked synthetic private material"
        );
    }
    let report_json: Value = serde_json::from_str(&report_text).unwrap();
    assert_eq!(report_json["removed"], 1);
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&report).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn stale_incomplete_marker_blocks_cli_publication_until_inspected() {
    let folder = temp_folder("incomplete-marker");
    let input = folder.join("fictional-input.json");
    let output = folder.join("clean.json");
    let report = folder.join("report.json");
    let marker = folder.join(".clean.json.bw-dedup.incomplete");
    synthetic_input(&input);
    let originals = fs::read(&input).unwrap();

    // Simulate a private recovery marker left by a previous interrupted run.
    fs::write(&marker, b"incomplete fictional export").unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    let args = [
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
    ];
    let blocked = binary(&args);
    assert!(!blocked.status.success());
    assert!(
        String::from_utf8_lossy(&blocked.stderr).contains("incomplete export"),
        "failure must explain the recovery marker"
    );
    assert_eq!(fs::read(&marker).unwrap(), b"incomplete fictional export");
    assert_eq!(fs::read(&input).unwrap(), originals);
    assert!(!output.exists());
    assert!(!report.exists());

    // Only after explicitly inspecting all destinations in this fictional
    // test can the marker be cleared for a separate clean export attempt.
    fs::remove_file(&marker).unwrap();
    let completed = binary(&args);
    assert!(
        completed.status.success(),
        "synthetic export failed: {}",
        String::from_utf8_lossy(&completed.stderr)
    );
    assert!(output.exists());
    assert!(report.exists());
    assert!(!marker.exists());
    assert_eq!(fs::read(&input).unwrap(), originals);
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
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
    ]);
    assert!(!run.status.success());
    assert!(!output.exists());
    assert_eq!(
        fs::read(&report).unwrap(),
        b"existing report must stay intact"
    );
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn writable_by_others_destination_is_rejected_before_any_export() {
    let folder = temp_folder("untrusted-destination");
    let source = folder.join("fictional-input.json");
    synthetic_input(&source);
    let original = fs::read(&source).unwrap();

    let shared = folder.join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    let output = shared.join("credentials.json");
    let report = shared.join("report.json");
    let run = binary(&[
        "--input",
        source.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
    ]);
    assert!(!run.status.success());
    assert!(!output.exists());
    assert!(!report.exists());
    assert_eq!(fs::read(&source).unwrap(), original);

    let key = shared.join("review.key");
    let init = binary(&["--init-review-key", key.to_str().unwrap()]);
    assert!(!init.status.success());
    assert!(!key.exists());

    fs::set_permissions(&shared, fs::Permissions::from_mode(0o700)).unwrap();
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
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--force",
    ]);
    assert!(
        run.status.success(),
        "forced export failed: {:?}",
        run.status
    );
    assert_eq!(fs::read(&input).unwrap(), old_input);
    let backups: Vec<_> = fs::read_dir(&folder)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".backup."))
        .collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(backups[0].path()).unwrap(), b"prior export");
    assert_eq!(
        fs::metadata(backups[0].path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn destructive_keep_mode_fails_closed() {
    let folder = temp_folder("keep");
    let input = folder.join("original.json");
    let output = folder.join("clean.json");
    synthetic_input(&input);
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--keep",
        "newest",
    ]);
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
    fs::write(
        &edge,
        b"name,url,username,password\nEdge,https://edge.test,e,EPass\n",
    )
    .unwrap();
    fs::write(
        &chrome,
        b"name,url,username,password,unknownColumn\nChrome,https://chrome.test,c,CPass,extra\n",
    )
    .unwrap();
    fs::write(&firefox, b"url,username,password,httpRealm,guid,timeCreated\nhttps://firefox.test,f,FPass,realm,id,123\n").unwrap();
    fs::write(&apple, b"Title,URL,Username,Password,Notes,OTPAuth\nApple,https://apple.test,a,APass,private note,otpauth://totp/EXAMPLE?secret=AA\n").unwrap();
    let edge_arg = format!("edge={}", edge.display());
    let chrome_arg = format!("chrome={}", chrome.display());
    let ff_arg = format!("firefox={}", firefox.display());
    let apple_arg = format!("apple={}", apple.display());
    let run = binary(&[
        "--source",
        &edge_arg,
        "--source",
        &chrome_arg,
        "--source",
        &ff_arg,
        "--source",
        &apple_arg,
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(
        run.status.success(),
        "multi-provider import failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let parsed: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let items = parsed["items"].as_array().unwrap();
    assert_eq!(items.len(), 4);
    assert_eq!(items[0]["login"]["password"], "EPass");
    assert_eq!(items[1]["login"]["password"], "CPass");
    assert_eq!(items[2]["login"]["password"], "FPass");
    assert_eq!(items[3]["notes"], "private note");
    assert_eq!(
        items[3]["login"]["totp"],
        "otpauth://totp/EXAMPLE?secret=AA"
    );
    assert!(
        items[1]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |field| field["name"] == "source.chrome.unknownColumn" && field["value"] == "extra"
            )
    );
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn browser_and_bitwarden_inputs_preserve_original_items() {
    let folder = temp_folder("mixed");
    let input = folder.join("original.json");
    let edge = folder.join("edge.csv");
    let output = folder.join("merged.json");
    let secure_note = json!({"type": 2, "name": "fictional secure note", "notes": "synthetic"});
    fs::write(
        &input,
        serde_json::to_vec(&json!({
            "encrypted": false, "folders": [], "items": [secure_note]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &edge,
        b"name,url,username,password\nEdge,https://edge.test,e,EPass\n",
    )
    .unwrap();
    let edge_arg = format!("edge={}", edge.display());
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--source",
        &edge_arg,
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(
        run.status.success(),
        "mixed import failed: {:?}",
        run.status
    );
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
    fs::write(
        &input,
        b"name,url,username,password\nExample,https://example.test,u,p\n",
    )
    .unwrap();
    let edge_arg = format!("edge={}", input.display());
    let chrome_arg = format!("chrome={}", input.display());
    let run = binary(&[
        "--source",
        &edge_arg,
        "--source",
        &chrome_arg,
        "--output",
        output.to_str().unwrap(),
    ]);
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
    fs::write(
        &edge,
        b"name,url,username,password\nExample,https://example.test,u,p\n",
    )
    .unwrap();
    fs::write(&apple, b"URL,Username,Password\nhttps://example.test,u,p\n").unwrap();
    let edge_arg = format!("edge={}", edge.display());
    let apple_arg = format!("apple={}", apple.display());
    let run = binary(&[
        "--source",
        &edge_arg,
        "--source",
        &apple_arg,
        "--output",
        output.to_str().unwrap(),
    ]);
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
    fs::write(
        &edge,
        b"name,url,username,password\nEdge,https://edge.test,e,EPass\n",
    )
    .unwrap();
    fs::write(&apple, b"Title,URL,Username,Password,Notes,OTPAuth\nApple,https://apple.test,a,APass,note,otpauth://totp/EXAMPLE?secret=AA\n").unwrap();
    let edge_arg = format!("edge={}", edge.display());
    let apple_arg = format!("apple={}", apple.display());
    let run_a = binary(&[
        "--source",
        &edge_arg,
        "--source",
        &apple_arg,
        "--output",
        first.to_str().unwrap(),
    ]);
    let run_b = binary(&[
        "--source",
        &apple_arg,
        "--source",
        &edge_arg,
        "--output",
        second.to_str().unwrap(),
    ]);
    assert!(run_a.status.success());
    assert!(run_b.status.success());
    let mut items_a: Vec<Value> = serde_json::from_slice::<Value>(&fs::read(&first).unwrap())
        .unwrap()["items"]
        .as_array()
        .unwrap()
        .clone();
    let mut items_b: Vec<Value> = serde_json::from_slice::<Value>(&fs::read(&second).unwrap())
        .unwrap()["items"]
        .as_array()
        .unwrap()
        .clone();
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
    fs::write(
        &input,
        serde_json::to_vec(&json!({
            "encrypted": true, "folders": [], "items": []
        }))
        .unwrap(),
    )
    .unwrap();
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
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
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(run.status.success());
    let roundtrip: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(roundtrip, original);
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn conflicting_browser_passwords_remain_separate_and_reported_without_secrets() {
    let folder = temp_folder("cross-browser-conflict");
    let edge = folder.join("edge.csv");
    let chrome = folder.join("chrome.csv");
    let output = folder.join("clean.json");
    let report = folder.join("redacted-report.json");
    fs::write(&edge, b"name,url,username,password\nSynthetic,https://example.test/edge,identity,SYNTH_PASSWORD_A\n").unwrap();
    fs::write(&chrome, b"name,url,username,password\nSynthetic,https://example.test/chrome,identity,SYNTH_PASSWORD_B\n").unwrap();
    let edge_arg = format!("edge={}", edge.display());
    let chrome_arg = format!("chrome={}", chrome.display());
    let run = binary(&[
        "--source",
        &edge_arg,
        "--source",
        &chrome_arg,
        "--output",
        output.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
    ]);
    assert!(run.status.success(), "CLI failed: {:?}", run.status);
    let output_data: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(output_data["items"].as_array().unwrap().len(), 2);
    let report_bytes = fs::read(&report).unwrap();
    let report: Value = serde_json::from_slice(&report_bytes).unwrap();
    assert_eq!(report["account_groups"][0]["candidates"], 2);
    assert_eq!(report["account_groups"][0]["conflicting_passwords"], true);
    assert_eq!(
        report["account_groups"][0]["decision"],
        "unresolved-preserve-all"
    );
    let report_text = String::from_utf8(report_bytes).unwrap();
    for value in [
        "SYNTH_PASSWORD_A",
        "SYNTH_PASSWORD_B",
        "example.test",
        "identity",
    ] {
        assert!(!report_text.contains(value));
    }
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn missing_or_ambiguous_account_ids_do_not_create_report_groups() {
    let folder = temp_folder("no-conflict-group");
    let edge = folder.join("edge.csv");
    let output = folder.join("out.json");
    let report = folder.join("out-report.json");
    fs::write(&edge, b"name,url,username,password\nNo account,https://example.test/, ,SECRET_A\nNo account,http://example.test/, ,SECRET_B\n").unwrap();
    let source = format!("edge={}", edge.display());
    let run = binary(&[
        "--source",
        &source,
        "--output",
        output.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
    ]);
    assert!(run.status.success());
    let data: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert!(data["account_groups"].as_array().unwrap().is_empty());
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn optional_uri_only_merge_keeps_all_uri_entries_and_preserves_unrelated_fields() {
    let folder = temp_folder("uri-union");
    let input = folder.join("original.json");
    let output = folder.join("merged.json");
    let report = folder.join("counts.json");
    let first = json!({
        "type":1,"name":"Synthetic","notes":"fictional",
        "login":{"username":"same-user","password":"SYNTH_secret","totp":"SYNTH_otp",
                 "uris":[{"uri":"https://example.test/a","match":0}]}
    });
    let mut second = first.clone();
    second["login"]["uris"] = json!([{"uri":"https://example.test/b","match":0}]);
    let original_bytes = serde_json::to_vec(&json!({"encrypted":false,
        "folders":[],"items":[first.clone(),second]}))
    .unwrap();
    fs::write(&input, &original_bytes).unwrap();
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "--merge-compatible-uris",
    ]);
    assert!(run.status.success(), "uri merge failed: {:?}", run.status);
    let data: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let entries = data["items"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["notes"], "fictional");
    assert_eq!(entries[0]["login"]["password"], "SYNTH_secret");
    assert_eq!(entries[0]["login"]["uris"].as_array().unwrap().len(), 2);
    let counts: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(counts["compatible_uri_merges"], 1);
    assert_eq!(fs::read(&input).unwrap(), original_bytes);
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn merge_audit_reconciles_chained_merges_without_leaking_secrets() {
    let folder = temp_folder("merge-audit");
    let input = folder.join("source.json");
    let output = folder.join("clean.json");
    let report = folder.join("audit.json");
    let first = json!({
        "type":1, "name":"SECRET_ACCOUNT_NAME",
        "login":{"uris":[{"uri":"https://SYNTHSECRET.test/a"}],
                 "username":"SECRET_USERNAME","password":"SECRET_PASSWORD",
                 "totp":"SECRET_TOTP"}
    });
    let mut uri_variant = first.clone();
    uri_variant["login"]["uris"] = json!([{"uri":"https://SYNTHSECRET.test/b"}]);
    let originals = json!({"encrypted":false,"folders":[],
        "items":[first.clone(),first,uri_variant]});
    let source_bytes = serde_json::to_vec(&originals).unwrap();
    fs::write(&input, &source_bytes).unwrap();
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "--merge-compatible-uris",
    ]);
    assert!(run.status.success(), "merge failed: {:?}", run.status);
    let cleaned: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(cleaned["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        cleaned["items"][0]["login"]["uris"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let report_text = fs::read_to_string(&report).unwrap();
    let audit: Value = serde_json::from_str(&report_text).unwrap();
    assert_eq!(audit["reconciliation"]["input_records"], 3);
    assert_eq!(audit["reconciliation"]["output_records"], 1);
    assert_eq!(audit["reconciliation"]["accounted_for_inputs"], 3);
    assert_eq!(
        audit["reconciliation"]["events"][0]["inputs"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    for canary in [
        "SECRET_ACCOUNT_NAME",
        "SYNTHSECRET",
        "SECRET_USERNAME",
        "SECRET_PASSWORD",
        "SECRET_TOTP",
    ] {
        assert!(!report_text.contains(canary));
    }
    assert_eq!(fs::read(&input).unwrap(), source_bytes);
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn opt_in_field_union_preserves_apple_note_and_edge_custom_fields() {
    let folder = temp_folder("field-union");
    let edge = folder.join("edge.csv");
    let apple = folder.join("apple.csv");
    let output = folder.join("out.json");
    let report = folder.join("audit.json");
    fs::write(&edge, b"name,url,username,password,edgeTag\nExample,https://example.test/edge,user,SamePassword,edge-value\n").unwrap();
    fs::write(&apple, b"Title,URL,Username,Password,Notes\nExample,https://example.test/apple,user,SamePassword,Important fictional note\n").unwrap();
    let edge_original = fs::read(&edge).unwrap();
    let apple_original = fs::read(&apple).unwrap();
    let edge_arg = format!("edge={}", edge.display());
    let apple_arg = format!("apple={}", apple.display());
    let run = binary(&[
        "--source",
        &edge_arg,
        "--source",
        &apple_arg,
        "--output",
        output.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "--merge-compatible-fields",
    ]);
    assert!(
        run.status.success(),
        "field import failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let exported: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let items = exported["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["notes"], "Important fictional note");
    assert_eq!(items[0]["login"]["password"], "SamePassword");
    assert_eq!(items[0]["login"]["uris"].as_array().unwrap().len(), 2);
    let fields = items[0]["fields"].as_array().unwrap();
    assert!(
        fields
            .iter()
            .any(|f| f["name"] == "source.edge.edgeTag" && f["value"] == "edge-value")
    );
    assert_eq!(
        fields
            .iter()
            .filter(|f| f["name"] == "migration.source")
            .count(),
        2
    );
    assert_eq!(
        fields
            .iter()
            .filter(|f| f["name"] == "migration.record")
            .count(),
        2
    );
    let report_text = fs::read_to_string(&report).unwrap();
    let audit: Value = serde_json::from_str(&report_text).unwrap();
    assert_eq!(audit["compatible_field_merges"], 1);
    assert_eq!(audit["reconciliation"]["compatible_field_merges"], 1);
    assert_eq!(audit["reconciliation"]["accounted_for_inputs"], 2);
    for canary in [
        "SamePassword",
        "Important fictional note",
        "example.test",
        "edge-value",
    ] {
        assert!(!report_text.contains(canary));
    }
    assert_eq!(fs::read(&edge).unwrap(), edge_original);
    assert_eq!(fs::read(&apple).unwrap(), apple_original);
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn review_template_is_private_redacted_and_non_executable() {
    let folder = temp_folder("review-template");
    let input = folder.join("source.json");
    let output = folder.join("clean.json");
    let template = folder.join("review.json");
    let one = json!({"type":1,"name":"PRIVATE_NAME","login":{
        "uris":[{"uri":"https://private-origin.test/a"}],
        "username":"private-user","password":"SYNTH_PASS_1","totp":"SYNTH_TOTP"}});
    let mut two = one.clone();
    two["login"]["password"] = json!("SYNTH_PASS_2");
    fs::write(
        &input,
        serde_json::to_vec(&json!({
            "encrypted":false,"folders":[],"items":[one,two]
        }))
        .unwrap(),
    )
    .unwrap();
    let original_bytes = fs::read(&input).unwrap();
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--review-template",
        template.to_str().unwrap(),
    ]);
    assert!(
        run.status.success(),
        "review template failed: {:?}",
        run.status
    );
    let file = fs::read(&template).unwrap();
    let value: Value = serde_json::from_slice(&file).unwrap();
    assert_eq!(value["kind"], "review-template-not-executable");
    assert_eq!(value["groups"][0]["decision"], "defer");
    assert_eq!(value["groups"][0]["references"][0]["input_position"], 1);
    assert_eq!(value["groups"][0]["references"][1]["input_position"], 2);
    assert_eq!(
        fs::metadata(&template).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let displayed = String::from_utf8(file).unwrap();
    for text in [
        "PRIVATE_NAME",
        "private-origin.test",
        "private-user",
        "SYNTH_PASS_1",
        "SYNTH_PASS_2",
        "SYNTH_TOTP",
    ] {
        assert!(!displayed.contains(text));
    }
    assert_eq!(fs::read(&input).unwrap(), original_bytes);
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn review_template_collisions_fail_before_export() {
    let folder = temp_folder("review-collision");
    let input = folder.join("source.json");
    let output = folder.join("output.json");
    let template = folder.join("template.json");
    synthetic_input(&input);
    fs::write(&template, b"must survive").unwrap();
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--review-template",
        template.to_str().unwrap(),
    ]);
    assert!(!run.status.success());
    assert!(!output.exists());
    assert_eq!(fs::read(&template).unwrap(), b"must survive");
    let dry = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--dry-run",
        "--review-template",
        folder.join("new-template.json").to_str().unwrap(),
    ]);
    assert!(!dry.status.success());
    assert!(!folder.join("new-template.json").exists());
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn sealed_choose_one_keeps_only_explicitly_selected_login_and_audits_exclusion() {
    let folder = temp_folder("sealed-choose");
    let source = folder.join("source.json");
    let key = folder.join("review.key");
    let template = folder.join("review.json");
    let preview = folder.join("preview.json");
    let output = folder.join("selected.json");
    let report = folder.join("audit.json");
    let first = json!({"type":1,"name":"Synthetic","login":{
        "uris":[{"uri":"https://example.test/a"}],
        "username":"fictional-user","password":"SyntheticSecretA","totp":"SyntheticOTP"}});
    let mut second = first.clone();
    second["login"]["password"] = json!("SyntheticSecretB");
    fs::write(
        &source,
        serde_json::to_vec(&json!({"encrypted":false,
        "folders":[],"items":[first.clone(),second]}))
        .unwrap(),
    )
    .unwrap();
    let original = fs::read(&source).unwrap();
    assert!(
        binary(&["--init-review-key", key.to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        !binary(&["--init-review-key", key.to_str().unwrap()])
            .status
            .success()
    );
    let made = binary(&[
        "--input",
        source.to_str().unwrap(),
        "--review-key",
        key.to_str().unwrap(),
        "--bound-review-template",
        template.to_str().unwrap(),
        "--output",
        preview.to_str().unwrap(),
    ]);
    assert!(
        made.status.success(),
        "review generation failed: {:?}",
        made.status
    );
    let mut decisions: Value = serde_json::from_slice(&fs::read(&template).unwrap()).unwrap();
    assert_eq!(decisions["schema_version"], 2);
    assert_eq!(decisions["groups"].as_array().unwrap().len(), 1);
    decisions["groups"][0]["decision"] = json!("choose-one");
    decisions["groups"][0]["selected_input_position"] = json!(2);
    fs::write(&template, serde_json::to_vec_pretty(&decisions).unwrap()).unwrap();
    let run = binary(&[
        "--input",
        source.to_str().unwrap(),
        "--review-key",
        key.to_str().unwrap(),
        "--decisions",
        template.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
    ]);
    assert!(
        run.status.success(),
        "decision replay failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let result: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(result["items"].as_array().unwrap().len(), 1);
    assert_eq!(result["items"][0]["login"]["password"], "SyntheticSecretB");
    let report_text = fs::read_to_string(&report).unwrap();
    let audit: Value = serde_json::from_str(&report_text).unwrap();
    assert_eq!(audit["reconciliation"]["review_excluded_records"], 1);
    assert_eq!(audit["reconciliation"]["accounted_for_inputs"], 2);
    assert_eq!(audit["review_decisions"][0]["action"], "choose-one");
    assert_eq!(audit["review_decisions"][0]["excluded_inputs"][0], 1);
    for canary in [
        "SyntheticSecretA",
        "SyntheticSecretB",
        "fictional-user",
        "example.test",
    ] {
        assert!(!report_text.contains(canary));
    }
    assert_eq!(fs::read(&source).unwrap(), original);
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn sealed_decisions_reject_changed_sources_or_wrong_key_without_writes() {
    let folder = temp_folder("sealed-stale");
    let source = folder.join("source.json");
    let key = folder.join("key.bin");
    let wrong_key = folder.join("other-key.bin");
    let manifest = folder.join("manifest.json");
    let preview = folder.join("preview.json");
    let out = folder.join("replay.json");
    let a = json!({"type":1,"name":"Synthetic","login":{
        "uris":[{"uri":"https://example.test/a"}],
        "username":"fictional","password":"PASS_A"}});
    let mut b = a.clone();
    b["login"]["password"] = json!("PASS_B");
    let root = json!({"encrypted":false,"folders":[],"items":[a,b]});
    fs::write(&source, serde_json::to_vec(&root).unwrap()).unwrap();
    assert!(
        binary(&["--init-review-key", key.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        binary(&["--init-review-key", wrong_key.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        binary(&[
            "--input",
            source.to_str().unwrap(),
            "--review-key",
            key.to_str().unwrap(),
            "--bound-review-template",
            manifest.to_str().unwrap(),
            "--output",
            preview.to_str().unwrap()
        ])
        .status
        .success()
    );
    let mut doc: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    doc["groups"][0]["decision"] = json!("choose-one");
    doc["groups"][0]["selected_input_position"] = json!(1);
    fs::write(&manifest, serde_json::to_vec(&doc).unwrap()).unwrap();
    let wrong = binary(&[
        "--input",
        source.to_str().unwrap(),
        "--review-key",
        wrong_key.to_str().unwrap(),
        "--decisions",
        manifest.to_str().unwrap(),
        "--output",
        out.to_str().unwrap(),
    ]);
    assert!(!wrong.status.success());
    assert!(!out.exists());
    let mut mutated = root.clone();
    mutated["items"][0]["login"]["password"] = json!("PASS_CHANGED");
    fs::write(&source, serde_json::to_vec(&mutated).unwrap()).unwrap();
    let stale = binary(&[
        "--input",
        source.to_str().unwrap(),
        "--review-key",
        key.to_str().unwrap(),
        "--decisions",
        manifest.to_str().unwrap(),
        "--output",
        out.to_str().unwrap(),
    ]);
    assert!(!stale.status.success());
    assert!(!out.exists());
    fs::write(&source, serde_json::to_vec(&root).unwrap()).unwrap();
    doc["groups"][0]["selected_input_position"] = json!(999);
    fs::write(&manifest, serde_json::to_vec(&doc).unwrap()).unwrap();
    let invalid = binary(&[
        "--input",
        source.to_str().unwrap(),
        "--review-key",
        key.to_str().unwrap(),
        "--decisions",
        manifest.to_str().unwrap(),
        "--output",
        out.to_str().unwrap(),
    ]);
    assert!(!invalid.status.success());
    assert!(!out.exists());
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn snapshot_bound_merge_nonsecret_requires_compatible_data() {
    let folder = temp_folder("sealed-merge");
    let input = folder.join("source.json");
    let key = folder.join("key.bin");
    let manifest = folder.join("manifest.json");
    let preview = folder.join("preview.json");
    let output = folder.join("merged.json");
    let a = json!({"type":1,"name":"Synthetic","login":{
        "uris":[{"uri":"https://example.test/a"}],
        "username":"fictional","password":"SamePassword","totp":"SameOTP"}});
    let mut b = a.clone();
    b["login"]["uris"] = json!([{"uri":"https://example.test/b"}]);
    b["notes"] = json!("Important fictional note");
    fs::write(
        &input,
        serde_json::to_vec(&json!({"encrypted":false,
        "folders":[],"items":[a,b]}))
        .unwrap(),
    )
    .unwrap();
    assert!(
        binary(&["--init-review-key", key.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        binary(&[
            "--input",
            input.to_str().unwrap(),
            "--review-key",
            key.to_str().unwrap(),
            "--bound-review-template",
            manifest.to_str().unwrap(),
            "--output",
            preview.to_str().unwrap()
        ])
        .status
        .success()
    );
    let mut doc: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    doc["groups"][0]["decision"] = json!("merge-nonsecret");
    fs::write(&manifest, serde_json::to_vec(&doc).unwrap()).unwrap();
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--review-key",
        key.to_str().unwrap(),
        "--decisions",
        manifest.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(
        run.status.success(),
        "manual merge failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let result: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(result["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        result["items"][0]["login"]["uris"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(result["items"][0]["notes"], "Important fictional note");
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn bound_review_rejects_reordered_sources_changed_policy_and_tampered_groups() {
    let folder = temp_folder("review-order");
    let edge = folder.join("edge.csv");
    let chrome = folder.join("chrome.csv");
    let key = folder.join("review.key");
    let manifest = folder.join("decisions.json");
    let preview = folder.join("preview.json");
    let output = folder.join("clean.json");
    fs::write(
        &edge,
        b"name,url,username,password\nSynthetic,https://example.test/a,user,SecretA\n",
    )
    .unwrap();
    fs::write(
        &chrome,
        b"name,url,username,password\nSynthetic,https://example.test/b,user,SecretB\n",
    )
    .unwrap();
    assert!(
        binary(&["--init-review-key", key.to_str().unwrap()])
            .status
            .success()
    );
    let a = format!("edge={}", edge.display());
    let b = format!("chrome={}", chrome.display());
    let generated = binary(&[
        "--source",
        &a,
        "--source",
        &b,
        "--review-key",
        key.to_str().unwrap(),
        "--bound-review-template",
        manifest.to_str().unwrap(),
        "--output",
        preview.to_str().unwrap(),
    ]);
    assert!(generated.status.success(), "{:?}", generated.status);
    let mut template: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    template["groups"][0]["decision"] = json!("keep-both");
    fs::write(&manifest, serde_json::to_vec(&template).unwrap()).unwrap();

    let reordered = binary(&[
        "--source",
        &b,
        "--source",
        &a,
        "--review-key",
        key.to_str().unwrap(),
        "--decisions",
        manifest.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(!reordered.status.success());
    assert!(!output.exists());

    let changed_policy = binary(&[
        "--source",
        &a,
        "--source",
        &b,
        "--review-key",
        key.to_str().unwrap(),
        "--decisions",
        manifest.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--policy-key",
        "domain",
    ]);
    assert!(!changed_policy.status.success());
    assert!(!output.exists());

    template["groups"][0]["references"][0]["input_position"] = json!(999);
    fs::write(&manifest, serde_json::to_vec(&template).unwrap()).unwrap();
    let tampered = binary(&[
        "--source",
        &a,
        "--source",
        &b,
        "--review-key",
        key.to_str().unwrap(),
        "--decisions",
        manifest.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(!tampered.status.success());
    assert!(!output.exists());
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn identical_bound_decisions_replay_deterministically_and_reject_bad_permissions() {
    let folder = temp_folder("review-idempotent");
    let source = folder.join("source.json");
    let key = folder.join("key.bin");
    let decisions = folder.join("review.json");
    let preview = folder.join("preview.json");
    let first_out = folder.join("first.json");
    let second_out = folder.join("second.json");
    let one = json!({"type":1,"name":"Synthetic","login":{
        "uris":[{"uri":"https://example.test/a"}],
        "username":"user","password":"SecretA"}});
    let mut two = one.clone();
    two["login"]["password"] = json!("SecretB");
    fs::write(
        &source,
        serde_json::to_vec(&json!({"encrypted":false,
        "folders":[],"items":[one,two]}))
        .unwrap(),
    )
    .unwrap();
    assert!(
        binary(&["--init-review-key", key.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        binary(&[
            "--input",
            source.to_str().unwrap(),
            "--review-key",
            key.to_str().unwrap(),
            "--bound-review-template",
            decisions.to_str().unwrap(),
            "--output",
            preview.to_str().unwrap()
        ])
        .status
        .success()
    );
    let mut edited: Value = serde_json::from_slice(&fs::read(&decisions).unwrap()).unwrap();
    edited["groups"][0]["decision"] = json!("keep-both");
    fs::write(&decisions, serde_json::to_vec(&edited).unwrap()).unwrap();
    for path in [&first_out, &second_out] {
        let result = binary(&[
            "--input",
            source.to_str().unwrap(),
            "--review-key",
            key.to_str().unwrap(),
            "--decisions",
            decisions.to_str().unwrap(),
            "--output",
            path.to_str().unwrap(),
        ]);
        assert!(result.status.success(), "{:?}", result.status);
    }
    assert_eq!(
        fs::read(&first_out).unwrap(),
        fs::read(&second_out).unwrap()
    );
    let edited_permissions = fs::Permissions::from_mode(0o644);
    fs::set_permissions(&decisions, edited_permissions).unwrap();
    let bad = binary(&[
        "--input",
        source.to_str().unwrap(),
        "--review-key",
        key.to_str().unwrap(),
        "--decisions",
        decisions.to_str().unwrap(),
        "--output",
        folder.join("bad.json").to_str().unwrap(),
    ]);
    assert!(!bad.status.success());
    assert!(!folder.join("bad.json").exists());
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn changing_totp_or_manifest_schema_fails_without_export() {
    let folder = temp_folder("review-totp");
    let source = folder.join("source.json");
    let key = folder.join("key.bin");
    let decisions = folder.join("review.json");
    let preview = folder.join("preview.json");
    let output = folder.join("clean.json");
    let one = json!({"type":1,"name":"Synthetic","login":{
        "uris":[{"uri":"https://example.test/a"}],
        "username":"user","password":"same","totp":"OtpA"}});
    let mut two = one.clone();
    two["login"]["totp"] = json!("OtpB");
    let original = json!({"encrypted":false,"folders":[],"items":[one,two]});
    fs::write(&source, serde_json::to_vec(&original).unwrap()).unwrap();
    assert!(
        binary(&["--init-review-key", key.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        binary(&[
            "--input",
            source.to_str().unwrap(),
            "--review-key",
            key.to_str().unwrap(),
            "--bound-review-template",
            decisions.to_str().unwrap(),
            "--output",
            preview.to_str().unwrap()
        ])
        .status
        .success()
    );
    let mut modified = original.clone();
    modified["items"][0]["login"]["totp"] = json!("OtpChanged");
    fs::write(&source, serde_json::to_vec(&modified).unwrap()).unwrap();
    let stale = binary(&[
        "--input",
        source.to_str().unwrap(),
        "--review-key",
        key.to_str().unwrap(),
        "--decisions",
        decisions.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(!stale.status.success());
    assert!(!output.exists());
    fs::write(&source, serde_json::to_vec(&original).unwrap()).unwrap();
    let mut manifest: Value = serde_json::from_slice(&fs::read(&decisions).unwrap()).unwrap();
    manifest["schema_version"] = json!(999);
    fs::write(&decisions, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let unsupported = binary(&[
        "--input",
        source.to_str().unwrap(),
        "--review-key",
        key.to_str().unwrap(),
        "--decisions",
        decisions.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(!unsupported.status.success());
    assert!(!output.exists());
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn opt_in_vaultwarden_schema_validation_accepts_documented_individual_items() {
    let folder = temp_folder("vaultwarden-schema");
    let input = folder.join("source.json");
    let output = folder.join("compatible.json");
    let source = json!({"encrypted":false,"folders":[],"items":[
        {"type":1,"name":"Synthetic",
         "login":{"username":"fictional","password":"SyntheticSecret",
                  "uris":[{"uri":"https://example.test","match":null}]}},
        {"type":2,"name":"Fictional note","secureNote":{}},
        {"type":3,"name":"Fictional card","card":{}},
        {"type":4,"name":"Fictional identity","identity":{}}
    ]});
    fs::write(&input, serde_json::to_vec(&source).unwrap()).unwrap();
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--validate-vaultwarden-import",
    ]);
    assert!(
        run.status.success(),
        "schema preflight failed: {:?}",
        run.status
    );
    let result: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(result, source);
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn unsupported_vaultwarden_item_fails_validation_without_losing_source() {
    let folder = temp_folder("vaultwarden-unsupported");
    let input = folder.join("source.json");
    let output = folder.join("compatible.json");
    let source = json!({"encrypted":false,"folders":[],"items":[
        {"type":99,"name":"Synthetic new item","opaque":{"future":true}}
    ]});
    let bytes = serde_json::to_vec(&source).unwrap();
    fs::write(&input, &bytes).unwrap();
    let strict = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--validate-vaultwarden-import",
    ]);
    assert!(!strict.status.success());
    assert!(!output.exists());
    assert_eq!(fs::read(&input).unwrap(), bytes);
    let preserved = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(preserved.status.success());
    let result: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(result, source);
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn passflick_projection_filters_by_provenance_and_retains_distinct_passwords() {
    let folder = temp_folder("passflick-projection");
    let edge = folder.join("edge.csv");
    let chrome = folder.join("chrome.csv");
    let clean = folder.join("clean.json");
    let pass_edge = folder.join("pass-edge.csv");
    let pass_chrome = folder.join("pass-chrome.csv");
    fs::write(
        &edge,
        b"name,url,username,password\nSynthetic,https://example.test/a,user,SECRET_A\n",
    )
    .unwrap();
    fs::write(
        &chrome,
        b"name,url,username,password\nSynthetic,https://example.test/b,user,SECRET_B\n",
    )
    .unwrap();
    let edge_source = format!("edge={}", edge.display());
    let chrome_source = format!("chrome={}", chrome.display());
    let edge_projection = format!("edge={}", pass_edge.display());
    let chrome_projection = format!("chrome={}", pass_chrome.display());
    let result = binary(&[
        "--source",
        &edge_source,
        "--source",
        &chrome_source,
        "--output",
        clean.to_str().unwrap(),
        "--passflick-export",
        &edge_projection,
        "--passflick-export",
        &chrome_projection,
    ]);
    assert!(
        result.status.success(),
        "projection failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let a = fs::read_to_string(&pass_edge).unwrap();
    let b = fs::read_to_string(&pass_chrome).unwrap();
    assert!(a.contains("SECRET_A"));
    assert!(!a.contains("SECRET_B"));
    assert!(b.contains("SECRET_B"));
    assert!(!b.contains("SECRET_A"));
    assert_eq!(
        fs::metadata(&pass_edge).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!fs::read(&clean).unwrap().is_empty());
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn passflick_projection_refuses_empty_or_duplicate_browser_destinations_without_writes() {
    let folder = temp_folder("passflick-projection-guard");
    let input = folder.join("vault.json");
    let output = folder.join("out.json");
    let projection = folder.join("source.csv");
    let original = json!({"encrypted":false,"folders":[],"items":[
        {"type":1,"name":"Vaultwarden-only",
         "login":{"username":"user","password":"SECRET","uris":[{"uri":"https://example.test"}]}}
    ]});
    fs::write(&input, serde_json::to_vec(&original).unwrap()).unwrap();
    let arg = format!("edge={}", projection.display());
    let result = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--passflick-export",
        &arg,
    ]);
    assert!(!result.status.success());
    assert!(!projection.exists());
    assert!(!output.exists());
    let duplicate = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--passflick-export",
        &arg,
        "--passflick-export",
        &arg,
    ]);
    assert!(!duplicate.status.success());
    assert!(!output.exists());
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn five_source_fixture_preserves_case_secrets_totp_and_consumer_provenance() {
    let folder = temp_folder("five-source-qa");
    let json_input = folder.join("original.json");
    let edge = folder.join("edge.csv");
    let chrome = folder.join("chrome.csv");
    let firefox = folder.join("firefox.csv");
    let apple = folder.join("apple.csv");
    let output = folder.join("merged.json");
    let report = folder.join("counts.json");
    let pass_edge = folder.join("pass-edge.csv");
    let pass_apple = folder.join("pass-apple.csv");
    let root = json!({"encrypted":false,"folders":[],"items":[
        {"type":1,"name":"Vault only","login":{
            "uris":[{"uri":"https://example.test/private"}],
            "username":"alice","password":"V_FICTIONAL"}},
        {"type":2,"name":"Synthetic secure note","secureNote":{},
            "notes":"Sensitive fictional note"}
    ]});
    fs::write(&json_input, serde_json::to_vec(&root).unwrap()).unwrap();
    fs::write(
        &edge,
        b"name,url,username,password\nSynthetic,https://example.test/edge,alice,CasesensA\n",
    )
    .unwrap();
    fs::write(
        &chrome,
        b"name,url,username,password\nSynthetic,https://example.test/chrome,alice,casesensa\n",
    )
    .unwrap();
    fs::write(
        &firefox,
        b"url,username,password,guid\nhttps://example.test/firefox,alice,F_FICTIONAL,fake-guid\n",
    )
    .unwrap();
    fs::write(&apple,b"Title,URL,Username,Password,Notes,OTPAuth\nSynthetic,https://example.test/apple,alice,A_FICTIONAL,Fictional Apple note,otpauth://totp/Fictional?secret=FAKEOTP\n").unwrap();
    let originals =
        [&json_input, &edge, &chrome, &firefox, &apple].map(|file| fs::read(file).unwrap());
    let specs = [
        format!("edge={}", edge.display()),
        format!("chrome={}", chrome.display()),
        format!("firefox={}", firefox.display()),
        format!("apple={}", apple.display()),
    ];
    let edge_export = format!("edge={}", pass_edge.display());
    let apple_export = format!("apple={}", pass_apple.display());
    let run = binary(&[
        "--input",
        json_input.to_str().unwrap(),
        "--source",
        &specs[0],
        "--source",
        &specs[1],
        "--source",
        &specs[2],
        "--source",
        &specs[3],
        "--output",
        output.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "--validate-vaultwarden-import",
        "--passflick-export",
        &edge_export,
        "--passflick-export",
        &apple_export,
    ]);
    assert!(
        run.status.success(),
        "five-source QA failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let merged: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(merged["items"].as_array().unwrap().len(), 6);
    let contents = merged["items"].to_string();
    for canary in [
        "CasesensA",
        "casesensa",
        "F_FICTIONAL",
        "A_FICTIONAL",
        "FAKEOTP",
        "Fictional Apple note",
        "Sensitive fictional note",
        "V_FICTIONAL",
    ] {
        assert!(contents.contains(canary), "lost fictional source field");
    }
    let edge_csv = fs::read_to_string(&pass_edge).unwrap();
    let apple_csv = fs::read_to_string(&pass_apple).unwrap();
    assert!(edge_csv.contains("CasesensA"));
    assert!(!edge_csv.contains("casesensa"));
    assert!(!edge_csv.contains("V_FICTIONAL"));
    assert!(apple_csv.contains("A_FICTIONAL"));
    assert!(!apple_csv.contains("FAKEOTP"));
    let report_text = fs::read_to_string(&report).unwrap();
    let audit: Value = serde_json::from_str(&report_text).unwrap();
    assert_eq!(audit["reconciliation"]["input_records"], 6);
    assert_eq!(audit["reconciliation"]["accounted_for_inputs"], 6);
    for canary in [
        "CasesensA",
        "casesensa",
        "A_FICTIONAL",
        "FAKEOTP",
        "alice",
        "example.test",
        "Sensitive fictional note",
    ] {
        assert!(
            !report_text.contains(canary),
            "secret or identity leaked to redacted report"
        );
    }
    for (file, original) in [&json_input, &edge, &chrome, &firefox, &apple]
        .iter()
        .zip(&originals)
    {
        assert_eq!(fs::read(file).unwrap(), *original);
    }
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn cli_help_and_readme_agree_on_supported_export_and_review_options() {
    let help = binary(&["--help"]);
    assert!(help.status.success());
    let surface = String::from_utf8(help.stdout).unwrap();
    let readme = include_str!("../README.md");
    for option in [
        "--input",
        "--source",
        "--output",
        "--report",
        "--dry-run",
        "--merge-compatible-uris",
        "--merge-compatible-fields",
        "--validate-vaultwarden-import",
        "--passflick-export",
        "--init-review-key",
        "--review-key",
        "--bound-review-template",
        "--decisions",
        "--review-template",
    ] {
        assert!(
            surface.contains(option),
            "CLI help is missing a documented switch"
        );
        assert!(
            readme.contains(option),
            "README is missing a supported CLI switch"
        );
    }
    assert!(readme.contains("bw-passport-dedup"));
    assert!(readme.contains("bw-password-dedup"));
    assert!(readme.contains("Passflick remains an independent local password picker"));
}

#[test]
fn forged_bitwarden_json_browser_metadata_cannot_contaminate_passflick_source() {
    let folder = temp_folder("forged-browser-origin");
    let input = folder.join("bitwarden.json");
    let edge = folder.join("edge.csv");
    let cleaned = folder.join("clean.json");
    let snapshot = folder.join("passflick.csv");
    let fake = json!({"type":1,"name":"Forged Browser Attribution",
    "login":{"username":"synthetic-vault-only",
             "password":"SYNTH_VAULT_PASSWORD",
             "uris":[{"uri":"https://vault.example.test"}]},
    "fields":[
        {"name":"migration.source","value":"edge","type":0},
        {"name":"migration.record","value":"1","type":0}
    ]});
    let data = serde_json::to_vec(&json!({
        "encrypted":false,"folders":[],"items":[fake]
    }))
    .unwrap();
    fs::write(&input, &data).unwrap();
    fs::write(&edge,b"name,url,username,password\nReal Synthetic CSV,https://edge.example.test,synthetic-browser,CSV_ONLY_SECRET\n").unwrap();
    let spec = format!("edge={}", edge.display());
    let pass_spec = format!("edge={}", snapshot.display());
    let run = binary(&[
        "--input",
        input.to_str().unwrap(),
        "--source",
        &spec,
        "--output",
        cleaned.to_str().unwrap(),
        "--passflick-export",
        &pass_spec,
    ]);
    assert!(
        !run.status.success(),
        "untrusted JSON browser origin was accepted"
    );
    assert!(!snapshot.exists());
    assert!(!cleaned.exists());
    assert_eq!(fs::read(&input).unwrap(), data);
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn excessive_number_of_browser_sources_is_rejected_without_output() {
    let folder = temp_folder("too-many-sources");
    let output = folder.join("out.json");
    let mut inputs: Vec<String> = Vec::new();
    for _ in 0..33 {
        inputs.push("--source".to_string());
        inputs.push("edge=/missing/synthetic-password-export.csv".to_string());
    }
    inputs.push("--output".to_string());
    inputs.push(output.to_str().unwrap().to_string());
    let args = inputs.iter().map(String::as_str).collect::<Vec<_>>();
    let result = binary(&args);
    assert!(!result.status.success());
    assert!(!output.exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("32 browser source files"));
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn review_key_initialization_rejects_mixed_passflick_export_flags() {
    let folder = temp_folder("key-init-mixed-flags");
    let key = folder.join("review.key");
    let snapshot = folder.join("browser.csv");
    let export = format!("edge={}", snapshot.display());
    let result = binary(&[
        "--init-review-key",
        key.to_str().unwrap(),
        "--passflick-export",
        &export,
    ]);
    assert!(!result.status.success());
    assert!(!key.exists());
    assert!(!snapshot.exists());
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn source_symlinks_are_rejected_without_exporting_credentials() {
    use std::os::unix::fs::symlink;
    let folder = temp_folder("source-symlink");
    let original = folder.join("original.json");
    let alias = folder.join("alias.json");
    let output = folder.join("clean.json");
    synthetic_input(&original);
    let untouched = fs::read(&original).unwrap();
    symlink(&original, &alias).unwrap();
    let json_run = binary(&[
        "--input",
        alias.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(!json_run.status.success());
    assert!(!output.exists());
    assert_eq!(fs::read(&original).unwrap(), untouched);

    let browser = folder.join("edge.csv");
    let browser_link = folder.join("edge-link.csv");
    fs::write(
        &browser,
        b"name,url,username,password\nFictional,https://example.test,user,SecretOnly\n",
    )
    .unwrap();
    symlink(&browser, &browser_link).unwrap();
    let spec = format!("edge={}", browser_link.display());
    let csv_run = binary(&["--source", &spec, "--output", output.to_str().unwrap()]);
    assert!(!csv_run.status.success());
    assert!(!output.exists());
    assert_eq!(
        fs::read(&browser).unwrap(),
        b"name,url,username,password\nFictional,https://example.test,user,SecretOnly\n",
    );
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn cumulative_source_limit_rejects_sparse_large_inputs_before_parsing() {
    let folder = temp_folder("aggregate-input-bound");
    let output = folder.join("should-not-exist.json");
    let mut source_args = Vec::new();
    for index in 0..5 {
        let path = folder.join(format!("fictional-{index}.csv"));
        let file = fs::File::create(&path).unwrap();
        file.set_len(60 * 1024 * 1024).unwrap();
        source_args.push(format!("edge={}", path.display()));
    }
    let mut args = Vec::new();
    for source in &source_args {
        args.push("--source");
        args.push(source.as_str());
    }
    args.push("--output");
    args.push(output.to_str().unwrap());
    let run = binary(&args);
    assert!(!run.status.success());
    assert!(!output.exists());
    assert!(
        String::from_utf8_lossy(&run.stderr)
            .contains("combined sources exceed the 256 MiB size limit")
    );
    fs::remove_dir_all(folder).unwrap();
}
