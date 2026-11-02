//! Conservative, redacted discovery of cross-source account candidates.
//! This is not a resolver. Every input entry remains intact until explicit
//! lossless merge/review logic is verified in later M4/M5 tasks.

use crate::{extract_origin_from_uri, extract_uris, is_login};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Serialize)]
pub(crate) struct AccountGroupSummary {
    /// Never emit account identifiers or secret-bearing keys in a report.
    pub(crate) candidates: usize,
    pub(crate) records: Vec<CandidateReference>,
    pub(crate) conflicting_passwords: bool,
    pub(crate) conflicting_totp: bool,
    pub(crate) differing_metadata: bool,
    pub(crate) decision: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct CandidateReference {
    /// 1-based position in the concatenated input batch, before cleanup.
    pub(crate) input_position: usize,
    /// Fixed-source label, never copied unchecked from secret-bearing input.
    pub(crate) provider: &'static str,
    /// 1-based CSV record ordinal when present and well-formed.
    pub(crate) source_record: Option<usize>,
}

fn reference_for(item: &Value, index: usize) -> CandidateReference {
    let mut provider = "unlabeled";
    let mut source_record = None;
    if let Some(fields) = item.get("fields").and_then(Value::as_array) {
        for field in fields {
            match field.get("name").and_then(Value::as_str) {
                Some("migration.source") => {
                    provider = match field.get("value").and_then(Value::as_str) {
                        Some("edge") => "edge",
                        Some("chrome") => "chrome",
                        Some("firefox") => "firefox",
                        Some("apple") => "apple",
                        _ => "unlabeled",
                    };
                }
                Some("migration.record") => {
                    source_record = field
                        .get("value")
                        .and_then(Value::as_str)
                        .and_then(|ordinal| ordinal.parse::<usize>().ok())
                        .filter(|ordinal| *ordinal > 0);
                }
                _ => {}
            }
        }
    }
    CandidateReference {
        input_position: index + 1,
        provider,
        source_record,
    }
}

/// Important: account identity can be built only for one unambiguous web
/// origin and an explicit nonempty username. Other records pass through.
fn account_identity(item: &Value) -> Option<(String, String)> {
    if !is_login(item) {
        return None;
    }
    let username = item.get("login")?.get("username")?.as_str()?;
    if username.is_empty() {
        return None;
    }
    let uri_values = extract_uris(item);
    if uri_values.is_empty() {
        return None;
    }
    let mut origins = HashSet::new();
    for uri in uri_values {
        let origin = extract_origin_from_uri(uri.as_str()?)?;
        origins.insert(origin);
        if origins.len() > 1 {
            return None;
        }
    }
    Some((origins.into_iter().next()?, username.to_owned()))
}

fn secret_value<'a>(item: &'a Value, key: &str) -> Option<&'a Value> {
    item.get("login").and_then(|login| login.get(key))
}

fn distinct_secret_values(items: &[Value], indices: &[usize], key: &str) -> bool {
    let first = secret_value(&items[indices[0]], key);
    indices
        .iter()
        .skip(1)
        .any(|index| secret_value(&items[*index], key) != first)
}

fn differs_in_metadata(items: &[Value], indices: &[usize]) -> bool {
    let first = &items[indices[0]];
    indices.iter().skip(1).any(|index| {
        let other = &items[*index];
        [
            "name",
            "notes",
            "fields",
            "folderId",
            "favorite",
            "reprompt",
            "passwordHistory",
            "collectionIds",
            "organizationId",
            "revisionDate",
            "creationDate",
        ]
        .iter()
        .any(|field| other.get(*field) != first.get(*field))
    })
}

pub(crate) fn analyze_accounts(items: &[Value]) -> Vec<AccountGroupSummary> {
    // BTreeMap keeps presentation order deterministic and does not serialize
    // these private (origin, username) keys.
    let mut groups: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        if let Some(identity) = account_identity(item) {
            groups.entry(identity).or_default().push(index);
        }
    }

    groups
        .into_values()
        .filter(|indices| indices.len() > 1)
        .map(|indices| {
            let passwords_differ = distinct_secret_values(items, &indices, "password");
            let totp_differ = distinct_secret_values(items, &indices, "totp");
            AccountGroupSummary {
                candidates: indices.len(),
                records: indices
                    .iter()
                    .map(|index| reference_for(&items[*index], *index))
                    .collect(),
                conflicting_passwords: passwords_differ,
                conflicting_totp: totp_differ,
                differing_metadata: differs_in_metadata(items, &indices),
                // Review even compatible accounts until lossless union is proven.
                decision: "unresolved-preserve-all",
            }
        })
        .collect()
}

/// Merge only URI variants whose *entire* remaining record is identical.
/// This intentionally excludes different names, notes, custom fields, IDs,
/// timestamps, password histories, organization scopes and provenance.
fn merge_uri_only(a: &Value, b: &Value) -> Option<Value> {
    if account_identity(a)? != account_identity(b)? {
        return None;
    }
    let mut base_a = a.clone();
    let mut base_b = b.clone();
    let uris_a = base_a.get_mut("login")?.as_object_mut()?.remove("uris")?;
    let uris_b = base_b.get_mut("login")?.as_object_mut()?.remove("uris")?;
    if base_a != base_b {
        return None;
    }
    let mut combined = uris_a.as_array()?.clone();
    for entry in uris_b.as_array()? {
        let uri = match entry {
            Value::String(uri) => uri.as_str(),
            Value::Object(map) => map.get("uri")?.as_str()?,
            _ => return None,
        };
        for old in &combined {
            let prior_uri = match old {
                Value::String(uri) => uri.as_str(),
                Value::Object(map) => map.get("uri")?.as_str()?,
                _ => return None,
            };
            if prior_uri == uri && old != entry {
                return None; // Same URL with different match options is a conflict.
            }
        }
        if !combined.contains(entry) {
            combined.push(entry.clone());
        }
    }
    combined.sort_by_key(|uri| serde_json::to_string(uri).unwrap_or_default());
    let mut result = a.clone();
    result["login"]["uris"] = Value::Array(combined);
    Some(result)
}

/// Merge nonconflicting custom fields, notes, and URI variants only after
/// proving that every other field is identical. No arbitrary "newest" wins.
fn merge_compatible_fields(a: &Value, b: &Value) -> Option<Value> {
    if account_identity(a)? != account_identity(b)? {
        return None;
    }
    let mut left = a.clone();
    let mut right = b.clone();
    let left_uris = left.get_mut("login")?.as_object_mut()?.remove("uris")?;
    let right_uris = right.get_mut("login")?.as_object_mut()?.remove("uris")?;
    let left_fields = left.as_object_mut()?.remove("fields");
    let right_fields = right.as_object_mut()?.remove("fields");
    let left_notes = left.as_object_mut()?.remove("notes");
    let right_notes = right.as_object_mut()?.remove("notes");
    // This comparison includes type, favorite, owner, folder, title,
    // password, OTP, password history, IDs, timestamps and unknown fields.
    if left != right {
        return None;
    }
    let merged_uris = union_uris(&left_uris, &right_uris)?;
    let merged_fields = union_custom_fields(left_fields.as_ref(), right_fields.as_ref())?;
    let merged_notes = choose_nonconflicting_notes(left_notes.as_ref(), right_notes.as_ref())?;
    let mut result = a.clone();
    result["login"]["uris"] = Value::Array(merged_uris);
    if let Some(fields) = merged_fields {
        result["fields"] = Value::Array(fields);
    } else {
        result.as_object_mut()?.remove("fields");
    }
    if let Some(notes) = merged_notes {
        result["notes"] = notes;
    } else {
        result.as_object_mut()?.remove("notes");
    }
    Some(result)
}

fn choose_nonconflicting_notes(a: Option<&Value>, b: Option<&Value>) -> Option<Option<Value>> {
    let text = |value: Option<&Value>| -> Option<Option<&str>> {
        match value {
            None | Some(Value::Null) => Some(None),
            Some(Value::String(s)) if s.is_empty() => Some(None),
            Some(Value::String(s)) => Some(Some(s)),
            _ => None,
        }
    };
    let left = text(a)?;
    let right = text(b)?;
    if left.is_some() && right.is_some() && left != right {
        return None;
    }
    if right.is_some() && left.is_none() {
        Some(b.cloned())
    } else {
        Some(a.cloned())
    }
}

/// Preserve source and row pairs by keeping their array order. For all other
/// custom field names, conflicting values are incompatible.
fn union_custom_fields(a: Option<&Value>, b: Option<&Value>) -> Option<Option<Vec<Value>>> {
    let array = |v: Option<&Value>| -> Option<Vec<Value>> {
        match v {
            None | Some(Value::Null) => Some(Vec::new()),
            Some(Value::Array(items)) => Some(items.clone()),
            _ => None,
        }
    };
    let left = array(a)?;
    let right = array(b)?;
    fn field_name(item: &Value) -> Option<&str> {
        item.as_object()?.get("name")?.as_str()
    }
    fn valid_provenance_fields(fields: &[Value]) -> bool {
        let mut names = Vec::new();
        for field in fields {
            if let Some("migration.source" | "migration.record") = field_name(field) {
                names.push(field_name(field).unwrap());
            }
        }
        names.chunks_exact(2).remainder().is_empty()
            && names.chunks_exact(2).all(|pair| pair == ["migration.source", "migration.record"])
    }
    if !valid_provenance_fields(&left) || !valid_provenance_fields(&right) {
        return None;
    }
    let mut result = left;
    for field in right {
        let name = field_name(&field)?;
        // Distinct provenance pairs are retained in their original order.
        // They are never silently collapsed or confused with other fields.
        if matches!(name, "migration.source" | "migration.record") {
            result.push(field);
            continue;
        }
        if result.iter().any(|existing| {
            field_name(existing) == Some(name) && existing != &field
        }) {
            return None;
        }
        if !result.contains(&field) {
            result.push(field);
        }
    }
    if a.is_none() && b.is_none() {
        Some(None)
    } else {
        Some(Some(result))
    }
}

fn union_uris(a: &Value, b: &Value) -> Option<Vec<Value>> {
    let mut combined = a.as_array()?.clone();
    for entry in b.as_array()? {
        let uri = match entry {
            Value::String(uri) => uri.as_str(),
            Value::Object(map) => map.get("uri")?.as_str()?,
            _ => return None,
        };
        for old in &combined {
            let previous = match old {
                Value::String(uri) => uri.as_str(),
                Value::Object(map) => map.get("uri")?.as_str()?,
                _ => return None,
            };
            if previous == uri && old != entry {
                return None;
            }
        }
        if !combined.contains(entry) {
            combined.push(entry.clone());
        }
    }
    combined.sort_by_key(|value| serde_json::to_string(value).unwrap_or_default());
    Some(combined)
}

/// Preserve the complete contribution of every original input in one
/// surviving record. Never derive Debug/Serialize for this secret-bearing type.
pub(crate) struct TrackedRecord {
    pub(crate) value: Value,
    input_positions: Vec<usize>,
    operations: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub(crate) struct MergeAuditEvent {
    output_position: usize,
    inputs: Vec<CandidateReference>,
    operations: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Reconciliation {
    input_records: usize,
    output_records: usize,
    exact_duplicate_removals: usize,
    compatible_uri_merges: usize,
    accounted_for_inputs: usize,
    events: Vec<MergeAuditEvent>,
}

pub(crate) fn exact_dedup_tracked(
    items: Vec<Value>,
    config: &crate::Config,
    ignore_keys: &HashSet<String>,
    ignore_paths: &[Vec<String>],
) -> (Vec<TrackedRecord>, usize) {
    let mut seen: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut retained: Vec<TrackedRecord> = Vec::with_capacity(items.len());
    let mut removed = 0usize;
    for (source_index, item) in items.into_iter().enumerate() {
        let model = crate::model::CanonicalRecord::from_value(item);
        let complete_provenance = match model.source() {
            Some("edge" | "chrome" | "firefox" | "apple") => model.source_record().is_some(),
            _ => true,
        };
        let eligible = model.kind() == crate::model::RecordKind::Login && complete_provenance;
        let key = if eligible {
            Some(crate::build_key(
                model.as_value(),
                config,
                ignore_keys,
                ignore_paths,
            ))
        } else {
            None
        };
        let value = model.into_value();
        let duplicate = key
            .as_ref()
            .and_then(|key| seen.get(key))
            .and_then(|indices| {
                indices
                    .iter()
                    .copied()
                    .find(|index| retained[*index].value == value)
            });
        if let Some(index) = duplicate {
            retained[index].input_positions.push(source_index + 1);
            retained[index].operations.push("exact-identical-record");
            removed += 1;
        } else {
            let index = retained.len();
            retained.push(TrackedRecord {
                value,
                input_positions: vec![source_index + 1],
                operations: vec![],
            });
            if let Some(key) = key {
                seen.entry(key).or_default().push(index);
            }
        }
    }
    (retained, removed)
}

pub(crate) fn merge_uris_tracked(items: Vec<TrackedRecord>) -> (Vec<TrackedRecord>, usize) {
    let mut groups: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    let mut output: Vec<TrackedRecord> = Vec::with_capacity(items.len());
    let mut merged = 0usize;
    for item in items {
        let identity = account_identity(&item.value);
        let candidate = identity
            .as_ref()
            .and_then(|key| groups.get(key))
            .and_then(|indices| {
                if indices.len() > 32 {
                    return None;
                }
                indices.iter().find_map(|index| {
                    merge_uri_only(&output[*index].value, &item.value)
                        .map(|combined| (*index, combined))
                })
            });
        if let Some((index, combined)) = candidate {
            output[index].value = combined;
            output[index].input_positions.extend(item.input_positions);
            output[index].operations.extend(item.operations);
            output[index].operations.push("compatible-uri-union");
            merged += 1;
        } else {
            let index = output.len();
            output.push(item);
            if let Some(key) = identity {
                groups.entry(key).or_default().push(index);
            }
        }
    }
    (output, merged)
}

/// Every source ordinal must appear exactly once across the result, including
/// exact duplicates. If accounting ever fails, refuse to emit a cleaned export.
pub(crate) fn reconcile(
    tracked: &[TrackedRecord],
    input_records: usize,
    exact_removed: usize,
    uri_merges: usize,
    originals: &[Value],
) -> anyhow::Result<Reconciliation> {
    use anyhow::Context;
    let mut observed = vec![false; input_records];
    let mut events = Vec::new();
    for (output_index, item) in tracked.iter().enumerate() {
        for &position in &item.input_positions {
            let seen = observed
                .get_mut(position.checked_sub(1).context("invalid source ordinal")?)
                .context("source ordinal exceeds input count")?;
            if *seen {
                anyhow::bail!("input contribution accounted more than once");
            }
            *seen = true;
        }
        if item.input_positions.len() > 1 {
            let mut positions = item.input_positions.clone();
            positions.sort_unstable();
            positions.dedup();
            let mut operations = item.operations.clone();
            operations.sort_unstable();
            operations.dedup();
            events.push(MergeAuditEvent {
                output_position: output_index + 1,
                inputs: positions
                    .iter()
                    .map(|position| reference_for(&originals[position - 1], position - 1))
                    .collect(),
                operations,
            });
        }
    }
    if observed.iter().any(|value| !*value)
        || tracked.len() + exact_removed + uri_merges != input_records
    {
        anyhow::bail!("merge reconciliation failed; refusing export");
    }
    Ok(Reconciliation {
        input_records,
        output_records: tracked.len(),
        exact_duplicate_removals: exact_removed,
        compatible_uri_merges: uri_merges,
        accounted_for_inputs: observed.len(),
        events,
    })
}

#[cfg(test)]
pub(crate) fn merge_compatible_uris(items: Vec<Value>) -> (Vec<Value>, usize) {
    let tracked = items
        .into_iter()
        .enumerate()
        .map(|(i, value)| TrackedRecord {
            value,
            input_positions: vec![i + 1],
            operations: vec![],
        })
        .collect();
    let (out, merged) = merge_uris_tracked(tracked);
    (out.into_iter().map(|item| item.value).collect(), merged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn login(uri: &str, username: &str, password: &str, totp: &str) -> Value {
        json!({"type":1,"name":"Synthetic","login":{
            "uris":[{"uri":uri}],"username":username,
            "password":password,"totp":totp}})
    }

    #[test]
    fn detects_password_and_totp_conflicts_without_resolving() {
        let a = login("https://example.test/a", "user", "PasswordABC", "TOTPABC");
        let b = login("https://example.test/b", "user", "passwordabc", "TOTPABC");
        let c = login("https://example.test/c", "user", "PasswordABC", "totpabc");
        let groups = analyze_accounts(&[a, b, c]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].candidates, 3);
        assert_eq!(groups[0].records[0].input_position, 1);
        assert_eq!(groups[0].records[1].input_position, 2);
        assert!(groups[0].conflicting_passwords);
        assert!(groups[0].conflicting_totp);
        assert_eq!(groups[0].decision, "unresolved-preserve-all");
    }

    #[test]
    fn groups_cross_browser_records_despite_migration_provenance() {
        let mut a = login("https://example.test/login", "user", "secret", "otp");
        let mut b = login("https://example.test/account", "user", "secret", "otp");
        a["fields"] = json!([{"name":"migration.source","value":"edge","type":0}]);
        b["fields"] = json!([{"name":"migration.source","value":"firefox","type":0}]);
        let groups = analyze_accounts(&[a, b]);
        assert_eq!(groups.len(), 1);
        assert!(!groups[0].conflicting_passwords);
        assert!(groups[0].differing_metadata);
    }

    #[test]
    fn unrelated_accounts_and_ambiguous_origins_are_never_grouped() {
        let items = vec![
            login("https://example.test", "alice", "one", "otp"),
            login("https://example.test", "bob", "one", "otp"),
            login("http://example.test", "alice", "one", "otp"),
            login("https://other.example.test", "alice", "one", "otp"),
            login("androidapp://com.example", "alice", "one", "otp"),
            login("https://example.test:8443", "alice", "one", "otp"),
            login("https://example.test", "", "one", "otp"),
            json!({"type":2,"name":"synthetic note"}),
        ];
        assert!(analyze_accounts(&items).is_empty());
    }

    #[test]
    fn multiple_distinct_origins_fail_closed() {
        let mut a = login("https://example.test", "alice", "one", "otp");
        a["login"]["uris"] = json!([
            {"uri":"https://example.test"},
            {"uri":"https://different.test"}]);
        let b = login("https://example.test", "alice", "two", "otp");
        assert!(analyze_accounts(&[a, b]).is_empty());
    }

    #[test]
    fn serialized_summary_never_contains_private_identity_or_secrets() {
        let a = login(
            "https://SECRET-DOMAIN.test",
            "SECRET-USERNAME",
            "SECRET-PASSWORD",
            "SECRET-TOTP",
        );
        let b = login(
            "https://secret-domain.test",
            "SECRET-USERNAME",
            "another-secret",
            "SECRET-TOTP",
        );
        let report = serde_json::to_string(&analyze_accounts(&[a, b])).unwrap();
        assert!(report.contains("unresolved-preserve-all"));
        for canary in [
            "SECRET-DOMAIN",
            "SECRET-USERNAME",
            "SECRET-PASSWORD",
            "SECRET-TOTP",
            "another-secret",
        ] {
            assert!(!report.contains(canary));
        }
    }
    #[test]
    fn record_references_are_useful_but_never_include_user_data() {
        let mut a = login(
            "https://example.test/login",
            "private-username",
            "SECRET1",
            "TOTP1",
        );
        let mut b = login(
            "https://example.test/account",
            "private-username",
            "SECRET2",
            "TOTP2",
        );
        a["fields"] = json!([
            {"name":"migration.source","value":"edge","type":0},
            {"name":"migration.record","value":"42","type":0}
        ]);
        b["fields"] = json!([
            {"name":"migration.source","value":"unknown-user-controlled-value","type":0},
            {"name":"migration.record","value":"untrusted","type":0}
        ]);
        let groups = analyze_accounts(&[a, b]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].records[0].provider, "edge");
        assert_eq!(groups[0].records[0].source_record, Some(42));
        assert_eq!(groups[0].records[1].provider, "unlabeled");
        assert_eq!(groups[0].records[1].source_record, None);
        let report = serde_json::to_string(&groups).unwrap();
        for forbidden in [
            "private-username",
            "SECRET1",
            "SECRET2",
            "TOTP1",
            "TOTP2",
            "unknown-user-controlled-value",
        ] {
            assert!(!report.contains(forbidden));
        }
    }

    #[test]
    fn compatible_uri_variants_preserve_both_urls() {
        let a = login("https://example.test/login", "alice", "SeCrEt", "TOTP");
        let b = login("https://example.test/account", "alice", "SeCrEt", "TOTP");
        let (out, merged) = merge_compatible_uris(vec![a, b]);
        assert_eq!(merged, 1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["login"]["uris"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn differing_metadata_and_secrets_are_never_merged() {
        let a = login("https://example.test/login", "alice", "SeCrEt", "TOTP");
        let mut note_variant = login("https://example.test/account", "alice", "SeCrEt", "TOTP");
        note_variant["notes"] = json!("Important fictional note");
        let password_variant = login("https://example.test/new", "alice", "secret", "TOTP");
        let totp_variant = login("https://example.test/otp", "alice", "SeCrEt", "totp");
        let (out, merged) =
            merge_compatible_uris(vec![a, note_variant, password_variant, totp_variant]);
        assert_eq!(merged, 0);
        assert_eq!(out.len(), 4);
    }

    #[test]
    fn provenance_difference_is_not_erased_by_uri_union() {
        let mut a = login("https://example.test/login", "alice", "pw", "otp");
        let mut b = login("https://example.test/account", "alice", "pw", "otp");
        a["fields"] = json!([{"name":"migration.source","value":"edge","type":0}]);
        b["fields"] = json!([{"name":"migration.source","value":"chrome","type":0}]);
        let (out, merged) = merge_compatible_uris(vec![a, b]);
        assert_eq!(merged, 0);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn incompatible_uri_match_metadata_is_not_collapsed() {
        let mut a = login("https://example.test/login", "alice", "pw", "otp");
        let mut b = login("https://example.test/login", "alice", "pw", "otp");
        a["login"]["uris"][0]["match"] = json!(0);
        b["login"]["uris"][0]["match"] = json!(1);
        let (out, merged) = merge_compatible_uris(vec![a, b]);
        assert_eq!(merged, 0);
        assert_eq!(out.len(), 2);
    }
    #[test]
    fn blank_missing_and_populated_secrets_are_distinct_alternatives() {
        let mut missing = login("https://example.test/a", "alice", "", "");
        missing["login"].as_object_mut().unwrap().remove("password");
        missing["login"].as_object_mut().unwrap().remove("totp");
        let empty = login("https://example.test/b", "alice", "", "");
        let populated = login("https://example.test/c", "alice", "SYNTH_PW", "SYNTH_TOTP");
        let originals = vec![missing, empty, populated];
        let report = analyze_accounts(&originals);
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].candidates, 3);
        assert!(report[0].conflicting_passwords);
        assert!(report[0].conflicting_totp);
        let (result, merges) = merge_compatible_uris(originals);
        assert_eq!(merges, 0);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn different_ownership_scopes_and_item_types_never_union() {
        let mut first = login("https://example.test/a", "alice", "pw", "otp");
        first["organizationId"] = json!("org-one");
        let mut second = login("https://example.test/b", "alice", "pw", "otp");
        second["organizationId"] = json!("org-two");
        let mut third = login("https://example.test/c", "alice", "pw", "otp");
        third["folderId"] = json!("private-folder");
        let note = json!({"type": 2, "name":"fictional secure note",
            "notes":"do not erase"});
        let unknown = json!({"type":99,"name":"future item","metadata":{"a":1}});
        let originals = vec![first, second, third, note.clone(), unknown.clone()];
        let (result, merges) = merge_compatible_uris(originals);
        assert_eq!(merges, 0);
        assert_eq!(result.len(), 5);
        assert_eq!(result[3], note);
        assert_eq!(result[4], unknown);
    }
    #[test]
    fn chained_exact_and_uri_merges_reconcile_all_input_positions() {
        let first = login("https://example.test/a", "alice", "SECRETA", "OTPA");
        let next = login("https://example.test/b", "alice", "SECRETA", "OTPA");
        let originals = vec![first.clone(), first, next];
        let (tracked, removed) = exact_dedup_tracked(
            originals.clone(),
            &crate::Config::default(),
            &HashSet::new(),
            &[],
        );
        assert_eq!(removed, 1);
        let (tracked, merged) = merge_uris_tracked(tracked);
        assert_eq!(merged, 1);
        let ledger = reconcile(&tracked, originals.len(), removed, merged, &originals).unwrap();
        let json = serde_json::to_value(&ledger).unwrap();
        assert_eq!(json["input_records"], 3);
        assert_eq!(json["output_records"], 1);
        assert_eq!(json["accounted_for_inputs"], 3);
        assert_eq!(json["exact_duplicate_removals"], 1);
        assert_eq!(json["compatible_uri_merges"], 1);
        assert_eq!(json["events"][0]["output_position"], 1);
        assert_eq!(json["events"][0]["inputs"].as_array().unwrap().len(), 3);
        assert_eq!(json["events"][0]["operations"].as_array().unwrap().len(), 2);
        let text = json.to_string();
        for canary in ["example.test", "alice", "SECRETA", "OTPA"] {
            assert!(!text.contains(canary));
        }
        assert_eq!(
            tracked[0].value["login"]["uris"].as_array().unwrap().len(),
            2
        );
    }

    #[test]
    fn reconciliation_rejects_missing_or_reused_input_positions() {
        let first = login("https://example.test/a", "alice", "secret", "totp");
        let originals = vec![first.clone(), first.clone()];
        let record = TrackedRecord {
            value: first.clone(),
            input_positions: vec![1, 1],
            operations: vec!["exact-identical-record"],
        };
        assert!(reconcile(&[record], 2, 1, 0, &originals).is_err());
        let record = TrackedRecord {
            value: first,
            input_positions: vec![1],
            operations: vec![],
        };
        assert!(reconcile(&[record], 2, 1, 0, &originals).is_err());
    }

    #[test]
    fn unrecognized_items_and_organization_scopes_are_preserved_in_audit() {
        let first = login("https://example.test/a", "alice", "secret", "totp");
        let mut other_scope = login("https://example.test/b", "alice", "secret", "totp");
        other_scope["organizationId"] = json!("other-org");
        let unknown = json!({"type":77, "name":"synthetic-unknown", "privateData":"canary"});
        let originals = vec![first, other_scope, unknown.clone()];
        let (tracked, removed) = exact_dedup_tracked(
            originals.clone(),
            &crate::Config::default(),
            &HashSet::new(),
            &[],
        );
        let (tracked, merged) = merge_uris_tracked(tracked);
        let ledger = reconcile(&tracked, originals.len(), removed, merged, &originals).unwrap();
        assert_eq!(merged, 0);
        assert_eq!(tracked.len(), 3);
        assert_eq!(tracked[2].value, unknown);
        assert!(
            serde_json::to_value(ledger).unwrap()["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}
