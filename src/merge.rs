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
                    source_record = field.get("value")
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
                records: indices.iter()
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
        let mut a = login("https://example.test/login", "private-username", "SECRET1", "TOTP1");
        let mut b = login("https://example.test/account", "private-username", "SECRET2", "TOTP2");
        a["fields"] = json!([
            {"name":"migration.source","value":"edge","type":0},
            {"name":"migration.record","value":"42","type":0}
        ]);
        b["fields"] = json!([
            {"name":"migration.source","value":"unknown-user-controlled-value","type":0},
            {"name":"migration.record","value":"untrusted","type":0}
        ]);
        let groups = analyze_accounts(&[a,b]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].records[0].provider, "edge");
        assert_eq!(groups[0].records[0].source_record, Some(42));
        assert_eq!(groups[0].records[1].provider, "unlabeled");
        assert_eq!(groups[0].records[1].source_record, None);
        let report = serde_json::to_string(&groups).unwrap();
        for forbidden in ["private-username", "SECRET1", "SECRET2", "TOTP1", "TOTP2", "unknown-user-controlled-value"] {
            assert!(!report.contains(forbidden));
        }
    }

}
