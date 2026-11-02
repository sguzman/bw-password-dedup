//! A source-preserving CSV projection for Passflick's existing import API.
//! It never pretends a unified vault is an Edge/Chrome/Firefox/Apple source.
//! No direct changes to Passflick's encrypted vault or external browser stores.

use anyhow::{Context, Result};
use serde_json::Value;

const MAX_CSV_BYTES: usize = 32 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Provider {
    Edge,
    Chrome,
    Firefox,
    Apple,
}

impl Provider {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "edge" => Ok(Self::Edge),
            "chrome" | "chromium" => Ok(Self::Chrome),
            "firefox" => Ok(Self::Firefox),
            "apple" | "safari" => Ok(Self::Apple),
            _ => anyhow::bail!("Passflick source must be edge, chrome, firefox or apple"),
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Edge => "edge",
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Apple => "apple",
        }
    }
}

pub(crate) struct Projection {
    pub(crate) bytes: Vec<u8>,
    pub(crate) credentials: usize,
    pub(crate) skipped_passwordless: usize,
    pub(crate) skipped_other_sources: usize,
}

/// Accept only complete, ordered source/record pairs created by the CSV
/// importer. Never assign a legacy Bitwarden-only entry to a browser provider.
fn source_labels(item: &Value) -> Result<Vec<&str>> {
    let mut labels = Vec::new();
    let mut pending_source: Option<&str> = None;
    for field in item
        .get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(name) = field.get("name").and_then(Value::as_str) else {
            if pending_source.is_some() {
                anyhow::bail!("unpaired source provenance");
            }
            continue;
        };
        match name {
            "migration.source" => {
                if pending_source.is_some() {
                    anyhow::bail!("duplicate or incomplete provenance pair");
                }
                let source = field
                    .get("value")
                    .and_then(Value::as_str)
                    .context("source provenance missing label")?;
                if !matches!(source, "edge" | "chrome" | "firefox" | "apple") {
                    anyhow::bail!("unsupported source provenance");
                }
                pending_source = Some(source);
            }
            "migration.record" => {
                let source = pending_source
                    .take()
                    .context("unpaired source record ordinal")?;
                let position = field
                    .get("value")
                    .and_then(Value::as_str)
                    .and_then(|raw| raw.parse::<usize>().ok())
                    .filter(|v| *v > 0)
                    .context("invalid source record ordinal")?;
                let _ = position;
                if !labels.contains(&source) {
                    labels.push(source);
                }
            }
            _ if pending_source.is_some() => {
                anyhow::bail!("source/record provenance pair is not adjacent");
            }
            _ => {}
        }
    }
    if pending_source.is_some() {
        anyhow::bail!("missing source provenance ordinal");
    }
    Ok(labels)
}

pub(crate) fn project_source(
    items: &[Value],
    provider: Provider,
    trusted_source_labels: &[Vec<&'static str>],
) -> Result<Projection> {
    if items.len() != trusted_source_labels.len() {
        anyhow::bail!("source lineage does not match consolidated record count");
    }
    let mut csv = csv::WriterBuilder::new().from_writer(Vec::new());
    csv.write_record(["name", "url", "username", "password"])?;
    let mut credentials = 0;
    let mut skipped_passwordless = 0;
    let mut skipped_other_sources = 0;
    for (item, trusted) in items.iter().zip(trusted_source_labels) {
        if item.get("type").and_then(Value::as_u64) != Some(1) {
            skipped_other_sources += 1;
            continue;
        }
        let declared = source_labels(item)?;
        if declared.iter().any(|label| !trusted.contains(label)) {
            anyhow::bail!(
                "unverified browser provenance: use the original browser CSV instead of a JSON-supplied source label"
            );
        }
        if !trusted.contains(&provider.label()) || !declared.contains(&provider.label()) {
            skipped_other_sources += 1;
            continue;
        }
        let login = item
            .get("login")
            .and_then(Value::as_object)
            .context("imported login has malformed data")?;
        let password = login
            .get("password")
            .and_then(Value::as_str)
            .context("projected login missing string password")?;
        if password.is_empty() {
            skipped_passwordless += 1;
            continue;
        }
        let username = login
            .get("username")
            .and_then(Value::as_str)
            .context("projected login missing string username")?;
        if username.contains('\0') || password.contains('\0') {
            anyhow::bail!("Passflick cannot represent NUL in clipboard credentials");
        }
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .context("projected login missing title")?;
        let uris = login.get("uris").and_then(Value::as_array);
        let urls: Vec<&str> = match uris {
            Some(uris) if !uris.is_empty() => uris
                .iter()
                .map(|entry| {
                    entry
                        .get("uri")
                        .and_then(Value::as_str)
                        .or_else(|| entry.as_str())
                        .context("URI missing string address")
                })
                .collect::<Result<Vec<_>>>()?,
            _ => vec![""],
        };
        for url in urls {
            if (url.is_empty() && name.trim().is_empty())
                || name.trim() != name
                || url.trim() != url
            {
                anyhow::bail!("Passflick would lose or alter source site metadata");
            }
            csv.write_record([name, url, username, password])?;
            credentials += 1;
            if credentials > MAX_RECORDS {
                anyhow::bail!("Passflick projection exceeds 100,000 record limit");
            }
        }
    }
    if credentials == 0 {
        anyhow::bail!("no usable login records for selected Passflick browser source");
    }
    let bytes = csv
        .into_inner()
        .context("finalizing private Passflick snapshot")?;
    if bytes.len() > MAX_CSV_BYTES {
        anyhow::bail!("Passflick projection exceeds 32 MiB limit");
    }
    Ok(Projection {
        bytes,
        credentials,
        skipped_passwordless,
        skipped_other_sources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn login(provider: &str, password: &str) -> Value {
        json!({"type":1,"name":"Synthetic","login":{
            "username":"fictional","password":password,
            "uris":[{"uri":"https://example.test/a"},{"uri":"https://example.test/b"}]},
            "fields":[
                {"name":"migration.source","value":provider,"type":0},
                {"name":"migration.record","value":"2","type":0}
            ]
        })
    }

    #[test]
    fn preserves_browser_attribution_and_multiple_urls() {
        let values = vec![
            login("edge", "SyntheticSecret"),
            login("chrome", "OtherSecret"),
        ];
        let projected =
            project_source(&values, Provider::Edge, &[vec!["edge"], vec!["chrome"]]).unwrap();
        let data = String::from_utf8(projected.bytes).unwrap();
        assert!(data.contains("https://example.test/a"));
        assert!(data.contains("https://example.test/b"));
        assert!(data.contains("SyntheticSecret"));
        assert!(!data.contains("OtherSecret"));
        assert_eq!(projected.credentials, 2);
        assert_eq!(projected.skipped_other_sources, 1);
    }

    #[test]
    fn provenance_pairs_are_required_and_bad_passwords_fail_closed() {
        let mut record = login("edge", "secret");
        record["fields"][1]["name"] = json!("custom");
        assert!(project_source(&[record], Provider::Edge, &[vec!["edge"]]).is_err());
        let mut record = login("edge", "secret");
        record["login"]["password"] = json!("nul\u{0000}character");
        assert!(project_source(&[record], Provider::Edge, &[vec!["edge"]]).is_err());
        let unlabelled = json!({"type":1,"name":"Vaultwarden-only","login":{
            "username":"fictional","password":"secret","uris":[]}});
        assert!(project_source(&[unlabelled], Provider::Edge, &[vec![]]).is_err());
    }

    #[test]
    fn field_merged_cross_source_provenance_is_not_misattributed() {
        let mut record = login("edge", "SyntheticSecret");
        record["fields"].as_array_mut().unwrap().extend(vec![
            json!({"name":"migration.source","value":"apple","type":0}),
            json!({"name":"migration.record","value":"15","type":0}),
        ]);
        assert_eq!(
            project_source(&[record.clone()], Provider::Apple, &[vec!["edge", "apple"]])
                .unwrap()
                .credentials,
            2
        );
        assert_eq!(
            project_source(&[record], Provider::Edge, &[vec!["edge", "apple"]])
                .unwrap()
                .credentials,
            2
        );
    }
    #[test]
    fn bitwarden_json_cannot_spoof_browser_origin_with_custom_fields() {
        let record = login("edge", "SyntheticSecret");
        assert!(project_source(&[record.clone()], Provider::Edge, &[vec![]]).is_err());
        let valid = login("edge", "TrustedSecret");
        assert!(project_source(&[record, valid], Provider::Edge, &[vec![], vec!["edge"]]).is_err());
    }

    #[test]
    fn trusted_lineage_cannot_be_mismatched_to_outputs() {
        let record = login("edge", "TrustedSecret");
        assert!(project_source(&[record.clone()], Provider::Edge, &[]).is_err());
        assert!(project_source(&[record.clone()], Provider::Edge, &[vec!["chrome"]]).is_err());
        assert_eq!(
            project_source(&[record], Provider::Edge, &[vec!["edge"]])
                .unwrap()
                .credentials,
            2
        );
    }
}
