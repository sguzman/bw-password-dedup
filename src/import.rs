//! Read-only adapters for password-manager CSV exports.
//! Never silently drop unrecognized columns: preserve their values as
//! user-visible custom fields on imported Bitwarden login items.

use crate::{MAX_INPUT_BYTES, MAX_INPUT_ITEMS, open_checked_input};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceKind {
    Edge,
    Chrome,
    Firefox,
    Apple,
}

impl SourceKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Edge => "edge",
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Apple => "apple",
        }
    }

    fn parse(name: &str) -> Result<Self> {
        match name.to_ascii_lowercase().as_str() {
            "edge" => Ok(Self::Edge),
            "chrome" | "chromium" => Ok(Self::Chrome),
            "firefox" => Ok(Self::Firefox),
            "apple" | "safari" => Ok(Self::Apple),
            _ => anyhow::bail!("unsupported source: expected edge, chrome, firefox, or apple"),
        }
    }
}

pub(crate) fn parse_source_spec(spec: &str) -> Result<(SourceKind, PathBuf)> {
    let (kind, path) = spec
        .split_once('=')
        .context("source must use KIND=FILE syntax (for example edge=/private/export.csv)")?;
    if path.is_empty() {
        anyhow::bail!("source file path cannot be empty");
    }
    Ok((SourceKind::parse(kind)?, PathBuf::from(path)))
}

pub(crate) fn import_csv(source: SourceKind, path: &Path) -> Result<Vec<Value>> {
    let mut data = Vec::new();
    open_checked_input(path)?
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > MAX_INPUT_BYTES {
        anyhow::bail!("CSV input exceeds the 64 MiB limit");
    }
    parse_csv_bytes(source, &data)
}

fn normalize_header(s: &str) -> String {
    s.trim_start_matches('\u{feff}').trim().to_ascii_lowercase()
}

fn parse_csv_bytes(source: SourceKind, data: &[u8]) -> Result<Vec<Value>> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(false)
        .has_headers(true)
        .from_reader(data);
    let headers = reader
        .headers()
        .context("CSV header cannot be read")?
        .clone();
    if headers.is_empty() {
        anyhow::bail!("CSV file has no headers");
    }
    let mut names = HashMap::new();
    let mut seen = HashSet::new();
    for (idx, header) in headers.iter().enumerate() {
        let name = normalize_header(header);
        if name.is_empty() || !seen.insert(name.clone()) {
            anyhow::bail!("CSV has blank or duplicate normalized column names");
        }
        names.insert(name, idx);
    }

    let mandatory: &[&str] = match source {
        SourceKind::Apple => &["title", "url", "username", "password"],
        SourceKind::Firefox => &["url", "username", "password"],
        SourceKind::Edge | SourceKind::Chrome => &["name", "url", "username", "password"],
    };
    for name in mandatory {
        if !names.contains_key(*name) {
            anyhow::bail!("CSV is missing a required provider column");
        }
    }
    if source == SourceKind::Firefox
        && ![
            "httprealm",
            "formactionorigin",
            "guid",
            "timecreated",
            "timelastused",
            "timepasswordchanged",
        ]
        .iter()
        .any(|field| names.contains_key(*field))
    {
        anyhow::bail!("Firefox export lacks recognizable Firefox metadata columns");
    }

    let lookup = |record: &csv::StringRecord, field: &str| -> String {
        names
            .get(field)
            .and_then(|&idx| record.get(idx))
            .unwrap_or("")
            .to_owned()
    };
    let mut items = Vec::new();
    for (index, result) in reader.records().enumerate() {
        if index >= MAX_INPUT_ITEMS {
            anyhow::bail!("CSV exceeds the 100,000 item limit");
        }
        let record = result.context("invalid CSV record")?;
        let url = lookup(&record, "url");
        let username = lookup(&record, "username");
        let password = lookup(&record, "password");
        let title = match source {
            SourceKind::Apple => lookup(&record, "title"),
            SourceKind::Firefox => String::new(),
            _ => lookup(&record, "name"),
        };
        let display_name = if title.is_empty() {
            if !url.is_empty() {
                url.clone()
            } else {
                "Unnamed imported login".to_owned()
            }
        } else {
            title
        };

        let notes = if names.contains_key("notes") {
            lookup(&record, "notes")
        } else if names.contains_key("note") {
            lookup(&record, "note")
        } else {
            String::new()
        };
        let totp = if source == SourceKind::Apple && names.contains_key("otpauth") {
            Some(lookup(&record, "otpauth"))
        } else {
            None
        };

        let mut fields: Vec<Value> = vec![
            json!({"name": "migration.source", "value": source.label(), "type": 0}),
            json!({"name": "migration.record", "value": (index + 1).to_string(), "type": 0}),
        ];
        for (idx, header) in headers.iter().enumerate() {
            let normalized = normalize_header(header);
            let mapped = matches!(
                normalized.as_str(),
                "name" | "title" | "url" | "username" | "password" | "notes" | "note"
            ) || (source == SourceKind::Apple && normalized == "otpauth");
            if !mapped {
                fields.push(json!({
                    "name": format!("source.{}.{}", source.label(), header),
                    "value": record.get(idx).unwrap_or(""),
                    "type": 0
                }));
            }
        }

        let mut item = json!({
            "type": 1,
            "name": display_name,
            "notes": notes,
            "favorite": false,
            "reprompt": 0,
            "fields": fields,
            "login": {
                "username": username,
                "password": password,
                "uris": if url.is_empty() {Vec::new()} else {vec![json!({"uri":url,"match":null})]},
                "totp": totp
            }
        });
        // An absent OTPAuth column is different from an empty TOTP secret.
        if totp.is_none() {
            item["login"].as_object_mut().unwrap().remove("totp");
        }
        items.push(item);
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_spec_requires_supported_provider_and_path() {
        assert!(parse_source_spec("firefox=/private/ff.csv").is_ok());
        assert!(parse_source_spec("safari=/private/apple.csv").is_ok());
        assert!(parse_source_spec("edge").is_err());
        assert!(parse_source_spec("unknown=/tmp/example.csv").is_err());
        assert!(parse_source_spec("apple=").is_err());
    }

    #[test]
    fn edge_csv_preserves_quotes_multiline_and_custom_columns() {
        let input = b"name,url,username,password,Extra\r\n\"My, Site\",https://example.test,alpha,SeCrEt,\"line one\nline two\"\r\n";
        let items = parse_csv_bytes(SourceKind::Edge, input).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["name"], "My, Site");
        assert_eq!(items[0]["login"]["password"], "SeCrEt");
        assert_eq!(items[0]["fields"][2]["value"], "line one\nline two");
    }

    #[test]
    fn chrome_csv_preserves_blank_password_as_account() {
        let input = b"name,url,username,password\nExample,https://example.test,u,\n";
        let items = parse_csv_bytes(SourceKind::Chrome, input).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["login"]["password"], "");
    }

    #[test]
    fn firefox_csv_retains_provider_specific_metadata() {
        let input = b"url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\nhttps://example.test,u,secret,realm,action,id,123,456,789\n";
        let items = parse_csv_bytes(SourceKind::Firefox, input).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["login"]["password"], "secret");
        assert!(
            items[0]["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["name"] == "source.firefox.timePasswordChanged" && f["value"] == "789")
        );
    }

    #[test]
    fn apple_csv_preserves_notes_and_totp_seed() {
        let input = b"Title,URL,Username,Password,Notes,OTPAuth\nApple,https://example.test,u,AbC,\"note, one\",otpauth://totp/EXAMPLE?secret=ABCDEF\n";
        let items = parse_csv_bytes(SourceKind::Apple, input).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["notes"], "note, one");
        assert_eq!(
            items[0]["login"]["totp"],
            "otpauth://totp/EXAMPLE?secret=ABCDEF"
        );
    }

    #[test]
    fn malformed_csv_and_ambiguous_headers_fail_closed() {
        assert!(parse_csv_bytes(SourceKind::Apple, b"URL,Username,Password\na,b,c\n").is_err());
        assert!(
            parse_csv_bytes(
                SourceKind::Chrome,
                b"name,url,username,password,PASSWORD\na,b,c,d,e\n"
            )
            .is_err()
        );
        assert!(
            parse_csv_bytes(
                SourceKind::Edge,
                b"name,url,username,password\n\"unterminated,b,c,d\n"
            )
            .is_err()
        );
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        let raw = [b'n', b'a', b'm', b'e', b',', 0xff, b'\n'];
        assert!(parse_csv_bytes(SourceKind::Chrome, &raw).is_err());
    }
}
