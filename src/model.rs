//! Typed, lossless wrappers around the original export item values.
//!
//! Parsing and matching use typed classifications, but serialization keeps the
//! complete original JSON value (including unknown and future fields).

use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordKind {
    Login,
    SecureNote,
    Card,
    Identity,
    Unknown(u64),
    Malformed,
}

// Deliberately do not derive Debug: the raw item contains secrets.
pub(crate) struct CanonicalRecord {
    raw: Value,
    kind: RecordKind,
    source: Option<String>,
    source_record: Option<usize>,
}

impl CanonicalRecord {
    pub(crate) fn from_value(raw: Value) -> Self {
        let kind = match raw.get("type").and_then(Value::as_u64) {
            Some(1) if raw.get("login").is_some_and(Value::is_object) => RecordKind::Login,
            Some(1) => RecordKind::Malformed,
            Some(2) => RecordKind::SecureNote,
            Some(3) => RecordKind::Card,
            Some(4) => RecordKind::Identity,
            Some(unknown) => RecordKind::Unknown(unknown),
            None => RecordKind::Malformed,
        };
        let mut source = None;
        let mut source_record = None;
        if let Some(fields) = raw.get("fields").and_then(Value::as_array) {
            for field in fields {
                match field.get("name").and_then(Value::as_str) {
                    Some("migration.source") => {
                        source = field
                            .get("value")
                            .and_then(Value::as_str)
                            .map(str::to_owned);
                    }
                    Some("migration.record") => {
                        source_record = field
                            .get("value")
                            .and_then(Value::as_str)
                            .and_then(|number| number.parse().ok());
                    }
                    _ => {}
                }
            }
        }
        Self {
            raw,
            kind,
            source,
            source_record,
        }
    }

    pub(crate) fn kind(&self) -> RecordKind {
        self.kind
    }

    pub(crate) fn as_value(&self) -> &Value {
        &self.raw
    }

    pub(crate) fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub(crate) fn source_record(&self) -> Option<usize> {
        self.source_record
    }

    pub(crate) fn into_value(self) -> Value {
        self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classification_and_lossless_roundtrip() {
        let examples = [
            (
                json!({"type":1, "login":{"username":"u","password":"SyntheticSeCrEt"},
                    "unknown":{"nested":[1,2,3]}}),
                RecordKind::Login,
            ),
            (
                json!({"type":2,"notes":"fictional"}),
                RecordKind::SecureNote,
            ),
            (json!({"type":3,"card":{"number":"FAKE"}}), RecordKind::Card),
            (
                json!({"type":4,"identity":{"firstName":"Synthetic"}}),
                RecordKind::Identity,
            ),
            (
                json!({"type":77,"future":{"k":true}}),
                RecordKind::Unknown(77),
            ),
            (json!({"type":1,"login":"malformed"}), RecordKind::Malformed),
        ];
        for (original, kind) in examples {
            let record = CanonicalRecord::from_value(original.clone());
            assert_eq!(record.kind(), kind);
            assert_eq!(record.as_value(), &original);
            assert_eq!(record.into_value(), original);
        }
    }

    #[test]
    fn provenance_is_extracted_without_removing_original_fields() {
        let item = json!({
            "type": 1,
            "login": {"username":"fictional","password":"Synthetic"},
            "fields": [
                {"name":"migration.source","value":"apple","type":0},
                {"name":"migration.record","value":"42","type":0},
                {"name":"source.apple.OTPAuth","value":"fictional","type":0}
            ]
        });
        let record = CanonicalRecord::from_value(item.clone());
        assert_eq!(record.source(), Some("apple"));
        assert_eq!(record.source_record(), Some(42));
        assert_eq!(record.into_value(), item);
    }
}
