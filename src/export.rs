//! Validation of the documented plaintext Bitwarden individual-vault JSON
//! import format. This is a static check, not a replacement for testing a
//! real isolated Vaultwarden import.

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::HashSet;

pub(crate) struct ImportSummary {
    pub(crate) items: usize,
    pub(crate) folders: usize,
}

pub(crate) fn validate_individual_import(root: &Value) -> Result<ImportSummary> {
    let root = root.as_object().context("vault export must be an object")?;
    if root.get("encrypted").is_some_and(|flag| flag != &Value::Bool(false)) {
        anyhow::bail!("encrypted or unrecognized JSON cannot be imported as plaintext");
    }
    let folders = root.get("folders").and_then(Value::as_array)
        .context("individual vault import requires a folders array")?;
    let items = root.get("items").and_then(Value::as_array)
        .context("individual vault import requires an items array")?;
    if root.get("collections").is_some_and(|value| {
        value.as_array().is_none_or(|entries| !entries.is_empty())
    }) {
        anyhow::bail!("organization collections require a separate import workflow");
    }
    let mut ids = HashSet::new();
    for folder in folders {
        let obj = folder.as_object().context("folder must be an object")?;
        let id = obj.get("id").and_then(Value::as_str)
            .context("folder missing ID")?;
        let name = obj.get("name").and_then(Value::as_str)
            .context("folder missing name")?;
        if id.is_empty() || name.is_empty() || !ids.insert(id) {
            anyhow::bail!("folder ID/name is empty or a folder ID is duplicated");
        }
    }
    for item in items {
        let obj = item.as_object().context("vault item must be an object")?;
        let name = obj.get("name").and_then(Value::as_str)
            .context("vault item missing name")?;
        if name.is_empty() {
            anyhow::bail!("vault item has an empty name");
        }
        if obj.get("organizationId").is_some_and(|value| !value.is_null()) {
            anyhow::bail!("organization-owned vault item is not an individual-vault import");
        }
        if let Some(folder) = obj.get("folderId").filter(|value| !value.is_null()) {
            let id = folder.as_str().context("invalid folder reference")?;
            if !ids.contains(id) {
                anyhow::bail!("item references a folder not included in export");
            }
        }
        let kind = obj.get("type").and_then(Value::as_u64)
            .context("item missing numeric type")?;
        let required = match kind {
            1 => "login",
            2 => "secureNote",
            3 => "card",
            4 => "identity",
            _ => anyhow::bail!("item type is not supported by the documented individual import format"),
        };
        if !obj.get(required).is_some_and(Value::is_object) {
            anyhow::bail!("item is missing its type-specific data object");
        }
        if let Some(fields) = obj.get("fields").filter(|value| !value.is_null()) {
            for field in fields.as_array().context("custom fields must be an array")? {
                let f = field.as_object().context("custom field must be an object")?;
                if !f.get("name").is_some_and(Value::is_string)
                    || !f.get("type").is_some_and(Value::is_number)
                    || !f.get("value").is_some_and(|v| v.is_string() || v.is_null())
                {
                    anyhow::bail!("custom field has an invalid name, value, or type");
                }
            }
        }
        if kind == 1 {
            let login = &obj[required];
            for name in ["username","password","totp"] {
                if login.get(name).is_some_and(|v| !v.is_null() && !v.is_string()) {
                    anyhow::bail!("login secret or username has unsupported data type");
                }
            }
            if let Some(uris) = login.get("uris").filter(|value| !value.is_null()) {
                for entry in uris.as_array().context("login URIs must be an array")? {
                    if !entry.is_object()
                        || !entry.get("uri").is_some_and(Value::is_string)
                        || entry.get("match").is_some_and(|v| !v.is_null() && !v.is_number())
                    {
                        anyhow::bail!("login URI entry is incompatible with import format");
                    }
                }
            }
        }
    }
    Ok(ImportSummary {items: items.len(), folders: folders.len()})
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn documented_individual_import_types_pass_static_validation() {
        let root = json!({"encrypted":false,
            "folders":[{"id":"synthetic-folder","name":"Archive"}],
            "items":[
                {"type":1,"name":"Login","folderId":"synthetic-folder",
                 "login":{"uris":[{"uri":"https://example.test","match":null}],
                          "username":"fictional","password":"SyntheticSecret","totp":null}},
                {"type":2,"name":"Note","secureNote":{}},
                {"type":3,"name":"Card","card":{}},
                {"type":4,"name":"Identity","identity":{}}
            ]
        });
        let summary=validate_individual_import(&root).unwrap();
        assert_eq!((summary.items,summary.folders),(4,1));
    }

    #[test]
    fn unsupported_type_organization_and_unresolved_folder_rejected() {
        let mut root=json!({"encrypted":false,"folders":[],"items":[
            {"type":99,"name":"Future","opaque":{}}
        ]});
        assert!(validate_individual_import(&root).is_err());
        root["items"][0]=json!({"type":1,"name":"Synthetic",
            "organizationId":"org-1","login":{}});
        assert!(validate_individual_import(&root).is_err());
        root["items"][0]=json!({"type":1,"name":"Synthetic",
            "folderId":"unmapped","login":{}});
        assert!(validate_individual_import(&root).is_err());
    }

    #[test]
    fn malformed_fields_and_login_uris_fail_without_discarding_records() {
        let mut root=json!({"encrypted":false,"folders":[],"items":[
            {"type":1,"name":"Synthetic","login":{}}
        ]});
        root["items"][0]["fields"]=json!([{"name":"missing type","value":"fictional"}]);
        assert!(validate_individual_import(&root).is_err());
        root["items"][0].as_object_mut().unwrap().remove("fields");
        root["items"][0]["login"]["uris"]=json!(["not a Bitwarden URI object"]);
        assert!(validate_individual_import(&root).is_err());
        root["items"][0]["login"]["uris"]=json!([{"uri":"https://example.test","match":null}]);
        assert!(validate_individual_import(&root).is_ok());
    }
}
