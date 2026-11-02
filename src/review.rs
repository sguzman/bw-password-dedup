//! Private review templates contain references and fixed decision labels only.
//! This version is deliberately *not executable*: stale-input validation and
//! explicit decisions will be implemented separately for M5-02/M5-03.
use crate::merge::AccountGroupSummary;
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct ReviewTemplate {
    schema_version: u32,
    kind: &'static str,
    input_records: usize,
    groups: Vec<ReviewGroup>,
    warning: &'static str,
}

#[derive(Serialize)]
struct ReviewGroup {
    references: Vec<ReviewReference>,
    conflicting_passwords: bool,
    conflicting_totp: bool,
    differing_metadata: bool,
    decision: &'static str,
}

#[derive(Serialize)]
struct ReviewReference {
    input_position: usize,
    provider: &'static str,
    source_record: Option<usize>,
}

pub(crate) fn build_review_template(
    groups: &[AccountGroupSummary],
    input_records: usize,
) -> ReviewTemplate {
    ReviewTemplate {
        schema_version: 1,
        kind: "review-template-not-executable",
        input_records,
        groups: groups
            .iter()
            .map(|group| ReviewGroup {
                references: group
                    .records
                    .iter()
                    .map(|reference| ReviewReference {
                        input_position: reference.input_position,
                        provider: reference.provider,
                        source_record: reference.source_record,
                    })
                    .collect(),
                conflicting_passwords: group.conflicting_passwords,
                conflicting_totp: group.conflicting_totp,
                differing_metadata: group.differing_metadata,
                decision: "defer",
            })
            .collect(),
        warning: "Input positions are snapshot-relative; do not replay this template as decisions. Preserve original exports.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn template_contains_only_fixed_labels_and_positional_references() {
        let groups = vec![AccountGroupSummary {
            candidates: 2,
            records: vec![
                crate::merge::CandidateReference {
                    input_position: 2,
                    provider: "edge",
                    source_record: Some(14),
                },
                crate::merge::CandidateReference {
                    input_position: 3,
                    provider: "chrome",
                    source_record: Some(7),
                },
            ],
            conflicting_passwords: true,
            conflicting_totp: false,
            differing_metadata: true,
            decision: "unresolved-preserve-all",
        }];
        let template: Value = serde_json::to_value(build_review_template(&groups, 3)).unwrap();
        assert_eq!(template["kind"], "review-template-not-executable");
        assert_eq!(template["groups"][0]["decision"], "defer");
        assert_eq!(template["groups"][0]["references"][0]["input_position"], 2);
        assert_eq!(template["groups"][0]["references"][0]["provider"], "edge");
        assert_eq!(template["groups"][0]["conflicting_passwords"], true);
        let text = template.to_string();
        for secret in ["example.test", "synthetic_password", "secret_username"] {
            assert!(!text.contains(secret));
        }
    }
}
