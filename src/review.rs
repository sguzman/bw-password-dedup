//! Non-secret review inventories and explicitly authenticated source snapshots.
//! A decision is valid only for the exact ordered input + matching policy.
//! The HMAC key never enters a manifest or any user-facing report.

use crate::merge::AccountGroupSummary;
use anyhow::{Context, Result};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;
const KEY_SIZE: usize = 32;
const MAX_MANIFEST: u64 = 4 * 1024 * 1024;

#[derive(Serialize)]
pub(crate) struct ReviewTemplate {
    schema_version: u32,
    kind: &'static str,
    input_records: usize,
    groups: Vec<UnsealedGroup>,
    warning: &'static str,
}

#[derive(Serialize)]
struct UnsealedGroup {
    references: Vec<ReviewReference>,
    conflicting_passwords: bool,
    conflicting_totp: bool,
    differing_metadata: bool,
    decision: &'static str,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewReference {
    pub(crate) input_position: usize,
    pub(crate) provider: String,
    pub(crate) source_record: Option<usize>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecisionManifest {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) input_records: usize,
    pub(crate) snapshot_mac: String,
    pub(crate) groups: Vec<DecisionGroup>,
    warning: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecisionGroup {
    pub(crate) references: Vec<ReviewReference>,
    pub(crate) conflicting_passwords: bool,
    pub(crate) conflicting_totp: bool,
    pub(crate) differing_metadata: bool,
    pub(crate) decision: ReviewDecision,
    pub(crate) selected_input_position: Option<usize>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReviewDecision {
    Defer,
    KeepBoth,
    ChooseOne,
    MergeNonsecret,
}

pub(crate) struct ValidatedDecision {
    pub(crate) positions: Vec<usize>,
    pub(crate) action: ReviewDecision,
    pub(crate) selected_input_position: Option<usize>,
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
            .map(|group| UnsealedGroup {
                references: group
                    .records
                    .iter()
                    .map(|reference| ReviewReference {
                        input_position: reference.input_position,
                        provider: reference.provider.to_owned(),
                        source_record: reference.source_record,
                    })
                    .collect(),
                conflicting_passwords: group.conflicting_passwords,
                conflicting_totp: group.conflicting_totp,
                differing_metadata: group.differing_metadata,
                decision: "defer",
            })
            .collect(),
        warning: "Snapshot-relative positions: this v1 inventory cannot execute decisions. Keep original exports.",
    }
}

pub(crate) fn init_review_key(path: &Path) -> Result<()> {
    crate::path_safety::check_output_parent(path)?;
    // The key must be locally generated, stored separately from decisions,
    // and never overwritten, printed, or accidentally left in a temp file.
    let mut raw = [0_u8; KEY_SIZE];
    fs::File::open("/dev/urandom")
        .context("secure OS randomness unavailable")?
        .read_exact(&mut raw)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .context("creating private review key")?;
    file.write_all(&raw)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn load_review_key(path: &Path) -> Result<[u8; KEY_SIZE]> {
    let mut file = open_private_read(path, Some(KEY_SIZE as u64), KEY_SIZE as u64)
        .context("checking private review key")?;
    let mut raw = [0_u8; KEY_SIZE];
    file.read_exact(&mut raw)?;
    Ok(raw)
}

/// File identity must remain unchanged across the pathname check and open.
/// Without the fd metadata comparison, an attacker with directory write access
/// can replace a private manifest/key with a symlink after the initial lstat.
fn open_private_read(path: &Path, exact_size: Option<u64>, max_size: u64) -> Result<fs::File> {
    let before = fs::symlink_metadata(path).context("checking private file path")?;
    if !before.is_file()
        || before.permissions().mode() & 0o077 != 0
        || before.len() > max_size
        || exact_size.is_some_and(|n| before.len() != n)
    {
        anyhow::bail!("private input must be a regular file with safe permissions and size");
    }
    let file = fs::File::open(path).context("opening private file")?;
    let after = file.metadata().context("checking opened private file")?;
    if !after.is_file()
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.permissions().mode() & 0o077 != 0
        || after.len() > max_size
        || exact_size.is_some_and(|n| after.len() != n)
    {
        anyhow::bail!("private file changed or became unsafe during open");
    }
    Ok(file)
}

pub(crate) fn snapshot_mac(key: &[u8; KEY_SIZE], material: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("fixed length HMAC key");
    mac.update(b"bw-password-dedup-review-v2\0");
    mac.update(material);
    hex::encode(mac.finalize().into_bytes())
}

fn verify_snapshot_mac(key: &[u8; KEY_SIZE], material: &[u8], digest: &str) -> Result<()> {
    let decoded = hex::decode(digest).context("invalid snapshot binding encoding")?;
    let mut mac = HmacSha256::new_from_slice(key).expect("fixed length HMAC key");
    mac.update(b"bw-password-dedup-review-v2\0");
    mac.update(material);
    mac.verify_slice(&decoded)
        .map_err(|_| anyhow::anyhow!("decision snapshot is stale or unauthenticated"))
}

pub(crate) fn build_bound_manifest(
    groups: &[AccountGroupSummary],
    input_records: usize,
    snapshot_mac: String,
) -> DecisionManifest {
    DecisionManifest {
        schema_version: 2,
        kind: "snapshot-bound-decisions".to_owned(),
        input_records,
        snapshot_mac,
        groups: groups.iter().map(|group| DecisionGroup {
            references: group.records.iter().map(|record| ReviewReference {
                input_position: record.input_position,
                provider: record.provider.to_owned(),
                source_record: record.source_record,
            }).collect(),
            conflicting_passwords: group.conflicting_passwords,
            conflicting_totp: group.conflicting_totp,
            differing_metadata: group.differing_metadata,
            decision: ReviewDecision::Defer,
            selected_input_position: None,
        }).collect(),
        warning: "Review locally. Replaying requires the same key, source snapshots, order and policies. Original exports remain unchanged.".to_owned(),
    }
}

pub(crate) fn read_decisions(path: &Path) -> Result<DecisionManifest> {
    let file = open_private_read(path, None, MAX_MANIFEST)
        .context("checking private decision manifest")?;
    let doc: DecisionManifest = serde_json::from_reader(file)
        .context("invalid or unsupported review decisions manifest")?;
    Ok(doc)
}

pub(crate) fn validate_decisions(
    decisions: &DecisionManifest,
    current: &DecisionManifest,
    key: &[u8; KEY_SIZE],
    snapshot_material: &[u8],
) -> Result<Vec<ValidatedDecision>> {
    if decisions.schema_version != 2
        || decisions.kind != "snapshot-bound-decisions"
        || decisions.input_records != current.input_records
        || decisions.groups.len() != current.groups.len()
    {
        anyhow::bail!("unsupported or stale decision manifest");
    }
    verify_snapshot_mac(key, snapshot_material, &decisions.snapshot_mac)?;
    let mut used = std::collections::HashSet::new();
    let mut validated = Vec::new();
    for (given, expected) in decisions.groups.iter().zip(&current.groups) {
        if given.references != expected.references
            || given.conflicting_passwords != expected.conflicting_passwords
            || given.conflicting_totp != expected.conflicting_totp
            || given.differing_metadata != expected.differing_metadata
        {
            anyhow::bail!("decision group membership or metadata changed");
        }
        let positions: Vec<usize> = given.references.iter().map(|r| r.input_position).collect();
        if positions.len() < 2
            || positions
                .iter()
                .any(|p| *p == 0 || *p > decisions.input_records || !used.insert(*p))
        {
            anyhow::bail!("duplicate, missing or out-of-range decision references");
        }
        match given.decision {
            ReviewDecision::ChooseOne => {
                if !given
                    .selected_input_position
                    .is_some_and(|choice| positions.contains(&choice))
                {
                    anyhow::bail!("choose-one requires a member of the exact reviewed group");
                }
            }
            _ if given.selected_input_position.is_some() => {
                anyhow::bail!("unexpected chosen position for non-selecting decision");
            }
            _ => {}
        }
        validated.push(ValidatedDecision {
            positions,
            action: given.decision,
            selected_input_position: given.selected_input_position,
        });
    }
    Ok(validated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn demo_groups() -> Vec<AccountGroupSummary> {
        vec![AccountGroupSummary {
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
        }]
    }

    #[test]
    fn old_review_template_stays_non_executable() {
        let template: Value =
            serde_json::to_value(build_review_template(&demo_groups(), 3)).unwrap();
        assert_eq!(template["kind"], "review-template-not-executable");
        assert_eq!(template["groups"][0]["decision"], "defer");
        assert_eq!(template["groups"][0]["references"][0]["input_position"], 2);
        assert_eq!(template["groups"][0]["references"][0]["provider"], "edge");
        assert!(serde_json::from_value::<DecisionManifest>(template).is_err());
    }

    #[test]
    fn authenticated_review_refuses_modified_snapshot_and_membership() {
        let key = [0x32; 32];
        let data = b"synthetic ordered source data";
        let current = build_bound_manifest(&demo_groups(), 3, snapshot_mac(&key, data));
        let mut given: DecisionManifest =
            serde_json::from_value(serde_json::to_value(&current).unwrap()).unwrap();
        given.groups[0].decision = ReviewDecision::ChooseOne;
        given.groups[0].selected_input_position = Some(2);
        assert_eq!(
            validate_decisions(&given, &current, &key, data)
                .unwrap()
                .len(),
            1
        );
        assert!(validate_decisions(&given, &current, &key, b"modified data").is_err());
        assert!(validate_decisions(&given, &current, &[0x33; 32], data).is_err());
        given.groups[0].references[0].input_position = 99;
        assert!(validate_decisions(&given, &current, &key, data).is_err());
    }

    #[test]
    fn decision_options_must_be_unambiguous() {
        let key = [0x42; 32];
        let data = b"synthetic";
        let current = build_bound_manifest(&demo_groups(), 3, snapshot_mac(&key, data));
        let mut user: DecisionManifest =
            serde_json::from_value(serde_json::to_value(&current).unwrap()).unwrap();
        user.groups[0].decision = ReviewDecision::ChooseOne;
        assert!(validate_decisions(&user, &current, &key, data).is_err());
        user.groups[0].selected_input_position = Some(1);
        assert!(validate_decisions(&user, &current, &key, data).is_err());
        user.groups[0].selected_input_position = Some(2);
        assert!(validate_decisions(&user, &current, &key, data).is_ok());
        user.groups[0].decision = ReviewDecision::Defer;
        assert!(validate_decisions(&user, &current, &key, data).is_err());
    }
    #[test]
    fn private_review_files_refuse_symlinks_unsafe_permissions_and_sizes() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "bw-dedup-private-file-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let key_path = root.join("key.bin");
        fs::write(&key_path, [0x42; KEY_SIZE]).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load_review_key(&key_path).unwrap(), [0x42; KEY_SIZE]);

        let alias = root.join("alias.bin");
        symlink(&key_path, &alias).unwrap();
        assert!(load_review_key(&alias).is_err());

        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_review_key(&key_path).is_err());
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&key_path, [0x42; KEY_SIZE - 1]).unwrap();
        assert!(load_review_key(&key_path).is_err());

        let material = b"fictional-only";
        let manifest =
            build_bound_manifest(&demo_groups(), 3, snapshot_mac(&[0x42; KEY_SIZE], material));
        let manifest_path = root.join("decisions.json");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_decisions(&manifest_path).unwrap().groups.len(), 1);
        let manifest_alias = root.join("decisions-alias.json");
        symlink(&manifest_path, &manifest_alias).unwrap();
        assert!(read_decisions(&manifest_alias).is_err());
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_decisions(&manifest_path).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
