//! Best-effort multi-file publication of local secret-bearing output.
//! Companion files are published first; the primary JSON is published last.
//! This avoids updating the primary output if a companion write fails.
//! This is deliberately NOT a crash-atomic transaction across multiple files.

use crate::source_io;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(crate) struct PendingFile<'a> {
    pub(crate) path: &'a Path,
    pub(crate) bytes: &'a [u8],
    pub(crate) force: bool,
}

struct Published {
    path: PathBuf,
    device: u64,
    inode: u64,
}

// Confirm that every published file is actually the expected private,
// unmodified content. A successful write() by itself is insufficient: an
// unexpected writer, truncation, or wrong bytes must never produce "Wrote".
// Stream through a bounded buffer rather than materializing another copy of
// a potentially large plaintext credential export.
fn verify_published(entry: &PendingFile<'_>) -> Result<fs::Metadata> {
    let initial = fs::symlink_metadata(entry.path)
        .with_context(|| format!("checking published file {}", entry.path.display()))?;
    if !initial.file_type().is_file()
        || initial.permissions().mode() & 0o077 != 0
        || initial.len() != entry.bytes.len() as u64
    {
        anyhow::bail!("published output is not an expected private regular file");
    }

    let mut file = source_io::open_readonly_nofollow(entry.path)?;
    let opened = file
        .metadata()
        .context("checking opened published output")?;
    if !same_published_snapshot(&initial, &opened) {
        anyhow::bail!("published output changed before verification");
    }

    let mut reader = file.by_ref().take(initial.len() + 1);
    let mut buffer = [0_u8; 16 * 1024];
    let mut digest = Sha256::new();
    let mut read_bytes = 0_u64;
    loop {
        let n = reader
            .read(&mut buffer)
            .context("verifying published output")?;
        if n == 0 {
            break;
        }
        read_bytes += n as u64;
        digest.update(&buffer[..n]);
    }
    let final_fd = file
        .metadata()
        .context("checking verified output descriptor")?;
    let final_path =
        fs::symlink_metadata(entry.path).context("checking verified output pathname")?;
    if read_bytes != initial.len()
        || digest.finalize() != Sha256::digest(entry.bytes)
        || !same_published_snapshot(&opened, &final_fd)
        || !same_published_snapshot(&opened, &final_path)
    {
        anyhow::bail!("published output changed or failed content verification");
    }
    Ok(opened)
}

fn same_published_snapshot(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    after.file_type().is_file()
        && after.permissions().mode() & 0o077 == 0
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn cleanup_owned_outputs(published: &[Published]) -> Result<()> {
    let mut errors = Vec::new();
    for entry in published.iter().rev() {
        // Never unlink a pathname replaced by someone else after publication.
        match fs::symlink_metadata(&entry.path) {
            Ok(meta)
                if meta.file_type().is_file()
                    && meta.dev() == entry.device
                    && meta.ino() == entry.inode =>
            {
                if let Err(error) = fs::remove_file(&entry.path) {
                    errors.push(format!("{}: {error}", entry.path.display()));
                }
            }
            Ok(_) => errors.push(format!("{}: identity changed", entry.path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => errors.push(format!("{}: {error}", entry.path.display())),
        }
    }
    if !errors.is_empty() {
        anyhow::bail!(
            "partial output cleanup failed; inspect destination files before retry: {}",
            errors.join("; ")
        );
    }
    Ok(())
}

fn failed_publication(error: anyhow::Error, published: &[Published]) -> anyhow::Error {
    match cleanup_owned_outputs(published) {
        Ok(()) => error
            .context("output bundle incomplete; previously published companions were cleaned up"),
        Err(cleanup_error) => error.context(cleanup_error.to_string()),
    }
}

/// All destination collisions and protected input aliases must be preflighted
/// by the caller before invoking this function. The final entry is the primary
/// JSON output, so a failure among companion files never changes it.
///
/// A durable, private marker is created before any output and deleted only
/// after successful bundle verification and output fsync. If the process is
/// killed or publishing fails, the marker remains. It is not a transaction:
/// an abrupt crash can still leave partial data and backup files.
pub(crate) fn publish_bundle(pending: &[PendingFile<'_>], input: Option<&Path>) -> Result<()> {
    publish_guarded_with(pending, || {
        publish_with(pending, |entry| {
            crate::write_private_atomically(entry.path, entry.bytes, entry.force, input)
        })
    })
}

fn incomplete_marker_path(primary: &Path) -> Result<PathBuf> {
    let name = primary
        .file_name()
        .context("primary output must have a filename")?;
    let mut filename = OsString::from(".");
    filename.push(name);
    filename.push(".bw-dedup.incomplete");
    let parent = primary
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(parent.join(filename))
}

fn sync_output_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)
        .with_context(|| format!("opening publication directory {}", parent.display()))?
        .sync_all()
        .context("syncing publication directory")
}

// Write-ahead recovery marker: its presence means the output set must not be
// trusted or automatically retried. It contains only expected destination
// filenames (as private JSON metadata), never the credential bytes or hashes.
// The creation and parent-directory fsync finish BEFORE the first output write.
// Existing markers are not overwritten, even by --force.
fn publish_guarded_with(
    pending: &[PendingFile<'_>],
    publish: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let primary = pending
        .last()
        .context("output bundle must contain a primary file")?;
    if pending.iter().rev().skip(1).any(|entry| entry.force) {
        anyhow::bail!("forced output replacement must be the final publication");
    }
    let marker_path = incomplete_marker_path(primary.path)?;
    if pending
        .iter()
        .any(|entry| crate::same_destination(entry.path, &marker_path).unwrap_or(true))
    {
        anyhow::bail!("incomplete marker would collide with a requested output");
    }
    crate::path_safety::check_output_parent(&marker_path)?;
    let destinations = pending
        .iter()
        .map(|entry| entry.path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let contents = serde_json::to_vec_pretty(&serde_json::json!({
        "kind": "bw-password-dedup-incomplete-bundle",
        "status": "incomplete",
        "warning": "Inspect ALL outputs and backups before import or retry. This is not an atomic transaction.",
        "expected_destinations": destinations
    }))?;

    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&marker_path)
        .with_context(|| format!(
            "an incomplete export may already exist at {}; inspect all destinations and backups before removing that marker or retrying",
            marker_path.display()
        ))?;
    let identity = marker
        .metadata()
        .context("checking new incomplete marker")?;
    // An error while initializing the marker intentionally leaves it in
    // place to prevent a blind retry after an ambiguous durability failure.
    marker.write_all(&contents).with_context(|| {
        format!(
            "could not initialize {}; inspect the incomplete marker before retrying",
            marker_path.display()
        )
    })?;
    marker.sync_all()?;
    sync_output_parent(&marker_path)?;
    drop(marker);

    if let Err(error) = publish() {
        return Err(error).with_context(|| {
            format!(
                "incomplete export marker retained at {}; inspect all destinations before retrying",
                marker_path.display()
            )
        });
    }

    let current = fs::symlink_metadata(&marker_path)
        .context("verifying incomplete marker before completion")?;
    if !current.file_type().is_file()
        || current.dev() != identity.dev()
        || current.ino() != identity.ino()
    {
        anyhow::bail!(
            "incomplete export marker identity changed at {}; inspect outputs",
            marker_path.display()
        );
    }
    fs::remove_file(&marker_path)
        .context("could not remove incomplete marker after successful output verification")?;
    sync_output_parent(&marker_path)
        .context("could not durably clear incomplete marker; inspect outputs before retrying")?;
    Ok(())
}

fn publish_with(
    pending: &[PendingFile<'_>],
    mut writer: impl FnMut(&PendingFile<'_>) -> Result<()>,
) -> Result<()> {
    // Validate publication order before touching any destination.
    if pending.iter().rev().skip(1).any(|entry| entry.force) {
        anyhow::bail!("forced output replacement must be the final publication");
    }
    let mut published: Vec<Published> = Vec::new();
    for entry in pending {
        // The primary JSON is always last; earlier companions can be removed
        // on ordinary failure without replacing the authoritative output.
        if let Err(error) = writer(entry) {
            return Err(failed_publication(error, &published));
        }
        // Capture the newly written inode BEFORE verifying its bytes. On a
        // verification failure, remove only outputs still owned by this run.
        // The forced primary may have replaced the old path and is not
        // automatically removed: retain its private backup for inspection.
        if !entry.force {
            match fs::symlink_metadata(entry.path) {
                Ok(meta) if meta.file_type().is_file() => {
                    published.push(Published {
                        path: entry.path.to_owned(),
                        device: meta.dev(),
                        inode: meta.ino(),
                    });
                }
                Ok(_) => {
                    return Err(failed_publication(
                        anyhow::anyhow!(
                            "published output is not a regular file: {}",
                            entry.path.display()
                        ),
                        &published,
                    ));
                }
                Err(error) => {
                    return Err(failed_publication(
                        anyhow::Error::from(error)
                            .context("published output could not be checked; inspect outputs"),
                        &published,
                    ));
                }
            }
        }
        if let Err(error) = verify_published(entry) {
            return Err(failed_publication(
                error.context("output bundle verification failed; inspect outputs before import"),
                &published,
            ));
        }
    }

    // The primary JSON is written last, but an earlier companion could
    // change after its initial verification. Re-verify the entire bundle
    // before signaling success; ordinary errors clean up only our files.
    for entry in pending {
        if let Err(error) = verify_published(entry) {
            return Err(failed_publication(
                error.context("output bundle changed after publication; do not import"),
                &published,
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture_root() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("bw-dedup-bundle-{}-{stamp}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[test]
    fn incomplete_marker_survives_interrupted_bundle_and_blocks_retry() {
        let root = fixture_root();
        let report = root.join("redacted-report.json");
        let primary = root.join("clean.json");
        let marker = incomplete_marker_path(&primary).unwrap();
        let pending = [
            PendingFile {
                path: &report,
                bytes: b"fictional report",
                force: false,
            },
            PendingFile {
                path: &primary,
                bytes: b"fictional vault",
                force: false,
            },
        ];
        let result = publish_guarded_with(&pending, || {
            crate::write_private_atomically(&report, b"fictional report", false, None)?;
            anyhow::bail!("simulated interruption after first companion publication")
        });
        assert!(result.is_err());
        assert!(marker.exists());
        assert_eq!(fs::read(&report).unwrap(), b"fictional report");
        assert!(!primary.exists());
        assert_eq!(
            fs::metadata(&marker).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let marker_text = String::from_utf8(fs::read(&marker).unwrap()).unwrap();
        assert!(marker_text.contains("incomplete"));
        assert!(marker_text.contains("redacted-report.json"));
        // A repeated run must stop BEFORE invoking its writer.
        let mut invoked = false;
        let repeat = publish_guarded_with(&pending, || {
            invoked = true;
            Ok(())
        });
        assert!(repeat.is_err());
        assert!(!invoked);
        assert!(marker.exists());
        assert_eq!(fs::read(&report).unwrap(), b"fictional report");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verified_bundle_clears_write_ahead_marker() {
        let root = fixture_root();
        let primary = root.join("clean.json");
        let marker = incomplete_marker_path(&primary).unwrap();
        let pending = [PendingFile {
            path: &primary,
            bytes: b"fictional vault",
            force: false,
        }];
        publish_bundle(&pending, None).unwrap();
        assert!(!marker.exists());
        assert_eq!(fs::read(&primary).unwrap(), b"fictional vault");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn marker_collision_with_output_fails_without_writes() {
        let root = fixture_root();
        let primary = root.join("clean.json");
        let marker = incomplete_marker_path(&primary).unwrap();
        let pending = [
            PendingFile {
                path: &marker,
                bytes: b"fictional companion",
                force: false,
            },
            PendingFile {
                path: &primary,
                bytes: b"fictional vault",
                force: false,
            },
        ];
        let mut invoked = false;
        let result = publish_guarded_with(&pending, || {
            invoked = true;
            Ok(())
        });
        assert!(result.is_err());
        assert!(!invoked);
        assert!(!marker.exists());
        assert!(!primary.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn companion_failure_removes_only_new_files_and_preserves_old_primary() {
        let root = fixture_root();
        let report = root.join("report.json");
        let csv = root.join("browser.csv");
        let primary = root.join("clean.json");
        fs::write(&primary, b"previous synthetic vault").unwrap();
        let pending = [
            PendingFile {
                path: &report,
                bytes: b"synthetic report",
                force: false,
            },
            PendingFile {
                path: &csv,
                bytes: b"synthetic csv",
                force: false,
            },
            PendingFile {
                path: &primary,
                bytes: b"new synthetic vault",
                force: true,
            },
        ];
        let mut index = 0;
        let result = publish_with(&pending, |entry| {
            index += 1;
            if index == 2 {
                anyhow::bail!("simulated companion write failure");
            }
            crate::write_private_atomically(entry.path, entry.bytes, entry.force, None)
        });
        assert!(result.is_err());
        assert!(!report.exists());
        assert!(!csv.exists());
        assert_eq!(fs::read(&primary).unwrap(), b"previous synthetic vault");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn primary_failure_rolls_back_companions_without_replacing_original() {
        let root = fixture_root();
        let report = root.join("report.json");
        let primary = root.join("clean.json");
        fs::write(&primary, b"old synthetic vault").unwrap();
        let pending = [
            PendingFile {
                path: &report,
                bytes: b"synthetic report",
                force: false,
            },
            PendingFile {
                path: &primary,
                bytes: b"new synthetic vault",
                force: true,
            },
        ];
        let result = publish_with(&pending, |entry| {
            if entry.force {
                anyhow::bail!("simulated primary write failure");
            }
            crate::write_private_atomically(entry.path, entry.bytes, entry.force, None)
        });
        assert!(result.is_err());
        assert!(!report.exists());
        assert_eq!(fs::read(&primary).unwrap(), b"old synthetic vault");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn successful_bundle_publishes_private_companions_before_primary() {
        let root = fixture_root();
        let report = root.join("report.json");
        let primary = root.join("clean.json");
        let pending = [
            PendingFile {
                path: &report,
                bytes: b"synthetic report",
                force: false,
            },
            PendingFile {
                path: &primary,
                bytes: b"synthetic vault",
                force: false,
            },
        ];
        publish_bundle(&pending, None).unwrap();
        assert_eq!(fs::read(&report).unwrap(), b"synthetic report");
        assert_eq!(fs::read(&primary).unwrap(), b"synthetic vault");
        assert_eq!(
            fs::metadata(&report).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&primary).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replaced_companion_keeps_foreign_symlink_and_cleans_earlier_outputs() {
        let root = fixture_root();
        let report = root.join("report.json");
        let csv = root.join("browser.csv");
        let primary = root.join("clean.json");
        let victim = root.join("unrelated.txt");
        fs::write(&victim, b"untouched unrelated file").unwrap();
        let pending = [
            PendingFile {
                path: &report,
                bytes: b"synthetic report",
                force: false,
            },
            PendingFile {
                path: &csv,
                bytes: b"synthetic browser credentials",
                force: false,
            },
            PendingFile {
                path: &primary,
                bytes: b"synthetic vault",
                force: false,
            },
        ];
        let result = publish_with(&pending, |entry| {
            crate::write_private_atomically(entry.path, entry.bytes, entry.force, None)?;
            if entry.path == csv.as_path() {
                fs::remove_file(&csv)?;
                symlink(&victim, &csv)?;
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(!report.exists());
        assert!(fs::symlink_metadata(&csv).unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&victim).unwrap(), b"untouched unrelated file");
        assert!(!primary.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn vanished_companion_after_write_cleans_previously_published_files() {
        let root = fixture_root();
        let report = root.join("report.json");
        let csv = root.join("browser.csv");
        let primary = root.join("clean.json");
        let pending = [
            PendingFile {
                path: &report,
                bytes: b"synthetic report",
                force: false,
            },
            PendingFile {
                path: &csv,
                bytes: b"synthetic browser credentials",
                force: false,
            },
            PendingFile {
                path: &primary,
                bytes: b"synthetic vault",
                force: false,
            },
        ];
        let result = publish_with(&pending, |entry| {
            crate::write_private_atomically(entry.path, entry.bytes, entry.force, None)?;
            if entry.path == csv.as_path() {
                fs::remove_file(&csv)?;
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(!report.exists());
        assert!(!csv.exists());
        assert!(!primary.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn silent_companion_corruption_cannot_claim_success_or_publish_primary() {
        let root = fixture_root();
        let report = root.join("report.json");
        let primary = root.join("clean.json");
        let pending = [
            PendingFile {
                path: &report,
                bytes: b"expected fictional report",
                force: false,
            },
            PendingFile {
                path: &primary,
                bytes: b"fictional consolidated output",
                force: false,
            },
        ];

        let result = publish_with(&pending, |entry| {
            crate::write_private_atomically(entry.path, entry.bytes, entry.force, None)?;
            if entry.path == report.as_path() {
                fs::write(&report, b"wrong but private content")?;
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(!report.exists());
        assert!(!primary.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn late_companion_mutation_after_primary_publication_revokes_bundle() {
        let root = fixture_root();
        let report = root.join("report.json");
        let primary = root.join("clean.json");
        let pending = [
            PendingFile {
                path: &report,
                bytes: b"expected fictional report",
                force: false,
            },
            PendingFile {
                path: &primary,
                bytes: b"fictional consolidated output",
                force: false,
            },
        ];

        let result = publish_with(&pending, |entry| {
            crate::write_private_atomically(entry.path, entry.bytes, entry.force, None)?;
            if entry.path == primary.as_path() {
                fs::write(&report, b"tampered after report verification")?;
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(!report.exists());
        assert!(!primary.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn changed_companion_permissions_cannot_claim_private_bundle() {
        let root = fixture_root();
        let report = root.join("report.json");
        let primary = root.join("clean.json");
        let pending = [
            PendingFile {
                path: &report,
                bytes: b"fictional report",
                force: false,
            },
            PendingFile {
                path: &primary,
                bytes: b"fictional output",
                force: false,
            },
        ];
        let result = publish_with(&pending, |entry| {
            crate::write_private_atomically(entry.path, entry.bytes, entry.force, None)?;
            if entry.path == report.as_path() {
                fs::set_permissions(&report, fs::Permissions::from_mode(0o644))?;
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(!report.exists());
        assert!(!primary.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn forced_companion_replacement_is_refused() {
        let root = fixture_root();
        let report = root.join("report.json");
        let primary = root.join("clean.json");
        let pending = [
            PendingFile {
                path: &report,
                bytes: b"synthetic report",
                force: true,
            },
            PendingFile {
                path: &primary,
                bytes: b"synthetic vault",
                force: false,
            },
        ];
        assert!(publish_bundle(&pending, None).is_err());
        assert!(!report.exists());
        assert!(!primary.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
