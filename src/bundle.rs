//! Best-effort multi-file publication of local secret-bearing output.
//! Companion files are published first; the primary JSON is published last.
//! This avoids updating the primary output if a companion write fails.
//! This is deliberately NOT a crash-atomic transaction across multiple files.

use crate::source_io;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
/// Filesystems cannot offer an atomic commit across independent pathnames.
/// A process kill, power loss, or a write failure after a pathname is linked
/// can still require manual inspection. Never auto-reimport after uncertainty.
pub(crate) fn publish_bundle(pending: &[PendingFile<'_>], input: Option<&Path>) -> Result<()> {
    publish_with(pending, |entry| {
        crate::write_private_atomically(entry.path, entry.bytes, entry.force, input)
    })
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
