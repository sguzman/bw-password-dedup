//! Private file publication and recovery. Only the primary export may
//! replace an existing destination, and only after a private backup succeeds.
//! Independent companion files are not crash-atomic as a group.

use crate::{path_safety, source_io};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Cap the size of pre-existing files copied by --force. This cap is
/// separate from the input-source limits because converted output grows.
pub(crate) const MAX_EXISTING_BACKUP_BYTES: u64 = 1024 * 1024 * 1024;

// Create exports with mode 0600, without truncating old data. On overwrite,
// retain a private backup first. All temporary files live next to their output
// to allow atomic rename on the same filesystem.
pub(crate) fn write_private_atomically(
    output: &Path,
    data: &[u8],
    force: bool,
    input: Option<&Path>,
) -> Result<()> {
    write_private_atomically_inner(output, data, force, input, false, false)
}

// The injection flag is never exposed to CLI users. It lets tests exercise
// the exact failure point between durable staging and replacement.
// Preserve the exact source snapshot used for --force recovery, not only its
// inode. Reject any size, mtime or ctime changes before/after the backup copy.
fn backup_source_unchanged(current: &fs::Metadata, original: &fs::Metadata) -> bool {
    matches_original_file_identity(current, original)
        && current.len() == original.len()
        && current.mtime() == original.mtime()
        && current.mtime_nsec() == original.mtime_nsec()
        && current.ctime() == original.ctime()
        && current.ctime_nsec() == original.ctime_nsec()
}

// Hash precisely the bytes copied from the prior output while limiting the
// read to its initial length plus one. A concurrent append is not copied.
fn copy_exact_backup<R: Read, W: Write>(
    previous: &mut R,
    backup: &mut W,
    expected_length: u64,
) -> Result<[u8; 32]> {
    let mut limited = previous.take(expected_length + 1);
    let mut copied = 0_u64;
    let mut digest = Sha256::new();
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let n = limited.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if copied + n as u64 > expected_length {
            anyhow::bail!("existing output grew during private backup");
        }
        backup.write_all(&chunk[..n])?;
        digest.update(&chunk[..n]);
        copied += n as u64;
    }
    if copied != expected_length {
        anyhow::bail!("existing output shrank during private backup");
    }
    Ok(digest.finalize().into())
}

// Check the PRIVATE backup's actual bytes, not just its inode and length,
// against the original bytes hashed during the copy. Never follow symlinks.
fn verify_private_backup(
    path: &Path,
    created: &fs::Metadata,
    expected_len: u64,
    expected_digest: &[u8; 32],
) -> Result<()> {
    let initial = fs::symlink_metadata(path).context("checking backup pathname")?;
    if !matches_original_file_identity(&initial, created)
        || initial.len() != expected_len
        || initial.permissions().mode() & 0o077 != 0
    {
        anyhow::bail!("private backup pathname changed or lost its private permissions");
    }

    let mut file = source_io::open_readonly_nofollow(path)?;
    let opened = file.metadata().context("checking opened backup")?;
    if !backup_snapshot_matches(&initial, &opened) {
        anyhow::bail!("private backup changed while opening for verification");
    }

    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    let mut bounded = Read::by_ref(&mut file).take(expected_len + 1);
    loop {
        let n = bounded.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        digest.update(&buffer[..n]);
    }
    let final_fd = file.metadata().context("checking backup descriptor after verification")?;
    let final_path = fs::symlink_metadata(path).context("checking backup name after verification")?;
    if bytes != expected_len
        || digest.finalize().as_slice() != expected_digest
        || !backup_snapshot_matches(&opened, &final_fd)
        || !backup_snapshot_matches(&opened, &final_path)
    {
        anyhow::bail!("private backup content or identity changed; original not replaced");
    }
    Ok(())
}

fn backup_snapshot_matches(before: &fs::Metadata, after: &fs::Metadata) -> bool {
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

fn backup_existing_output(
    output: &Path,
    backup_path: &Path,
    original: &fs::Metadata,
    before_open: impl FnOnce() -> Result<()>,
    after_copy: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if original.len() > MAX_EXISTING_BACKUP_BYTES {
        anyhow::bail!("existing output exceeds the 1 GiB safe backup limit");
    }
    let mut backup = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(backup_path)?;
    let created = backup.metadata().context("checking newly created backup")?;

    let result = (|| -> Result<()> {
        before_open()?;
        // Reject a late symlink or FIFO swap before reading backup source.
        let mut previous = source_io::open_readonly_nofollow(output)?;
        let opened = previous.metadata()?;
        if !backup_source_unchanged(&opened, original) {
            anyhow::bail!("existing output changed while opening backup source");
        }
        let expected_digest = copy_exact_backup(&mut previous, &mut backup, original.len())?;
        after_copy()?;
        let final_fd = previous.metadata()?;
        let final_path = fs::symlink_metadata(output)?;
        if !backup_source_unchanged(&final_fd, original)
            || !backup_source_unchanged(&final_path, original)
        {
            anyhow::bail!("existing output changed during backup; original not replaced");
        }
        let named_backup = fs::symlink_metadata(backup_path)?;
        if !matches_original_file_identity(&named_backup, &created)
            || named_backup.len() != original.len()
            || named_backup.permissions().mode() & 0o077 != 0
        {
            anyhow::bail!("private backup pathname changed during copy");
        }
        backup.sync_all()?;
        verify_private_backup(backup_path, &created, original.len(), &expected_digest)?;
        // fsync of the backup FILE alone does not durably record its NAME.
        // Persist the directory entry BEFORE overwriting the original.
        let parent = backup_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::File::open(parent)
            .context("opening backup directory")?
            .sync_all()
            .context("syncing backup directory before forced replacement")?;
        Ok(())
    })();

    if let Err(error) = result {
        // A failed backup only removes the inode this invocation created.
        match fs::symlink_metadata(backup_path) {
            Ok(current) if matches_original_file_identity(&current, &created) => {
                if let Err(cleanup) = fs::remove_file(backup_path) {
                    anyhow::bail!(
                        "{error:#}; partial backup cleanup failed: {cleanup}; inspect the directory"
                    );
                }
            }
            Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                anyhow::bail!(
                    "{error:#}; backup pathname changed; unrelated replacement preserved"
                );
            }
            Err(cleanup) => {
                anyhow::bail!(
                    "{error:#}; could not inspect partial backup during cleanup: {cleanup}"
                );
            }
        }
        return Err(error).context("private backup creation failed");
    }
    Ok(())
}

pub(crate) fn matches_original_file_identity(
    candidate: &fs::Metadata,
    original: &fs::Metadata,
) -> bool {
    candidate.is_file() && candidate.dev() == original.dev() && candidate.ino() == original.ino()
}

pub(crate) fn write_private_atomically_inner(
    output: &Path,
    data: &[u8],
    force: bool,
    input: Option<&Path>,
    simulate_interruption: bool,
    simulate_post_publication_failure: bool,
) -> Result<()> {
    path_safety::check_output_parent(output)?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let existing = match fs::symlink_metadata(output) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                anyhow::bail!(
                    "refusing non-regular or symlink output: {}",
                    output.display()
                );
            }
            if !force {
                anyhow::bail!("output already exists: {} (use --force)", output.display());
            }
            if meta.len() > MAX_EXISTING_BACKUP_BYTES {
                anyhow::bail!("existing output exceeds the 1 GiB safe backup limit");
            }
            Some(meta)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).with_context(|| format!("checking {}", output.display())),
    };

    if let (Some(_), Some(source)) = (&existing, input) {
        let source_meta = fs::metadata(source)?;
        let target_meta = fs::metadata(output)?;
        if source_meta.dev() == target_meta.dev() && source_meta.ino() == target_meta.ino() {
            anyhow::bail!("refusing to overwrite the original input");
        }
    }

    let basename = output
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("vault");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock predates Unix epoch")?
        .as_nanos();
    let temp_path = parent.join(format!(".{basename}.tmp.{}.{}", std::process::id(), stamp));

    let mut linked_new_output: Option<fs::Metadata> = None;
    let result = (|| -> Result<()> {
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)
            .with_context(|| format!("creating private temporary file for {}", output.display()))?;
        temp.write_all(data)?;
        temp.sync_all()?;
        let staged_identity = temp.metadata()?;
        drop(temp);

        if existing.is_some() {
            let backup_path = parent.join(format!(
                "{basename}.backup.{}.{}",
                std::process::id(),
                stamp
            ));
            let backup_result = backup_existing_output(
                output,
                &backup_path,
                existing
                    .as_ref()
                    .context("missing original output identity")?,
                || Ok(()),
                || Ok(()),
            );
            // This function syncs the new backup filename before any rename
            // and performs identity-safe cleanup if its copy fails.
            backup_result.context("failed to preserve existing output backup")?;
            // Check the pathname again after copying. A moved/replaced file
            // must not silently become the target of a forced overwrite.
            let current = fs::symlink_metadata(output)
                .context("checking output identity before replacement")?;
            let original = existing
                .as_ref()
                .context("missing original output identity")?;
            if !matches_original_file_identity(&current, original) {
                anyhow::bail!("existing output changed before replacement");
            }
            if simulate_interruption {
                anyhow::bail!("simulated interruption before replacing existing output");
            }
            fs::rename(&temp_path, output).context("failed to atomically replace output")?;
        } else {
            // Unlike rename, hard_link fails if another process has just
            // created the destination. This preserves no-overwrite semantics.
            if simulate_interruption {
                anyhow::bail!("simulated interruption before creating new output");
            }
            fs::hard_link(&temp_path, output)
                .context("failed to create new output without overwriting")?;
            // Track the actual staged inode so any later error can only
            // remove the pathname that this invocation successfully linked.
            linked_new_output = Some(staged_identity);
            fs::remove_file(&temp_path)?;
        }

        if simulate_post_publication_failure {
            anyhow::bail!("simulated filesystem failure after output publication");
        }
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();

    if let Err(error) = result {
        let mut cleanup_errors = Vec::new();
        if let Some(expected) = linked_new_output {
            // A failed directory sync or temp unlink can happen AFTER
            // hard_link has published the plaintext destination. Revoke
            // only the inode actually linked by us, never a replacement.
            match fs::symlink_metadata(output) {
                Ok(current) if matches_original_file_identity(&current, &expected) => {
                    if let Err(err) = fs::remove_file(output) {
                        cleanup_errors.push(format!("new output removal failed: {err}"));
                    }
                }
                Ok(_) => cleanup_errors.push("new output identity changed".to_string()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => cleanup_errors.push(format!("new output inspection failed: {err}")),
            }
        }
        match fs::remove_file(&temp_path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => cleanup_errors.push(format!("temporary file removal failed: {err}")),
        }
        if !cleanup_errors.is_empty() {
            anyhow::bail!(
                "{error:#}; cleanup incomplete: {}; inspect private destination before retry",
                cleanup_errors.join("; ")
            );
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn fixture_dir(label: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "bw-private-writer-{label}-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[test]
    fn same_size_backup_corruption_is_rejected_without_replacing_original() {
        let root = fixture_dir("backup-corruption");
        let output = root.join("original.json");
        let backup = root.join("backup.json");
        fs::write(&output, b"previous fictional vault").unwrap();
        let original = fs::symlink_metadata(&output).unwrap();
        let result = backup_existing_output(
            &output,
            &backup,
            &original,
            || Ok(()),
            || {
                // Same byte count and same inode, but contents differ.
                fs::write(&backup, b"CORRUPT! fictional vault")?;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&output).unwrap(), b"previous fictional vault");
        assert!(!backup.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn intact_backup_is_verified_before_forced_replacement() {
        let root = fixture_dir("verified-backup");
        let output = root.join("original.json");
        let backup = root.join("backup.json");
        fs::write(&output, b"previous fictional vault").unwrap();
        let original = fs::symlink_metadata(&output).unwrap();
        backup_existing_output(&output, &backup, &original, || Ok(()), || Ok(())).unwrap();
        assert_eq!(fs::read(&backup).unwrap(), b"previous fictional vault");
        assert_eq!(fs::read(&output).unwrap(), b"previous fictional vault");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn growing_backup_copy_stops_after_one_extra_byte() {
        let mut input = std::io::Cursor::new(b"fictional growing content".as_slice());
        let mut destination = Vec::new();
        assert!(copy_exact_backup(&mut input, &mut destination, 8).is_err());
        assert!(destination.len() <= 8);
        let mut short = std::io::Cursor::new(b"short".as_slice());
        assert!(copy_exact_backup(&mut short, &mut Vec::new(), 8).is_err());
        let mut exact = std::io::Cursor::new(b"exact".as_slice());
        let mut copied = Vec::new();
        copy_exact_backup(&mut exact, &mut copied, 5).unwrap();
        assert_eq!(copied, b"exact");
    }

    #[test]
    fn failed_backup_copy_removes_only_its_private_inode() {
        let root = fixture_dir("partial-backup");
        let output = root.join("existing.json");
        let backup = root.join("backup.json");
        fs::write(&output, b"old fictional export").unwrap();
        let original = fs::symlink_metadata(&output).unwrap();
        let error = backup_existing_output(
            &output,
            &backup,
            &original,
            || Ok(()),
            || anyhow::bail!("synthetic failure"),
        );
        assert!(error.is_err());
        assert!(!backup.exists());
        assert_eq!(fs::read(&output).unwrap(), b"old fictional export");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_backup_copy_preserves_replaced_backup_name() {
        let root = fixture_dir("backup-swap");
        let output = root.join("existing.json");
        let backup = root.join("backup.json");
        let parked = root.join("parked-backup");
        fs::write(&output, b"old fictional export").unwrap();
        let original = fs::symlink_metadata(&output).unwrap();
        let error = backup_existing_output(
            &output,
            &backup,
            &original,
            || Ok(()),
            || {
                fs::rename(&backup, &parked)?;
                fs::write(&backup, b"unrelated replacement")?;
                anyhow::bail!("synthetic replacement")
            },
        );
        assert!(error.is_err());
        assert_eq!(fs::read(&backup).unwrap(), b"unrelated replacement");
        assert_eq!(fs::read(&parked).unwrap(), b"old fictional export");
        assert_eq!(fs::read(&output).unwrap(), b"old fictional export");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_existing_output_refuses_force_before_staging() {
        let root = fixture_dir("backup-cap");
        let output = root.join("existing.json");
        let file = fs::File::create(&output).unwrap();
        file.set_len(MAX_EXISTING_BACKUP_BYTES + 1).unwrap();
        drop(file);
        assert!(write_private_atomically(&output, b"fictional", true, None).is_err());
        assert_eq!(
            fs::metadata(&output).unwrap().len(),
            MAX_EXISTING_BACKUP_BYTES + 1
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn forced_backup_rejects_in_place_change_after_copy() {
        let root = fixture_dir("changed");
        let original_path = root.join("existing.json");
        let backup = root.join("backup.json");
        fs::write(&original_path, b"previous fictional export").unwrap();
        let original = fs::symlink_metadata(&original_path).unwrap();
        let result = backup_existing_output(
            &original_path,
            &backup,
            &original,
            || Ok(()),
            || {
                use std::io::Write;
                fs::OpenOptions::new()
                    .append(true)
                    .open(&original_path)?
                    .write_all(b" was modified")?;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(
            fs::read(&original_path).unwrap(),
            b"previous fictional export was modified"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn forced_backup_rejects_preopen_symlink_swap_without_reading_victim() {
        let root = fixture_dir("swapped");
        let output = root.join("existing.json");
        let backup = root.join("backup.json");
        let parked = root.join("parked.json");
        let victim = root.join("other.json");
        fs::write(&output, b"old fictional export").unwrap();
        fs::write(&victim, b"unrelated fictional content").unwrap();
        let original = fs::symlink_metadata(&output).unwrap();
        let result = backup_existing_output(
            &output,
            &backup,
            &original,
            || {
                fs::rename(&output, &parked)?;
                symlink(&victim, &output)?;
                Ok(())
            },
            || Ok(()),
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&parked).unwrap(), b"old fictional export");
        assert_eq!(fs::read(&victim).unwrap(), b"unrelated fictional content");
        fs::remove_dir_all(root).unwrap();
    }
}
