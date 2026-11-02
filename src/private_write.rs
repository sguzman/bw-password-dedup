//! Private file publication and recovery. Only the primary export may
//! replace an existing destination, and only after a private backup succeeds.
//! Independent companion files are not crash-atomic as a group.

use crate::{path_safety, source_io};
use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn backup_existing_output(
    output: &Path,
    backup_path: &Path,
    original: &fs::Metadata,
    before_open: impl FnOnce() -> Result<()>,
    after_copy: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut backup = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(backup_path)?;
    before_open()?;
    // Opening only after an lstat could otherwise block on a substituted
    // FIFO or follow a substituted symlink before fstat checks the inode.
    let mut previous = source_io::open_readonly_nofollow(output)?;
    let opened = previous.metadata()?;
    if !backup_source_unchanged(&opened, original) {
        anyhow::bail!("existing output changed while opening backup source");
    }
    let copied = std::io::copy(&mut previous, &mut backup)?;
    after_copy()?;
    let final_fd = previous.metadata()?;
    let final_path = fs::symlink_metadata(output)?;
    if copied != original.len()
        || !backup_source_unchanged(&final_fd, original)
        || !backup_source_unchanged(&final_path, original)
    {
        anyhow::bail!("existing output changed during backup; original not replaced");
    }
    backup.sync_all()?;
    Ok(())
}

fn matches_original_file_identity(candidate: &fs::Metadata, original: &fs::Metadata) -> bool {
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
            if backup_result.is_err() {
                let _ = fs::remove_file(&backup_path);
            }
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
