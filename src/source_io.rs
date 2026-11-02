//! Bounded, read-only ingestion of local credential snapshots.
//!
//! Checking both descriptor metadata and pathname identity before and after
//! reading detects common concurrent truncation, rewrite and path swaps.
//! It is not an atomic snapshot against hostile same-user writers; always
//! work from a private, quiescent copy of exported credentials.

use crate::MAX_INPUT_BYTES;
use anyhow::{Context, Result};
use std::fs::{self, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

fn unchanged_file(before: &Metadata, after: &Metadata) -> bool {
    before.file_type().is_file()
        && after.file_type().is_file()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn read_checked_source_with(input: &Path, after_read: impl FnOnce() -> Result<()>) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(input)
        .with_context(|| format!("checking input {}", input.display()))?;
    if !before.file_type().is_file() {
        anyhow::bail!(
            "input must be a regular, non-symlink file: {}",
            input.display()
        );
    }
    if before.len() > MAX_INPUT_BYTES {
        anyhow::bail!("input exceeds the 64 MiB limit");
    }

    let mut file =
        fs::File::open(input).with_context(|| format!("opening input {}", input.display()))?;
    let opened = file.metadata().context("checking opened input file")?;
    if !unchanged_file(&before, &opened) {
        anyhow::bail!("input file changed or became unsafe while opening");
    }

    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("reading bounded source snapshot")?;
    after_read()?;

    // Recheck the open descriptor as well as the pathname: a process may
    // modify bytes in place, truncate them, or swap the named file mid-read.
    let final_fd = file.metadata().context("checking read source identity")?;
    let final_path =
        fs::symlink_metadata(input).context("checking source pathname after read")?;
    if !unchanged_file(&opened, &final_fd)
        || !unchanged_file(&opened, &final_path)
        || bytes.len() as u64 != opened.len()
    {
        anyhow::bail!("source changed while reading; use an immutable private snapshot");
    }
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        anyhow::bail!("input exceeds the 64 MiB limit");
    }
    Ok(bytes)
}

pub(crate) fn read_checked_source(input: &Path) -> Result<Vec<u8>> {
    read_checked_source_with(input, || Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture_dir() -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("bw-source-{}-{stamp}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[test]
    fn unchanged_private_source_is_read_without_modification() {
        let root = fixture_dir();
        let input = root.join("fictional.json");
        fs::write(&input, b"fictional snapshot").unwrap();
        assert_eq!(read_checked_source(&input).unwrap(), b"fictional snapshot");
        assert_eq!(fs::read(&input).unwrap(), b"fictional snapshot");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn in_place_growth_during_read_is_rejected() {
        let root = fixture_dir();
        let input = root.join("fictional.json");
        fs::write(&input, b"initial fictional bytes").unwrap();
        let result = read_checked_source_with(&input, || {
            use std::io::Write;
            fs::OpenOptions::new()
                .append(true)
                .open(&input)?
                .write_all(b" changed")?;
            Ok(())
        });
        assert!(result.is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pathname_replacement_during_read_is_rejected() {
        let root = fixture_dir();
        let input = root.join("fictional.json");
        let moved = root.join("moved.json");
        fs::write(&input, b"original fictional bytes").unwrap();
        let result = read_checked_source_with(&input, || {
            fs::rename(&input, &moved)?;
            fs::write(&input, b"different fictional bytes")?;
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(fs::read(&moved).unwrap(), b"original fictional bytes");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn symlinked_input_is_rejected_without_following_it() {
        let root = fixture_dir();
        let input = root.join("fictional.json");
        let link = root.join("alias.json");
        fs::write(&input, b"fictional").unwrap();
        symlink(&input, &link).unwrap();
        assert!(read_checked_source(&link).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
