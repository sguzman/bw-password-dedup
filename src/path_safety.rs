//! Fail-closed validation for directories containing plaintext credentials.
//! This does not defend against another process running as the same user or
//! symlink swaps in higher directory components. A private workspace remains
//! a requirement for migration.

use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

pub(crate) fn check_output_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    // Reject symlinks in the explicitly provided path, not just at the
    // last directory component. Canonicalization alone would hide them.
    for prefix in parent.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let metadata = fs::symlink_metadata(prefix)
            .with_context(|| format!("checking output directory {}", prefix.display()))?;
        if !metadata.file_type().is_dir() {
            anyhow::bail!("output directory path must not contain symlinks or non-directories");
        }
    }

    let canonical = fs::canonicalize(parent).context("resolving output parent directory")?;
    let owner = fs::metadata(&canonical)?.uid();
    for (index, directory) in canonical.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(directory)
            .with_context(|| format!("checking output ancestor {}", directory.display()))?;
        let mode = metadata.permissions().mode();
        if !metadata.file_type().is_dir() {
            anyhow::bail!("output parent ancestry contains a non-directory");
        }
        if mode & 0o022 == 0 {
            continue;
        }
        // Sticky parent directories (such as root-owned /tmp) prevent other
        // unprivileged users from renaming a private child they do not own.
        // Never permit the actual output parent to be shared-writable.
        if index > 0 && mode & 0o1000 != 0 && (metadata.uid() == 0 || metadata.uid() == owner) {
            continue;
        }
        anyhow::bail!(
            "output directory or ancestor is writable by other users; use a private directory"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture_root() -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "bw-dedup-path-safety-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[test]
    fn private_parent_allows_output_and_readable_nonwritable_parent_is_allowed() {
        let root = fixture_root();
        assert!(check_output_parent(&root.join("safe.json")).is_ok());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_output_parent(&root.join("also-safe.json")).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn group_and_other_writable_parents_are_rejected() {
        let root = fixture_root();
        for mode in [0o770, 0o707, 0o777, 0o1777] {
            fs::set_permissions(&root, fs::Permissions::from_mode(mode)).unwrap();
            assert!(check_output_parent(&root.join("credentials.json")).is_err());
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_writable_ancestor_is_rejected_even_with_private_child() {
        let root = fixture_root();
        let shared = root.join("untrusted");
        let private = shared.join("private");
        fs::create_dir(&shared).unwrap();
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();

        assert!(check_output_parent(&private.join("fictional.json")).is_err());

        // A sticky directory owned by the same user protects its private
        // children from other accounts, as /tmp normally does.
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(check_output_parent(&private.join("fictional.json")).is_ok());

        fs::set_permissions(&shared, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn symlinked_ancestor_is_rejected() {
        let root = fixture_root();
        let real = root.join("real");
        let alias = root.join("alias");
        let child = real.join("child");
        fs::create_dir(&real).unwrap();
        fs::create_dir(&child).unwrap();
        symlink(&real, &alias).unwrap();
        assert!(check_output_parent(&alias.join("child").join("fictional.json")).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn symlinked_parent_is_rejected() {
        let root = fixture_root();
        let actual = root.join("actual");
        let alias = root.join("alias");
        fs::create_dir(&actual).unwrap();
        symlink(&actual, &alias).unwrap();
        assert!(check_output_parent(&alias.join("credentials.json")).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
