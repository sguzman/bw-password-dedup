//! Fail-closed validation for directories containing plaintext credentials.
//! This does not defend against another process running as the same user or
//! symlink swaps in higher directory components. A private workspace remains
//! a requirement for migration.

use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub(crate) fn check_output_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("checking output parent {}", parent.display()))?;
    if !metadata.file_type().is_dir() {
        anyhow::bail!("output parent must be a real directory, not a symlink");
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        anyhow::bail!(
            "output parent is writable by other users; use a private directory (chmod 700)"
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
