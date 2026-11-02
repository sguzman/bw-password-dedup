//! Linux process hardening for a CLI that handles plaintext credentials.
//! Disable kernel core dumps before parsing any input file or review key.
//!
//! FFI is isolated here because the standard library does not expose prctl.
//! A nondumpable process is not equivalent to zeroized RAM or encrypted swap.

use anyhow::{Context, Result};

#[cfg(target_os = "linux")]
const PR_GET_DUMPABLE: i32 = 3;
#[cfg(target_os = "linux")]
const PR_SET_DUMPABLE: i32 = 4;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn prctl(option: i32, ...) -> i32;
}

#[cfg(target_os = "linux")]
fn get_dumpable() -> Result<i32> {
    // SAFETY: Linux prctl accepts an int command followed by unsigned-long
    // arguments; PR_GET_DUMPABLE ignores all remaining zero-valued arguments.
    let state = unsafe { prctl(PR_GET_DUMPABLE, 0_usize, 0_usize, 0_usize, 0_usize) };
    if state < 0 {
        return Err(std::io::Error::last_os_error()).context("checking Linux core-dump policy");
    }
    Ok(state)
}

pub(crate) fn disable_core_dumps() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes one unsigned-long value, 0, and
        // additional unused zero arguments. No pointers or borrowed data.
        let status = unsafe { prctl(PR_SET_DUMPABLE, 0_usize, 0_usize, 0_usize, 0_usize) };
        if status != 0 {
            return Err(std::io::Error::last_os_error())
                .context("disabling Linux process core dumps");
        }
        if get_dumpable()? != 0 {
            anyhow::bail!("core-dump protection could not be verified");
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("credential processing requires Linux core-dump protection");
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn linux_process_is_nondumpable_before_credentials_are_handled() {
        disable_core_dumps().unwrap();
        assert_eq!(get_dumpable().unwrap(), 0);
    }
}
