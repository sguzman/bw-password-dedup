# bw-passport-dedup v0.1.0 — Linux x86_64

First public MIT-licensed release of the **offline, conservative credential
export consolidation** Rust CLI. The GitHub repository is named
`bw-password-dedup`, but the package and executable are
`bw-passport-dedup` for historical reasons.

## Highlights
- Import user-exported Bitwarden/Vaultwarden individual-vault JSON, and Edge,
  Chrome/Chromium, Firefox, and Apple Passwords CSV.
- Detect only safe identical credentials by default; do not silently overwrite
  differing passwords, TOTP secrets or incompatible metadata.
- Optional safe field/URI union, authenticated human conflict review, redacted
  reports, offline dry-run, and static Vaultwarden JSON validation.
- Export consolidated JSON for Vaultwarden and separately produce provider-
  attributed browser CSV snapshots compatible with independent Passflick.
- Bound source reads and output handling, use private 0600 files, maintain
  conservative force backups and a warning marker for interrupted output bundles.

## Asset and verification
The archive `bw-passport-dedup-v0.1.0-linux-x86_64.tar.gz` contains the optimized
Linux x86_64 executable, LICENSE, README, CHANGELOG, and the offline recovery
runbook. Compare it with the accompanying `SHA256SUMS.txt`.
The release job prints its exact Rust toolchain and runs formatting, Clippy,
locked tests, optimized build and a synthetic fish smoke before publishing.

## Safety and scope
**This is a local command-line migration utility, not a password manager or
unattended synchronization service. It has not processed a real user's vault.**
The owner ran a synthetic-only smoke successfully on EndeavourOS; a disposable
Vaultwarden import/export and actual pinned Passflick consumer integration
also passed in isolated CI. These do not certify success with all real exports.

Passwords in generated JSON/CSV and private backup files are **plaintext**.
Store them only in a trusted private directory; never commit, email or share
them. Never delete originals until a full independently checked migration.
**Do not blindly retry** a Vaultwarden import (duplicates may result). Read
`docs/migration-recovery.md` before any migration attempt.
Cross-file transactions are not crash/power-loss atomic; malicious same-user
writers and memory/swap zeroization are outside the current guarantees.

MIT applies to the original project code; bundled Rust dependencies maintain
their own license obligations. External GPL Bitwarden CLI and independent
Passflick executable are **not included in the release archive**.

Documentation: https://github.com/sguzman/bw-password-dedup
