# Changelog

All significant release changes are summarized here; the project's historical
development and verification evidence remains in [ROADMAP.md](ROADMAP.md).

## [0.1.0] - 2026-11-02

Initial public Linux x86_64 CLI release (Cargo executable `bw-passport-dedup`,
repository `bw-password-dedup`).

### Added
- Conservative offline consolidation of Bitwarden/Vaultwarden individual-vault
  JSON plus Apple, Firefox, Edge and Chrome CSV exports, preserving original sources.
- Exact-secret deduplication, opt-in compatible metadata/URI union,
  authenticated manual conflict review, source provenance and redacted reporting.
- Vaultwarden-compatible JSON export, source-attributed Passflick-compatible CSV
  projections, static Vaultwarden preflight and read-only dry runs.
- Fail-closed bounded file readers, private modes, no-clobber output, verified
  forced-replacement backups, a durable incomplete-export warning marker,
  and a private recovery runbook.
- Synthetic unit, CLI, isolated consumer, rollback, SIGKILL and Linux/fish
  smoke tests, including successful owner-run EndeavourOS synthetic host smoke.
- MIT license.

### Known limitations
- Plaintext exports are sensitive: mode 0600 is not encryption. Keep all exports,
  backups, review keys and reports in a trusted private, quiescent workspace.
- Publication of multiple outputs is not power-loss or crash atomic.
  An incomplete marker means manual inspection before retry/import; a missing
  marker is not an authenticated success certificate.
- Same-user adversarial filesystem races and RAM/swap zeroization are not solved.
- CSV cannot recover unavailable passkeys, attachments, external authenticator
  seeds or changes made after export; retain original stores.
- Bitwarden imports can create duplicates when repeated. Verify imports and
  backups manually before removing or changing existing vault data.
- Passflick is an independent browser-source consumer, not a vault replacement
  or a live synchronization feature.

See [release notes](docs/release-notes-v0.1.0.md) and
[release checklist](docs/release-readiness.md).
