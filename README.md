# bw-passport-dedup

A local Rust CLI for conservatively consolidating password-manager exports without modifying the original stores. The repository is [sguzman/bw-password-dedup](https://github.com/sguzman/bw-password-dedup); the existing Cargo executable name is `bw-passport-dedup`.

**Development status:** M1–M3 have passed synthetic Linux CI. M4 candidate matching, unresolved conflict reporting, and an opt-in URI-only union are now implemented; broader lossless metadata merging and reviewed conflict resolution remain unfinished. Vaultwarden/Passflick compatibility is not yet verified. **Do not use the current release to migrate or delete your only copy of real credentials.** Track the full scope in the [roadmap](ROADMAP.md).

## What it currently does

- Reads **plaintext Bitwarden/Vaultwarden JSON** and exported **Edge, Chrome/Chromium, Firefox, and Apple Passwords CSV** files.
- Accepts multiple named browser sources in one invocation, optionally alongside a Bitwarden JSON export.
- Preserves import provenance, provider-specific CSV columns, Apple notes and OTPAuth values in the mapped items.
- Rejects malformed provider headers, duplicate source files, encrypted Bitwarden JSON, oversized files, and unsafe legacy record-selection modes.
- By default removes only byte-for-byte identical login items; preserves nonidentical entries and treats password and TOTP values as case-sensitive.
- Reports same-origin/same-username account candidates, flags conflicting credentials, and provides position-based references without exposing account identities.
- Offers **opt-in** `--merge-compatible-uris` to union different URLs only when all other credential and metadata fields match exactly.
- Supports a read-only dry run, redacted summary reports, and private `0600` export files with backed-up forced replacement.
- Passes a synthetic end-to-end CLI test suite on Linux; see [CI](.github/workflows/rust.yml).

It is **not** yet a smart account merger. The same login imported from two browsers may remain twice because provenance and other fields differ; the upcoming merge/review stages will address that safely.

## Build and test

Rust stable with the edition-2024 toolchain is required.

```sh
cargo build --locked
cargo test --locked
```

No external service, browser database access, or Vaultwarden instance is required for the CLI. The tool only reads files you explicitly supply.

## Example commands

Run using synthetic or otherwise non-sensitive test exports while the remaining security and migration milestones are unfinished.

```sh
cargo run --locked -- --input fictional-bitwarden.json --dry-run

cargo run --locked -- \
  --source edge=./edge.csv \
  --source chrome=./chrome.csv \
  --source firefox=./firefox.csv \
  --source apple=./apple.csv \
  --output ./consolidated.json \
  --dry-run
```

For an intentional test export, remove `--dry-run`. To write a sanitized count-only report, add `--report ./report.json` (report writing is intentionally incompatible with `--dry-run`). Existing exports cannot be overwritten without `--force`; a separate private backup is saved before forced replacement.

The source argument is `--source KIND=FILE`, repeatable for the four named browser providers. `--input FILE` supplies optional Bitwarden/Vaultwarden JSON. An output defaults to `<input>.dedup.json` when JSON is provided, otherwise `consolidated.json`.

## Important limitations

- **CSV and plaintext JSON exports are unencrypted.** File mode `0600` restricts Linux permissions but does not encrypt their contents. Keep exports out of Git and synced folders, and do not upload real credentials to issues, CI, or chat.
- CSV source identity is supplied by the user. Edge and Chrome share similar export headers, so the tool cannot independently prove which browser exported the file.
- Source-specific metadata is preserved as custom fields where it has no direct Bitwarden mapping. Full downstream import compatibility and field-level fidelity still require testing.
- Passwords/TOTP are preserved when present in supported exports. Some passkeys, attachments, Wi-Fi accounts, and other data may **not** be exportable at all; do not assume they were migrated.
- The tool does not currently migrate Google Authenticator directly, synchronize with browsers, change Vaultwarden server state, or manage Passflick's vault.
- Automatic conflict resolution is deliberately unavailable. Keep both original exports and the original password stores until the whole migration has been verified.

## Project documentation

- [Roadmap and verified progress](ROADMAP.md)
- [Source field mapping, provenance, and export limitations](docs/source-mapping.md)
- [Conservative URI union and redacted account-review semantics](docs/merge-review.md)
- [CI build, test, format, and lint checks](.github/workflows/rust.yml)

The Rust code is local-first and intentionally non-networked. Vaultwarden is the future authoritative password store; Passflick remains a distinct local password picker and intended consumer of cleaned snapshots.
