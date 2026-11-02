# bw-passport-dedup

A local-first Rust CLI for conservatively consolidating password-manager exports **without modifying the source stores**. Repository: [sguzman/bw-password-dedup](https://github.com/sguzman/bw-password-dedup). The Cargo package and executable are named `bw-passport-dedup` for historical reasons; the repository is named `bw-password-dedup`.

**Development status: 92% verified against scoped tests.** The ingestion, conservative merging, explicit review, source-attributed Passflick consumer, and an actual **synthetic Vaultwarden 1.37.4 / Bitwarden CLI 2026.9.1 JSON import/export round trip** passed isolated Linux CI. Full five-source target acceptance and a disposable Vaultwarden rollback drill have passed. Adversarial security assessment, EndeavourOS host checks, production restoration proof and release packaging remain unfinished. **Do not use real credential collections for a production migration or delete existing password stores yet.** See [ROADMAP.md](ROADMAP.md).

## Current capabilities

- Ingests plaintext **Bitwarden/Vaultwarden individual-vault JSON** and named **Edge, Chrome/Chromium, Firefox and Apple Passwords CSV** snapshots, either separately or together.
- Retains source provenance, provider-specific extra CSV fields, Apple notes and OTPAuth/TOTP seeds where they are present in the input.
- Deduplicates only literally identical login records by default. Different password capitalization, TOTP values, notes or metadata are never silently resolved.
- Opt-in `--merge-compatible-uris` unions URLs only when all other fields match; `--merge-compatible-fields` additionally unions provably nonconflicting notes, source provenance, custom fields and URIs.
- Produces **redacted** account-candidate reports and a reconciliation ledger accounting for every original input position.
- Offers a private, HMAC-SHA256 authenticated, snapshot-bound review workflow: `defer`, `keep-both`, explicit `choose-one`, or compatible `merge-nonsecret`. Reordered/edited source snapshots, wrong keys, invalid selections or changed policies are rejected without an export.
- `--validate-vaultwarden-import` statically checks supported Bitwarden individual-vault JSON item types and limits. This **does not** perform a real Vaultwarden import.
- `--passflick-export KIND=FILE` produces private, **source-attributed** CSV files compatible with Passflick's existing browser source imports. The actual Passflick CLI passed an isolated synthetic consumer test.
- Enforces bounded input, no-clobber defaults, safe source/output path separation, private `0600` export files, and a private backup before any forced output replacement. Output directories must not be shared-writable; unsafe writable ancestors and explicit symlinked directory paths fail closed. Linux no-follow/nonblocking source opens reject late symlink/FIFO substitutions; forced backups reject observed in-place changes, refuse originals above 1 GiB, bound copying of growing files, and sync the backup's directory entry before replacing the original. Before reporting success, the CLI also checks published output file identity, private permissions, expected byte counts and SHA-256 content (including a final bundle-wide recheck). A private, synced `.<output-name>.bw-dedup.incomplete` marker is created before publication; it blocks another run at input preflight (before parsing credential bytes) if an earlier export was interrupted, and is removed after a verified successful bundle. Inspect all outputs and private backups before clearing a marker. **Neither the presence nor the absence of the marker alone proves a crash-atomic transaction.**

## Build and test

Rust stable supporting edition 2024 is required:

```sh
cargo build --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

The CLI reads only explicitly supplied local files and has no network dependency. Development tests use fictional records. The separate [Passflick consumer integration](.github/workflows/passflick-consumer.yml) builds a pinned Passflick commit in CI; its isolated encrypted test vault is unrelated to any user's Passflick data.

## Synthetic CLI examples

To inspect supported files without writing anything:

```sh
cargo run --locked -- \
  --source edge=./fictional-edge.csv \
  --source firefox=./fictional-firefox.csv \
  --dry-run
```

To create a test JSON export, redacted report, and provider-preserving Passflick CSV in a private working directory:

```sh
cargo run --locked -- \
  --source edge=./fictional-edge.csv \
  --source firefox=./fictional-firefox.csv \
  --output ./fictional-merged.json \
  --report ./fictional-report.json \
  --passflick-export edge=./fictional-passflick-edge.csv \
  --passflick-export firefox=./fictional-passflick-firefox.csv \
  --validate-vaultwarden-import
```

Use `--input FILE` for an optional plaintext Bitwarden/Vaultwarden JSON source. When `--input` is supplied, the default output name adds `.dedup.json`; otherwise it is `consolidated.json`. Existing destinations are refused unless `--force` is explicitly used on the primary output, in which case a private backup is kept. `--report` and review template options cannot be combined with `--dry-run`.

For explicit conflict choices, first generate a private review key with `--init-review-key ./review.key`, then use `--review-key ./review.key --bound-review-template ./decisions.json` with the **same input options**. Edit only the local, private manifest to select an allowed decision; replay using `--review-key ./review.key --decisions ./decisions.json`. See the [review workflow](docs/review-workflow.md) for complete commands and protections. The older `--review-template` produces a **non-executable** inventory.

## What is not verified or available

- **Vaultwarden:** A pinned isolated Vaultwarden 1.37.4 + GPL Bitwarden CLI 2026.9.1 integration test confirmed round-trip for a synthetic secure note/folder, login URLs, TOTP, notes and **two migration-source field pairs** on one merged login. This does not certify all item types or future versions. **Reimporting the same file was proven to create duplicate entries.**
- **Passflick:** Its current import API accepts only Edge, Chrome, Firefox or Apple snapshots. Source-attributed rows can be consumed offline, but **Vaultwarden-only accounts cannot be passed as a new consolidated source without a separately approved Passflick adapter**. This project does not modify Passflick's encrypted vault or promise live synchronization.
- **Unexportable data:** Passkeys, file attachments, some Apple device credentials, Google Authenticator accounts not present in exports, and changes made after the snapshot cannot be inferred or recovered from CSV.
- **Security and production acceptance:** Real credentials, local target-host installation, full attack-surface review, and release/rollback validation are outstanding. File mode `0600` is **not encryption**; CSV/JSON exports and review key files must never be committed to Git or shared through chat.

## Documentation and evidence

- [Verified weighted roadmap](ROADMAP.md)
- [Source mapping and export limitations](docs/source-mapping.md)
- [Conservative merge semantics](docs/merge-review.md)
- [Authenticated review workflow](docs/review-workflow.md)
- [Review decision safety contract](docs/decision-contract.md)
- [Vaultwarden JSON preflight and verified isolated import/export](docs/vaultwarden-export.md)
- [Passflick source-preserving handoff](docs/passflick-handoff.md)
- [Synthetic regression matrix](docs/qa-regression-matrix.md)
- [Offline migration and reversible recovery runbook](docs/migration-recovery.md)
- [Evidence-based security assessment and open risks](docs/security-assessment.md)
- [License and pre-release checklist](docs/release-readiness.md)
- [Core Rust CI](.github/workflows/rust.yml) and [isolated Passflick consumer CI](.github/workflows/passflick-consumer.yml)

**Most recent scoped evidence:** five-source Vaultwarden [import/export](https://github.com/sguzman/bw-password-dedup/actions/runs/41472026629), four-browser actual Passflick [consumer](https://github.com/sguzman/bw-password-dedup/actions/runs/41472122315), reversible disposable Vaultwarden [rollback](https://github.com/sguzman/bw-password-dedup/actions/runs/41473875734), and strict Rust regression [CI](https://github.com/sguzman/bw-password-dedup/actions/runs/41474089784). Trusted browser-source provenance, private review file identity checks, the 32-file source limit, and the tracked-private-file privacy gate passed [strict Rust CI (98 tests)](https://github.com/sguzman/bw-password-dedup/actions/runs/41475608499). Full security/release acceptance is still pending.

Vaultwarden remains the intended authoritative store after eventual acceptance. **Passflick remains an independent local password picker**, not a component being replaced.
