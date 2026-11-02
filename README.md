# bw-passport-dedup

A local-first Rust CLI for conservatively consolidating password-manager exports **without modifying the source stores**. Repository: [sguzman/bw-password-dedup](https://github.com/sguzman/bw-password-dedup). The Cargo package and executable are named `bw-passport-dedup` for historical reasons; the repository is named `bw-password-dedup`.

**Development status: 88% verified against scoped tests.** The ingestion, conservative merging, explicit review, source-attributed Passflick consumer, and an actual **synthetic Vaultwarden 1.37.4 / Bitwarden CLI 2026.9.1 JSON import/export round trip** passed isolated Linux CI. Comprehensive adversarial QA, full five-source target acceptance, EndeavourOS host checks, recovery runbook and release packaging remain unfinished. **Do not use real credential collections for a production migration or delete existing password stores yet.** See [ROADMAP.md](ROADMAP.md).

## Current capabilities

- Ingests plaintext **Bitwarden/Vaultwarden individual-vault JSON** and named **Edge, Chrome/Chromium, Firefox and Apple Passwords CSV** snapshots, either separately or together.
- Retains source provenance, provider-specific extra CSV fields, Apple notes and OTPAuth/TOTP seeds where they are present in the input.
- Deduplicates only literally identical login records by default. Different password capitalization, TOTP values, notes or metadata are never silently resolved.
- Opt-in `--merge-compatible-uris` unions URLs only when all other fields match; `--merge-compatible-fields` additionally unions provably nonconflicting notes, source provenance, custom fields and URIs.
- Produces **redacted** account-candidate reports and a reconciliation ledger accounting for every original input position.
- Offers a private, HMAC-SHA256 authenticated, snapshot-bound review workflow: `defer`, `keep-both`, explicit `choose-one`, or compatible `merge-nonsecret`. Reordered/edited source snapshots, wrong keys, invalid selections or changed policies are rejected without an export.
- `--validate-vaultwarden-import` statically checks supported Bitwarden individual-vault JSON item types and limits. This **does not** perform a real Vaultwarden import.
- `--passflick-export KIND=FILE` produces private, **source-attributed** CSV files compatible with Passflick's existing browser source imports. The actual Passflick CLI passed an isolated synthetic consumer test.
- Enforces bounded input, no-clobber defaults, safe source/output path separation, private `0600` export files, and a private backup before any forced output replacement.

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
- [Core Rust CI](.github/workflows/rust.yml) and [isolated Passflick consumer CI](.github/workflows/passflick-consumer.yml)

**Most recent scoped evidence:** 62 unit + 31 integration tests in [core CI](https://github.com/sguzman/bw-password-dedup/actions/runs/41471585810); the real Passflick CLI consumed fictional Edge and Chrome projections in [consumer CI](https://github.com/sguzman/bw-password-dedup/actions/runs/41466926259); a disposable Vaultwarden server imported and re-exported synthetic merged JSON, notes, TOTP, folder and provenance in [Vaultwarden CI](https://github.com/sguzman/bw-password-dedup/actions/runs/41471203907).

Vaultwarden remains the intended authoritative store after eventual acceptance. **Passflick remains an independent local password picker**, not a component being replaced.
