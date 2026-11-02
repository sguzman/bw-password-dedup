# Release and licensing readiness (not a release authorization)

**Status:** Pre-release engineering checklist only. This repository's current Cargo package is `bw-passport-dedup`, version `0.1.0` (Rust edition 2024), while the GitHub repository is `sguzman/bw-password-dedup`. The source code and binary names deliberately differ. Do not publish a release or Git tag without the owner's separate authorization.

## Critical licensing blocker

At this checkpoint there is **no root `LICENSE` file** in this repository, and the owner has not selected or approved one in this workflow. Do **not** silently add MIT, Apache-2.0, GPL, or another license. The fact that code is visible on GitHub does not itself establish a grant of rights for redistribution.

Before any public binary/source release, resolve and explicitly document the project's license with its owner. Preserve third-party license texts and attribution when redistributing externally sourced components; the separate Passflick CLI and GPL Bitwarden CLI are only downloaded in CI integration tests, never bundled into this Rust binary. The MIT-licensed bootstrap helper is pinned exclusively as test infrastructure. Avoid claiming the standalone binary is licensed under those projects' licenses.

## Release candidate gates

- [x] **Source-verified:** synthetic Bitwarden JSON and Edge/Chrome/Firefox/Apple CSV ingestion and conservative deduplication; authenticated conflict review, count-based reconciliation, redacted reports.
- [x] **Consumer smoke tests:** temporary Vaultwarden/Bitwarden CLI import and decrypted export; separate encrypted Passflick CLI import of all four browser-attributed snapshots.
- [x] **Known duplicate-import hazard:** a second Bitwarden import creates additional entries; never blindly retry.
- [x] **Recovery rehearsal:** no-write dry-run, synthetic import and reversible Trash rollback in an empty temporary Vaultwarden instance.
- [x] **Privacy-path CI check:** tracked files cannot use typical credential-export, private-key, database or archive filenames. This is **not** a secret-scanning guarantee.
- [ ] **Full adversarial security review:** especially filesystem races, cross-output partial failures, key/manifest disclosure, malformed exports and failed-write recovery. See M7-03.
- [ ] **EndeavourOS local test:** exact stable Rust version and test invocation, completed against a private disposable directory on the target system; *no live user's credential exports needed for the test*.
- [ ] **Licensing decision:** owner-approved project license and any accompanying notices.
- [ ] **Owner acceptance:** verify expected input-to-output counts, conflict handling, Vaultwarden import differences and Passflick browser-only limitation.
- [ ] **Explicit approval:** the owner authorizes a public release/tag **after** the above gates pass.

## Safe local build (not a release)

From the repository root, on an x86_64 Linux machine with Rust installed:

```fish
cargo +stable build --release --locked
target/release/bw-passport-dedup --help
cargo +stable test --locked --all-targets
cargo +stable clippy --locked --all-targets -- -D warnings
cargo +stable fmt --all -- --check
```

The package name is `bw-passport-dedup`, not the repository name. The binary does not require a Vaultwarden server at runtime to generate JSON; networked integration tests are a separate CI workflow. A local package or checksum is evidence only when the commands run successfully on the exact candidate commit. Never put real credentials in CI.

## Public privacy review

Before publishing, review the **entire proposed archive**, Git tag contents and history for accidental plaintext exports, private keys, review manifests, vault backups and sensitive reports. A clean `.gitignore` or filename-based gate does not prove earlier commits or code strings contain no credentials. The existing CI uses fictional examples only, and reports from actual migrations must remain local and private.

**Known limitations:** The consolidated JSON may contain vault-only items that Passflick's browser-source API cannot consume; Passflick remains independent. CSV cannot recover absent passkeys, attachments or external authenticator accounts. Secret-bearing output remains plaintext unless separately encrypted by the user. The system is not certified for production credential migration.
