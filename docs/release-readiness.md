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
- [x] **Private optimized Linux smoke:** [CI run 41478125698](https://github.com/sguzman/bw-password-dedup/actions/runs/41478125698) built the x86_64 Linux `bw-passport-dedup` binary on commit `402ee8f6`, tested CLI help and one fictional validated export, checked mode 0600, and printed SHA-256 `6e7c675d8b6eedf46e29cc77418b7ff6f848d085731b3f7890dcb74c321bfac4`. This is CI evidence only, **not** a release or reproducibility proof.
- [x] **Arch Linux + fish container smoke:** [CI run 41481718365](https://github.com/sguzman/bw-password-dedup/actions/runs/41481718365), source commit `02151ed8`, passed a locked optimized Rust build inside an ephemeral official Arch Linux container, invocation through fish, strict fictional JSON export validation, and mode-0600 output checks. Optimized binary SHA-256 in that runner: `d25b5144246ecbe5a1cc6b62e3f6b21f4d41bc1b5f859396ef631c95a0bb17b1`. This is **not EndeavourOS host acceptance**, a reproducibility claim, or a distributed artifact.
- [x] **Scoped internal security/resilience assessment:** original-secret safety, fail-closed input bounds and review files, crash/backup cases, redacted reporting, and recovery-marker protections have synthetic test evidence. [Security assessment](security-assessment.md), M7-03 complete under the private/quiescent Linux workspace threat model. **Not an independent adversarial audit or proof against malicious same-user access, power-loss atomicity or memory disclosure.**
  - The forced-replacement backup now uses file + directory fsync before overwrite and a 1 GiB pre-existing output limit; this improves rollback durability but **does not** demonstrate hard-power-loss safety or allow unattended import/retry. See the [security assessment](security-assessment.md).
  - A durable incomplete-export marker now blocks blind retries after observed failure, but it is not a positive completion receipt or crash-atomic transaction. Follow [the recovery runbook](migration-recovery.md) and inspect every expected destination and private backup before clearing a stale marker.
- [x] **Engineering CI and synthetic supported-platform gates:** [strict Rust 149-test candidate](https://github.com/sguzman/bw-password-dedup/actions/runs/41512838888), [Arch Linux/fish](https://github.com/sguzman/bw-password-dedup/actions/runs/41512547169), [optimized Linux](https://github.com/sguzman/bw-password-dedup/actions/runs/41512547234), [Vaultwarden](https://github.com/sguzman/bw-password-dedup/actions/runs/41512547027) and [Passflick consumer](https://github.com/sguzman/bw-password-dedup/actions/runs/41508893774) passed at their stated commits. M7-04 credits these gates and **explicitly records** target-host smoke as outstanding; rerun the relevant checks after future code changes.
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

For a **synthetic-only** smoke check on an actual EndeavourOS machine *after* building, the repository includes:

```fish
fish scripts/synthetic-host-smoke.fish
```

It exercises CLI help, strict JSON export validation, private output permissions and unchanged source bytes using one fictional credential inside a temporary directory. CI verified the helper through fish inside an official Arch Linux container on [run 41482415116](https://github.com/sguzman/bw-password-dedup/actions/runs/41482415116). **The helper has not yet been executed on the user's actual EndeavourOS workstation.** It does not import into Vaultwarden or modify Passflick.

The package name is `bw-passport-dedup`, not the repository name. The binary does not require a Vaultwarden server at runtime to generate JSON; networked integration tests are a separate CI workflow. A local package or checksum is evidence only when the commands run successfully on the exact candidate commit. Never put real credentials in CI.

The [official Arch Linux and fish smoke workflow](../.github/workflows/archlinux-smoke.yml) uses an ephemeral container on a GitHub runner; it does not run commands on the user's Arch workstation. Its `pacman` invocation is confined to that disposable container. Local EndeavourOS smoke remains explicitly outstanding.

The [optimized release-build smoke workflow](../.github/workflows/release-smoke.yml) intentionally does not create release assets, tags or downloadable binaries. A successful Ubuntu CI runner also does not substitute for an EndeavourOS host test.

## Public privacy review

Before publishing, review the **entire proposed archive**, Git tag contents and history for accidental plaintext exports, private keys, review manifests, vault backups and sensitive reports. A clean `.gitignore` or filename-based gate does not prove earlier commits or code strings contain no credentials. The existing CI uses fictional examples only, and reports from actual migrations must remain local and private.

**Known limitations:** The consolidated JSON may contain vault-only items that Passflick's browser-source API cannot consume; Passflick remains independent. CSV cannot recover absent passkeys, attachments or external authenticator accounts. Secret-bearing output remains plaintext unless separately encrypted by the user. The system is not certified for production credential migration.
