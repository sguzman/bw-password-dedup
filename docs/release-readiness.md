# v0.1.0 release and licensing readiness

**Status:** Owner approved the MIT license and public v0.1.0 release on **2026-11-02**. Final publication requires a passing version-specific CI/test/privacy gate. Cargo package and binary: `bw-passport-dedup` v0.1.0 (Rust 2024); repository: `sguzman/bw-password-dedup` (historical naming difference). This approval applies only to v0.1.0; do not treat it as blanket consent for future releases or production migrations.

## License approval and redistribution boundaries

The repository's original Rust source is now MIT-licensed under [LICENSE](../LICENSE), with owner approval on **2026-11-02**. `Cargo.toml` declares `license = "MIT"`; copyright notice covers the repository contributors. Third-party dependencies remain subject to their **own** licenses, which are not replaced by this project's MIT grant. External Passflick, MIT bootstrap helper, and GPL Bitwarden CLI are test-time dependencies and must not be bundled into the distributed standalone executable as separate binaries.

Publication approval is scoped to the **public v0.1.0 Linux x86_64 release** with its verified source tag, checksum and documented limitations. It does not authorize handling private credentials or changing original password stores.

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
- [x] **EndeavourOS host test:** owner reported successful `cargo +stable build --release --locked` (18.26 s, optimized) and `fish scripts/synthetic-host-smoke.fish` (`PASS: Synthetic local CLI smoke with private output and unchanged source.`) at **2026-11-02 14:45 America/Mexico_City**. See [host acceptance evidence](host-acceptance.md). The precise rustc stable patch version and compiled binary checksum were not supplied; do not invent them.
- [x] **Licensing decision:** MIT approved by owner on 2026-11-02; root `LICENSE`, Cargo metadata and changelog match v0.1.0.
- [x] **Owner acceptance (scoped):** owner accepted the synthetic-only working CLI and approved public release; CI has verified counts, review choices, Vaultwarden duplicate-import behavior, and source-attributed Passflick snapshots. Real account inventories, live Vaultwarden backups and user secrets remain **untested** and need independent cautious validation before any real migration.
- [x] **Explicit approval:** owner authorized public v0.1.0 release/tag on 2026-11-02. The release job must **still** pass clean candidate checks, build its archive, and publish SHA-256 checksums before this release is considered complete.

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

It exercises CLI help, strict JSON export validation, private output permissions and unchanged source bytes using one fictional credential inside a temporary directory. CI verified the helper through fish inside an official Arch Linux container on [run 41482415116](https://github.com/sguzman/bw-password-dedup/actions/runs/41482415116). **The owner also ran it successfully on their actual EndeavourOS workstation on 2026-11-02.** It does not import into Vaultwarden or modify Passflick.

The package name is `bw-passport-dedup`, not the repository name. The binary does not require a Vaultwarden server at runtime to generate JSON; networked integration tests are a separate CI workflow. A local package or checksum is evidence only when the commands run successfully on the exact candidate commit. Never put real credentials in CI.

The [official Arch Linux and fish smoke workflow](../.github/workflows/archlinux-smoke.yml) uses an ephemeral container on a GitHub runner; it does not run commands on the user's Arch workstation. Its `pacman` invocation is confined to that disposable container. Owner-run actual EndeavourOS synthetic smoke is independently reported as passed; this does not prove full real-vault acceptance.

The [optimized release-build smoke workflow](../.github/workflows/release-smoke.yml) intentionally does not create release assets or tags. An **independently gated, version-specific v0.1.0 publication workflow** will build and publish the approved binary with a checksum; it is not a future recurring auto-release pipeline. A successful Ubuntu CI runner also does not substitute for an EndeavourOS host test.

## Public privacy review

Before publishing, review the **entire proposed archive**, Git tag contents and history for accidental plaintext exports, private keys, review manifests, vault backups and sensitive reports. A clean `.gitignore` or filename-based gate does not prove earlier commits or code strings contain no credentials. The existing CI uses fictional examples only, and reports from actual migrations must remain local and private.

**Known limitations:** The consolidated JSON may contain vault-only items that Passflick's browser-source API cannot consume; Passflick remains independent. CSV cannot recover absent passkeys, attachments or external authenticator accounts. Secret-bearing output remains plaintext unless separately encrypted by the user. The system is not certified for production credential migration.
