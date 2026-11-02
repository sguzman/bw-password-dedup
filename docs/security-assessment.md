# Security and resilience assessment — in progress

**Scope:** Review of the Rust CLI and its Linux synthetic acceptance fixtures through the 2026-11-02 development checkpoint. This is a concrete engineering audit log, **not** an independent security audit, a certification, or permission to import live credentials. M7-03 remains unverified until the remaining risks are assessed and tested.

## Verified controls and their evidence

| Control | Implementation or evidence | Residual limitation |
| --- | --- | --- |
| Prevent changes to original exports | Source paths are compared against destinations; the JSON and browser-CSV readers reject symlinks and verify the opened descriptor matches the initially inspected device/inode; CI checks original file bytes remain unchanged | The input can still be modified in place by another process while reading; operate on an immutable private snapshot |
| Refuse accidental overwrites | Existing outputs fail by default; new outputs use private temporary files and a hard-link no-clobber installation | This does not make multiple files a single crash-atomic transaction |
| Explicit force-replacement recovery | Replacement creates a private backup and uses rename; the opened backup source and pre-replacement pathname are compared against the original device/inode, with synthetic interruption and substitution tests | These additional checks narrow—but cannot eliminate—a hostile directory-writer race between the final check and rename; operate in a private directory |
| Companion-output rollback on normal failures | `src/bundle.rs` writes the report, review manifest and source CSVs **before** primary JSON; on ordinary failed writes it removes previously created companions only if their original device/inode still matches. Forced replacement is preflighted for the last position. Simulated companion and primary failures preserve the old primary output. | A crash, kill, permission race, or error after a hard-link may still leave an incomplete set. Inspect every destination after ambiguous termination. |
| Redacted reports | Synthetic canary tests confirm usernames, domains, passwords and TOTP seeds do not appear in report data | A local file path in stderr or shell history can still reveal contextual information |
| Correct secret matching | Password and TOTP values require exact equality, including capitalization; unsafe legacy `--keep` modes fail closed | Source CSVs may omit passkeys, external authenticators or other attributes |
| Authenticated conflict replay | HMAC-SHA256 over ordered full input records and matching policy, with private 32-byte key and constant-time verification | HMAC binds the source snapshot, **not** who edited review instructions |
| Private review file safety | Review keys and manifests require regular files, strict permissions, bounded sizes and matching pre-open/post-open inode identity | A same-user malicious editor or mutable source file can still modify content; use a private directory, don't share local manifests |
| Browser provenance integrity | Passflick's browser labels are bound to actual original CSV source positions, not merely user-controlled `migration.*` fields in existing Bitwarden JSON | Vaultwarden-only accounts intentionally cannot enter browser-attributed Passflick snapshots |
| Input and format bounds | Maximum input file size, item count, review manifest size, Passflick CSV size, and static Vaultwarden item/folder limits | Many separate source arguments or unusually large nested metadata can still create memory pressure |
| Tracked-file privacy | `ci/release-privacy.sh` fails when source control tracks common credential-export, database, private-key, archive or backup file extensions | Filename checks **do not scan Git history or detect secret-like literals embedded in source text** |
| Isolated consumer acceptance | Real Vaultwarden import/export, duplicate-import detection, reversible Trash rollback and real Passflick CLI browser-snapshot import using synthetic disposable vaults | Not a real target-host deployment or proof that all future client/server versions behave identically |

## Open security work

1. **Multi-output failure semantics:** companion outputs are now published before primary JSON and cleaned up on ordinary later failures when their device/inode identities still match. The unit suite simulates both companion failure and final-primary failure and checks preservation of the old primary. However, **independent pathnames are still not one atomic transaction**. Power loss, process kill, or an I/O error *after* linking an individual pathname can require inspecting/clearing an incomplete bundle before retrying. Never import files from an uncertain or partial run. Consider an explicit final bundle receipt/manifest for production approval.
2. **Untrusted directories and filesystem races:** the JSON/CSV readers and private review reader verify opened-file identity against the initial pathname; forced-output replacement now checks the opened backup source and final pathname's inode. These protect against many substitution mistakes but cannot make an untrusted writable directory safe from concurrent pathname changes. Do not use an output folder writable by another account/process. An input file that is modified *in place* while reading can still produce an inconsistent snapshot. The `--force` check-before-rename window remains open.
3. **Memory and crash handling:** credentials are necessarily materialized as Rust `serde_json::Value` and temporary serialized buffers. No claim is made that secrets are zeroized from all allocations, kernel swap, core dumps, shell history, or backup/sync copies.
4. **Untrusted files and resource exhaustion:** each file is bounded, at most 32 browser source files are accepted, and malformed CSV/JSON is rejected. Unusually large nested metadata remains insufficiently assessed for memory pressure.
5. **Licensing and distribution:** no approved project license or source release authorization has been recorded. External Passflick, the MIT test helper and GPL Bitwarden CLI are test-time tools and must not be silently bundled into a public binary.
6. **Host acceptance:** the exact EndeavourOS/fish target-host smoke test and restoration from an existing local Vaultwarden backup have not been executed. No real credentials should be processed until owner acceptance.

## Evidence, not extrapolation

- [Synthetic Rust regression matrix](qa-regression-matrix.md) and strict CI gate in [rust.yml](../.github/workflows/rust.yml)
- [Strict CI run 41477767885](https://github.com/sguzman/bw-password-dedup/actions/runs/41477767885): 69 unit + 34 integration tests, rustfmt, Clippy and privacy gate, including output-bundle failure simulation
- [Strict CI run 41480644321](https://github.com/sguzman/bw-password-dedup/actions/runs/41480644321): 70 unit + 35 CLI integration tests, including symlinked input rejection and forced-output inode guard, plus rustfmt, Clippy, compilation and privacy gate
- [Verified isolated Vaultwarden import/rollback workflow](../.github/workflows/vaultwarden-roundtrip.yml)
- [Independent Passflick consumer workflow](../.github/workflows/passflick-consumer.yml)
- [Migration and recovery runbook](migration-recovery.md)
- [Licensing/release checklist](release-readiness.md)

**Assessment outcome:** meaningful safety controls have been verified and new filename/manifest protections added, but M7-03 is **not yet complete** because the operational and adversarial failure cases above remain open. No security audit or release claim should be inferred from passing CI alone.
