# Security and resilience assessment — in progress

**Scope:** Review of the Rust CLI and its Linux synthetic acceptance fixtures through the 2026-11-02 development checkpoint. This is a concrete engineering audit log, **not** an independent security audit, a certification, or permission to import live credentials. M7-03 remains unverified until the remaining risks are assessed and tested.

## Verified controls and their evidence

| Control | Implementation or evidence | Residual limitation |
| --- | --- | --- |
| Prevent changes to original exports | Source paths are compared against destinations, original files are read-only inputs, and CI checks that their bytes remain unchanged | Does not protect browser data or backups outside the tool |
| Refuse accidental overwrites | Existing outputs fail by default; new outputs use private temporary files and a hard-link no-clobber installation | A set of output files is **not committed transactionally**; late disk errors can leave an incomplete bundle |
| Explicit force-replacement recovery | Replacement creates a private backup and uses rename, with synthetic simulated-interruption tests | A hostile process with write access to the output directory may race pathname checks; operate in a user-owned private directory |
| Redacted reports | Synthetic canary tests confirm usernames, domains, passwords and TOTP seeds do not appear in report data | A local file path in stderr or shell history can still reveal contextual information |
| Correct secret matching | Password and TOTP values require exact equality, including capitalization; unsafe legacy `--keep` modes fail closed | Source CSVs may omit passkeys, external authenticators or other attributes |
| Authenticated conflict replay | HMAC-SHA256 over ordered full input records and matching policy, with private 32-byte key and constant-time verification | HMAC binds the source snapshot, **not** who edited review instructions |
| Private review file safety | Review keys and manifests require regular files, strict permissions, bounded sizes and matching pre-open/post-open inode identity | A same-user malicious editor or mutable source file can still modify content; use a private directory, don't share local manifests |
| Browser provenance integrity | Passflick's browser labels are bound to actual original CSV source positions, not merely user-controlled `migration.*` fields in existing Bitwarden JSON | Vaultwarden-only accounts intentionally cannot enter browser-attributed Passflick snapshots |
| Input and format bounds | Maximum input file size, item count, review manifest size, Passflick CSV size, and static Vaultwarden item/folder limits | Many separate source arguments or unusually large nested metadata can still create memory pressure |
| Tracked-file privacy | `ci/release-privacy.sh` fails when source control tracks common credential-export, database, private-key, archive or backup file extensions | Filename checks **do not scan Git history or detect secret-like literals embedded in source text** |
| Isolated consumer acceptance | Real Vaultwarden import/export, duplicate-import detection, reversible Trash rollback and real Passflick CLI browser-snapshot import using synthetic disposable vaults | Not a real target-host deployment or proof that all future client/server versions behave identically |

## Open security work

1. **Multi-output failure semantics:** validate preflight prevents known path collisions, but separate cleaned JSON, report, review manifest and Passflick CSV writes are not a single atomic transaction. After a late I/O failure, discard the incomplete output bundle, preserve the originals and backups, and rerun only after checking existing destinations. A robust all-or-nothing publication strategy or explicit manifest/cleanup protocol should be evaluated before production use.
2. **Untrusted directories and filesystem races:** no-clobber output creation is atomic for a single new file; `--force` still follows a sequence of pathname checks and operations. Running in a directory writable by another process or user is not within the accepted security model. The private review reader now confirms opened-file device/inode identity and permissions, but every input/output path must be assessed under the same threat model before release.
3. **Memory and crash handling:** credentials are necessarily materialized as Rust `serde_json::Value` and temporary serialized buffers. No claim is made that secrets are zeroized from all allocations, kernel swap, core dumps, shell history, or backup/sync copies.
4. **Untrusted files and resource exhaustion:** each file is bounded and malformed CSV/JSON is rejected. Very many separate files and unexpectedly large metadata are not yet proven safe against adversarial memory pressure.
5. **Licensing and distribution:** no approved project license or source release authorization has been recorded. External Passflick, the MIT test helper and GPL Bitwarden CLI are test-time tools and must not be silently bundled into a public binary.
6. **Host acceptance:** the exact EndeavourOS/fish target-host smoke test and restoration from an existing local Vaultwarden backup have not been executed. No real credentials should be processed until owner acceptance.

## Evidence, not extrapolation

- [Synthetic Rust regression matrix](qa-regression-matrix.md) and strict CI gate in [rust.yml](../.github/workflows/rust.yml)
- [Verified isolated Vaultwarden import/rollback workflow](../.github/workflows/vaultwarden-roundtrip.yml)
- [Independent Passflick consumer workflow](../.github/workflows/passflick-consumer.yml)
- [Migration and recovery runbook](migration-recovery.md)
- [Licensing/release checklist](release-readiness.md)

**Assessment outcome:** meaningful safety controls have been verified and new filename/manifest protections added, but M7-03 is **not yet complete** because the operational and adversarial failure cases above remain open. No security audit or release claim should be inferred from passing CI alone.
