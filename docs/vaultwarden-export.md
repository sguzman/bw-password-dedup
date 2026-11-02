# Vaultwarden/Bitwarden JSON import and round-trip acceptance

**Status: Real isolated synthetic integration passed for Vaultwarden 1.37.4 and native GPL Bitwarden CLI 2026.9.1.** This is scoped acceptance for the tested fixture, not a production security audit or a guarantee about future server/client versions. No real credentials were processed.

## Import target and static preflight

Bitwarden's [documented custom JSON import](https://bitwarden.com/help/condition-bitwarden-import/) supports individual-vault items with types 1 (login), 2 (secure note), 3 (card) and 4 (identity). The deduplicator preserves source metadata by default, even when an unknown record cannot be imported; it never silently drops unsupported items to manufacture an import-compatible file.

To validate the documented individual-vault import schema using only synthetic data:

```sh
cargo run --locked -- --input ./synthetic-export.json \
  --output ./synthetic-validated.json \
  --validate-vaultwarden-import
```

The validator checks plaintext JSON, item-specific objects, folder references, organization/collection exclusions, custom fields, URI shapes and the documented import-size limits of 7,000 items and 2,000 folders. Unsupported or malformed output fails before any output file is written. This flag alone makes no network request; it remains a **static** check.

## M6-01: real isolated Vaultwarden round-trip test

The separate [Vaultwarden integration workflow](../.github/workflows/vaultwarden-roundtrip.yml) uses:
- Pinned `vaultwarden/server:1.37.4` in a **throwaway Docker container bound only to 127.0.0.1**, with temporary data directory and locally generated HTTPS certificate
- Pinned official GPL Bitwarden native CLI `bw-oss-linux-2026.9.1.zip`, with its published SHA-256 verified before extraction
- Pinned MIT-licensed external bootstrap crypto helper, used **only for a fictional test account**, with an explicit PKCS#1 → PKCS#8 RSA private-key conversion needed for the client's decryption
- A private, isolated CLI app-data directory and synthetic credentials; no account, server, files, keys, or environment from the user's computer
- No npm, no Vaultwarden admin token, and no runtime service exposed outside the GitHub runner

The [test script](../ci/vaultwarden-roundtrip.sh) generates an individual-vault JSON from a Bitwarden synthetic secure note/folder plus Edge, Chrome and Apple CSV files. Compatible Edge/Chrome records are deliberately merged with `--merge-compatible-fields`, retaining **two ordered migration provenance pairs**.

It then uses the real `bw import bitwardenjson`, `bw sync`, and decrypted `bw export --format json` operations against Vaultwarden and checks:
1. The two synthetic logins and the secure note round-trip, with the folder reference still connected to the returned folder.
2. Case-sensitive login passwords, Apple OTPAuth/TOTP, a login note, URLs and custom-field values survive import.
3. **Both Edge and Chrome `migration.source` custom-field entries survive** in the same merged record, alongside the Apple entry in its separate record.
4. The initial import yields three items; importing the identical JSON again results in **six items**, confirming imports are **not idempotent**.
5. Every operation is against a temporary synthetic test account. The container, private data directory and temporary CLI binaries are destroyed after the run.

**Passing verification:** [GitHub Actions run 41471203907](https://github.com/sguzman/bw-password-dedup/actions/runs/41471203907), code commit `5dab856542d5f47845c8112c39394c063619338f`, Vaultwarden 1.37.4 with CLI 2026.9.1. Earlier compatible two-login tests also passed on [run 41470392223](https://github.com/sguzman/bw-password-dedup/actions/runs/41470392223) with CLI 2026.7.0.

## Limits and required safeguards

This acceptance is scoped to the fixture and tested pinned versions, not every possible custom-field type, unusual URI matching rule, organization feature, passkey, attachment, SSH key or future Bitwarden schema. The following data may be absent from the original input and cannot be recreated: passkeys, attachments, external authenticator accounts, Apple device-only items, and changes made after export.

**Reimporting the same file duplicates records.** Before attempting a real migration, use the separate M7/M8 verification and recovery steps, back up the current Vaultwarden state, isolate and inspect the target vault, and confirm the exact expected count and record contents. Never automatically reimport after an uncertain failure. Do not delete any originals until acceptance is complete.

The standalone redacted `--report` counts source contributions and flags unsupported data, but does not display the password, username, notes or URL. Real users' source exports, temporary CSV/JSON files, review keys and decrypted vault exports are secret-bearing even when Linux file permissions are `0600`.

The separate [Passflick source-preserving handoff](passflick-handoff.md) has its own isolated real-CLI test. Vaultwarden-only credentials cannot yet be consumed by Passflick's existing browser-source importer without a separately approved adapter.

**Still outstanding:** M7 adversarial security assessment, full five-source integrated acceptance across both consumers, local EndeavourOS host verification, rollback runbook execution and final release hygiene. Do not treat this project as production-ready yet.
