# Offline password consolidation and recovery runbook

**Status:** This is a safety-first migration rehearsal guide. Do **not** use it as permission for real production credentials until M7 security and M8 release/host acceptance pass. The synthetic CI drill exercises no-write preflight, temporary Vaultwarden import/export, duplicate-import detection and reversible Trash rollback; it never touches anyone's existing password-manager account.

## Stage 0 — Decide what remains authoritative

Keep the original password stores, all original exports and the existing Passflick encrypted vault intact. Vaultwarden is the intended long-term authoritative password store **after** verification. Passflick is a distinct local picker and consumes only source-attributed offline CSV snapshots; it is not being replaced.

Before a production migration, plan a *verified restorable backup* for Vaultwarden and, separately, an encrypted Passflick backup. Do not interpret a successful `bw sync` as a backup. Protect source files and backup encryption keys separately. Never upload passwords or review manifests to GitHub, CI, a public issue or chat.

## Stage 1 — Private preparation

For a fictional local rehearsal, create a new private directory outside Git, Dropbox and cloud sync. On Linux:

```fish
umask 077
set work "$HOME/.local/share/bw-password-dedup/rehearsal"
mkdir -p -- "$work"
chmod 700 -- "$work"
```

Only use deliberately **synthetic** Edge, Chrome, Firefox, Apple CSV exports and, optionally, a Bitwarden JSON individual-vault export while the project is unfinished. Review the source mapping in [source-mapping.md](source-mapping.md) for features that CSV cannot carry. Do not assume passkeys, external authenticator accounts or attachments appeared in these files.

## Stage 2 — Nonwriting preflight and schema check

Run a **nonwriting** dry run with the same ordered sources and merge options you intend to use. For example, in fish:

```fish
cargo run --locked -- \
  --input "$work/fictional-bitwarden.json" \
  --source "edge=$work/fictional-edge.csv" \
  --source "chrome=$work/fictional-chrome.csv" \
  --source "firefox=$work/fictional-firefox.csv" \
  --source "apple=$work/fictional-apple.csv" \
  --merge-compatible-fields \
  --output "$work/dry-run-output.json" \
  --dry-run
```

Check that no `dry-run-output.json` was created and that no source file changed. A report or review template is **not** allowed with `--dry-run` because those would write files.

Then create the synthetic consolidated JSON with the same source ordering and options, adding `--validate-vaultwarden-import` and a separate `--report` destination. The strict static validator must pass **before** attempting the isolated target import. Verify import item counts and the redacted reconciliation ledger. CSV/JSON output remains **plaintext**, despite file mode 0600.

## Stage 2b — Check that the output bundle is complete

A request can generate several secret-bearing files: consolidated JSON, a report, a review manifest and multiple Passflick browser CSVs. The CLI now publishes the **companion files first** and the primary JSON last; for an ordinary failed write, it attempts to remove any newly created companions whose file identities remain unchanged. The original inputs are never removed.

This is **not a crash-atomic multi-file transaction**. After a power loss, killed process, disk-full condition or any failure with uncertain status, inspect the full output directory and compare it with the expected destination list before using **any** output. Treat stale or unmatched CSV/report files as an incomplete batch. Do not re-run with `--force` as a shortcut around an ambiguous state. Keep the originals and any private output backup until verification succeeds.

## Stage 3 — Private unresolved conflict decisions

Create a new review key using `--init-review-key "$work/review.key"`, then generate a snapshot-bound manifest using the exact original ordered inputs and `--review-key "$work/review.key" --bound-review-template "$work/review.json"`. Inspect each position locally against its original export. Each group defaults to `defer`.

Explicit `choose-one` needs a selected input position belonging to that group; `keep-both` retains alternatives; `merge-nonsecret` refuses incompatible passwords, OTP seeds or metadata. Do not accept a manifest from another person. The key authenticates the *input snapshot*, not the human editor's intent.

Replay approved choices only with **the exact same source files, order, matching and merge policy** using `--review-key "$work/review.key" --decisions "$work/review.json"`, plus fresh distinct output/report paths. Any source edit or changed key must make decisions fail before export. Preserve the original source files throughout.

## Stage 4 — Isolated target import and verification

Use an **isolated, empty, disposable Vaultwarden instance**, not an existing household or production vault. Import the reviewed JSON once with a compatible Bitwarden client. Export it back into a private temporary location and verify:
- Record counts, unique accounts and password capitalization
- Notes, TOTP seeds, folder associations, URL match options and custom fields
- All expected source-provenance pairs on compatible merged logins
- No missing records, import warnings, or unexpected secret replacement

The integration evidence uses Vaultwarden 1.37.4 and Bitwarden CLI 2026.9.1. Versions may change behavior; retest on the intended versions. A repeat import demonstrably creates **duplicate records**, so **never blindly retry** after an import of uncertain outcome. Inspect the target state first.

Create Passflick snapshots using explicit `--passflick-export edge=...`, etc.; check each source CSV contains only records with trusted original browser CSV lineage. A Vaultwarden-only account does not belong to a browser provider. Back up the existing Passflick encrypted vault and confirm source counts before authorizing a provider snapshot replacement. The snapshot is not a live synchronization mechanism.

## Stage 5 — Rollback after a failed or ambiguous import

**Stop all further imports.** Keep original sources, snapshots, the pre-migration Vaultwarden backup and Passflick backup untouched.

Inspect the target against the recorded *pre-import inventory*. Never run a blanket delete or overwrite on an existing real vault. Determine whether a previous attempt already added records and identify only the **newly imported IDs**. For the actual household server, use its independently verified backup/restoration procedure and explicit owner approval for any removal or replacement. If the baseline cannot be reliably reconstructed, halt and report the uncertainty.

In the disposable synthetic CI vault, the runbook exercises a narrower reversible rollback drill: after proving duplicate import, identify all eight fictional imported item IDs, use the official `bw delete item ID` (without `--permanent`) to move them to Trash, sync, verify there are no active items and confirm all eight are recoverable from Trash. This **does not** establish full storage-level rollback for an existing real Vaultwarden server. Bitwarden's [official CLI documentation](https://bitwarden.com/en-gb/help/cli/) distinguishes reversible Trash deletion from irreversible `--permanent`. Never use `--permanent` as a recovery step.

Test recovery of the encrypted Passflick vault separately using Passflick's documented verify/recover process on a **disposable** vault, rather than modifying your installed picker or its saved snapshots.

## Stage 6 — Handoff and cleanup

Record the exact CLI and Vaultwarden versions, Git commit, input-count totals, reconciliation evidence, verified target counts and known missing/export-limited features. Do not store raw passwords in public logs. Keep all originals until you can independently restore both destination systems.

After successful acceptance, remove unnecessary temporary plaintext exports from local storage, understanding that `rm` does **not** guarantee secure erasure on SSDs or backed-up/synced filesystems. Prefer an encrypted working filesystem for real sensitive processing when authorized.

## CI rehearsal and limitations

- [Vaultwarden synthetic round-trip CI](../.github/workflows/vaultwarden-roundtrip.yml) and [test driver](../ci/vaultwarden-roundtrip.sh) verify the exact no-write preflight, real target import, decrypted export, repeated-import duplication and reversible rollback checks.
- [Passflick consumer CI](../.github/workflows/passflick-consumer.yml) verifies four source-labeled browser snapshots in a disposable encrypted Passflick vault, not an existing installation.
- M7-03 (adversarial security acceptance), M7-04 (final CI plus EndeavourOS host), M8-03/04 (release/licensing/packaging) remain separate acceptance gates.

**This document is not authorization for a production migration or public release.**
