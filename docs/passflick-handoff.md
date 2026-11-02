# Passflick offline consumption — source-preserving CSVs

**Status:** A synthetic, offline CSV projection exists. This is not a live Passflick synchronization service, and the target CLI smoke check must pass before M6-02 is credited.

Passflick is an existing **local password picker**, not a password manager to retire. Its current CLI accepts `passflick import edge|chrome|firefox|apple FILE`, replacing one provider's encrypted snapshot at a time. The deduplicator therefore **never** labels the entire consolidated vault as "Edge" or any other browser. It generates provider-specific CSVs only for login items containing complete `migration.source` and `migration.record` provenance pairs created by the original provider imports.

## Synthetic demonstration

```sh
cargo run --locked -- \
  --source edge=./synthetic-edge.csv \
  --source chrome=./synthetic-chrome.csv \
  --output ./synthetic-merged.json \
  --passflick-export edge=./synthetic-passflick-edge.csv \
  --passflick-export chrome=./synthetic-passflick-chrome.csv
```

Both CSVs use Passflick's currently supported `name,url,username,password` headers. Each original URI produces a separate CSV record. The exporter preserves the exact username and password strings and refuses embedded NULs, malformed login attributes, ambiguous provenance, missing destination source data, duplicate provider exports and source/output path collisions. Source records without passwords are counted as skipped. It enforces Passflick's 32 MiB and 100,000-record input bounds.

The generated file permissions are `0600`, but **CSV files are still plaintext**. Do not save them in Git, online storage, or a public directory. Remove them after independently verifying the encrypted snapshot import.

## What does and does not move

The projection carries:

- The login's title, each login URI, the exact username, and the exact password.
- The original **browser source**, inferred only from complete, ordered provenance pairs. A field-merged record attributed to both Edge and Chrome may legitimately appear in both source-specific snapshots.
- Multiple conflicting passwords for the same account as distinct rows; Passflick's own picker can show alternatives.

It **does not** carry notes, TOTP secrets, attachments, passkeys, identities, cards, organizations, folder metadata, or original creation timestamps. Those data remain in the separate consolidated JSON and original exports. Unattributed Vaultwarden-only records are **never** silently assigned to a browser source; they are excluded from the browser-specific handoff. If an entire requested source has no usable attributed login, the operation fails without writing any output.

Passflick imports replace the selected provider's existing encrypted snapshot. Do **not** use these experimental files against an existing real Passflick vault without first verifying the full handoff and backups. Its `--allow-shrink` option intentionally bypasses normal source-shrink safeguards and should not be used casually. This is an offline snapshot, not real-time browser/Vaultwarden synchronization.

## Isolated consumer acceptance

The independent CI smoke job checks out a **pinned Passflick commit** and exercises its actual local CLI against synthetic CSVs created by the deduplicator. It creates a temporary private Passflick vault, imports the Edge and Chrome projections, then verifies both fictional user accounts are present without revealing passwords in the list. No real passwords, local user keyrings, or existing Passflick vaults are accessed.

Only a passing run of that job establishes this pinned consumer's compatibility. Any future Passflick source schema changes require a fresh smoke check.

## Remaining architecture question

The current Passflick schema has no independent "consolidated Vaultwarden snapshot" provider. If the goal later includes **Vaultwarden-only accounts**, a dedicated source adapter in Passflick (or another explicitly selected local consumer interface) will be required. The deduplicator must not misattribute such credentials to Edge/Chrome/Firefox/Apple to work around the missing provider category. An adapter would be a separate change to Passflick, not part of this repository's implicit scope.
