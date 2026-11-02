# Offline conflict review

The review CLI supports a legacy read-only inventory and a new **authenticated, local, snapshot-bound decision workflow**. Neither workflow modifies browser stores or original exported files. Use synthetic exports until isolated Vaultwarden and Passflick acceptance (M6–M8) is complete.

## 1. Make a private review key

On the local Linux machine, create a key once:

```sh
cargo run --locked -- --init-review-key ./review.key
```

The command creates a new cryptographically random 32-byte key with file mode `0600`, refusing an existing file. Keep this file outside Git, public cloud sync, shared folders and plaintext password export locations. If the key is lost, old decisions cannot be replayed; a new key requires generating fresh manifests.

## 2. Create a snapshot-bound review manifest

With fictional test data:

```sh
cargo run --locked -- \
  --source edge=./fictional-edge.csv \
  --source firefox=./fictional-firefox.csv \
  --output ./preview.json \
  --review-key ./review.key \
  --bound-review-template ./decisions.json
```

The private `0600` JSON file identifies each conflicting group by the input-relative positions of its candidates and includes fixed source labels and conflict flags. It does **not** include site names, usernames, passwords, TOTP secrets, notes or any ordinary unsalted hash of the input credentials. The `snapshot_mac` is an HMAC-SHA256 value computed with the separate private key over the ordered, full canonical source records, vault metadata, input/source specifications, matching policy and merge flags. It is not a password.

## 3. Review and explicitly edit choices

Open the private `decisions.json` locally while consulting your original local exports. Each group defaults to `"decision": "defer"` with `"selected_input_position": null`.

Allowed decisions are:
- `defer`: retain unresolved alternatives.
- `keep-both`: explicitly retain all alternatives.
- `choose-one`: retain exactly one choice in the cleaned output; set `selected_input_position` to a record position **within that group**. Excluded records remain in the untouched original exports and are accounted for separately in the audit.
- `merge-nonsecret`: request a lossless union of compatible URIs, notes and custom fields. It refuses any conflicting passwords, TOTP, ownership, titles or other nonmergeable data.

Only `choose-one` permits a nonnull selected position. Unknown actions, unknown manifest fields, malformed references and contradictory choices are rejected. If automatic deduplication already coalesced a record in a way that makes a choice ambiguous, the program refuses that destructive choice.

The key authenticates the **source snapshot**, not a user's edits to the decision file. The editable file remains user-controlled. Protect it with local file permissions and do not accept decision manifests from untrusted people or software.

## 4. Apply decisions using exactly the same source snapshots

```sh
cargo run --locked -- \
  --source edge=./fictional-edge.csv \
  --source firefox=./fictional-firefox.csv \
  --review-key ./review.key \
  --decisions ./decisions.json \
  --output ./reviewed.json \
  --report ./review-audit.json
```

Source order, source contents, config, selected policies and merge flags must match the original review exactly. Reordered exports, changed password/TOTP values, added or removed accounts, wrong key, changed policy, tampered group references, bad file permissions and stale schema cause failure **before any output is written**. Identical inputs and the same reviewed decisions produce identical cleaned JSON output.

The report is redacted. Its `review_decisions` events show fixed action labels and input-relative positions, and its `reconciliation` accounts for retained, automatically merged, explicitly merged and explicitly excluded inputs. Every original input position must be accounted for exactly once. No original credential exports are modified.

## Legacy inventory-only option

`--review-template ./review-inventory.json` still writes the version-1, **non-executable** private inventory. It does not authorize decisions and cannot be used with `--decisions` in lieu of the snapshot-bound version.

## Safety limits

All review and output files must occupy distinct paths. Existing destinations are not silently overwritten; `--force` only applies to the cleaned output and preserves a private backup. Dry-run prevents writes and is incompatible with report or template generation.

**No actual production migration, Vaultwarden import or Passflick consumption has yet been accepted.** Never upload real credentials, manifests or keys to GitHub issues, CI, chat, or public storage. Keep source files and existing password stores until the whole migration and restoration process is verified.
