# M5 decision safety contract (design, not yet executable)

**Status:** Unimplemented design for M5-02 and M5-03. This is a non-executable specification; `--review-template` v1 remains inventory-only.

## Why source positions are insufficient

A simple decision such as “choose input #17” would become dangerous after re-exporting, adding an item, sorting browser exports, or changing input order. Positions in the current review report are deliberately **snapshot-relative**, not persistent identifiers.

The next implementation must refuse any decision generated for another snapshot. An unknown or altered decision must not silently choose a password.

## Explicit decision vocabulary

For each review group with a stable, checked snapshot reference:

- `defer`: keep all alternatives. This is the default.
- `keep-both`: intentionally retain all listed candidates as separate entries.
- `choose-one`: explicitly select a candidate **in the verified input snapshot**; do not silently delete the original exports. The reconciliation ledger must distinguish user-selected exclusion from automatic identical-record merging.
- `merge-nonsecret`: permitted only when password and TOTP values are exact and all incompatible metadata is either explicitly retained or the operation refuses to proceed. It must not guess current passwords by timestamp.

The CLI must never accept implicit `choose-one` defaults, arbitrary free-text action names, or partially matched groups.

## Snapshot binding and key management

An executable decision format needs a **cryptographically authenticated snapshot binding** covering:

1. The ordered list of source kinds and input file identities.
2. The full canonical typed source records in input order (including sensitive fields, but never serializing them to a log or manifest).
3. All deduplication and matching policy options that can change group membership.
4. The template's schema version and candidate reference set.

Use a keyed MAC with a random key stored **separately** from the manifest in a user-controlled private local file (mode `0600`). Do **not** publish an ordinary unsalted SHA hash of secret-bearing vault exports as a review identifier: it may enable offline guessing. Never serialize the MAC key, passwords or TOTP secrets to reports. For first-time use, fail closed if a key cannot be generated or securely persisted. A missing or changed key means old decision manifests cannot be replayed automatically.

Do not implement this by reading user credential files in a remote service, using GitHub Actions on real exports, or forwarding files to a chat.

## Replay validation

Before applying *any* decision:

- Load source files once into a bounded in-memory snapshot.
- Recompute and verify the keyed binding in constant time.
- Confirm all referenced input indices, group membership and candidate counts still match.
- Validate that a candidate belongs to exactly one group, and reject duplicate or contradictory instructions.
- Reject unsupported actions or source types, stale schema, unknown fields that change meaning, and truncated/modified manifests.
- Preserve unresolved alternatives, record explicit decisions in a **private** reconciliation ledger, and never overwrite original source exports.

Every failed validation must leave output and review files unmodified. A failed operation must not log account identities or secret values.

## Verification needed

Synthetic tests must demonstrate refusal after each of: input-file edit, changed password, changed TOTP, changed source order, insertion/deletion, changed matching policy, manipulated group references, modified MAC, replaced key, conflicting decisions, missing key and manifest permission changes. Replaying identical source snapshots and approved decisions must produce equivalent outputs. The final output must still be tested against an isolated Vaultwarden import and local Passflick consumer under M6.

**Do not claim M5-02/M5-03 complete from this document.** The current v1 review template cannot execute decisions or promise replay safety.
