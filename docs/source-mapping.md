# Export field mapping and preservation contract

This document describes the **currently implemented** local ingestion and its limitations. It does not establish compatibility with a real Vaultwarden import, which is a later acceptance gate.

## Source mapping

| Source | Accepted input | Direct login fields | Other source fields |
| --- | --- | --- | --- |
| Edge | Explicit CSV with `name,url,username,password` | Name, URI, username, password | Additional columns retained as `source.edge.<original-header>` text custom fields |
| Chrome/Chromium | Explicit CSV with `name,url,username,password` | Name, URI, username, password | Additional columns retained as `source.chrome.<original-header>` custom fields |
| Firefox | Explicit CSV with `url,username,password` and at least one recognizable Firefox metadata header | URI, username, password | `httpRealm`, `formActionOrigin`, `guid`, timestamps, and other columns retained as `source.firefox.<original-header>` custom fields |
| Apple Passwords/Safari | Explicit CSV with `Title,URL,Username,Password` | Name, URI, username, password | `Notes` (or `Note`) mapped to item notes, `OTPAuth` mapped verbatim to `login.totp`; other columns retained as custom fields |
| Bitwarden/Vaultwarden | Plaintext individual-vault JSON with `items`, optional `folders` | Original JSON item objects retained | Folders, custom fields, notes, TOTP, and unknown properties retained in the original JSON values |

The exact source CSV headers are normalized only for recognition (ASCII case and leading/trailing header whitespace); **field values are not lowercased or trimmed**. Duplicate normalized headers, missing required headers, malformed CSV and incompatible source signatures fail closed. Edge and Chrome often have indistinguishable header formats: provider attribution is supplied by the CLI argument rather than verified cryptographically.

## Canonical record

The Rust `CanonicalRecord` holds the **complete original JSON item** plus a typed classification (`Login`, `SecureNote`, `Card`, `Identity`, `Unknown`, or `Malformed`) and optional import provenance. All unknown and future JSON fields remain in the raw item. CSV records are materialized as Bitwarden-like login items without deleting source-specific data.

Each imported CSV row receives custom fields:
- `migration.source`: one of the explicitly supplied source names
- `migration.record`: 1-based record ordinal in that CSV, **not** a physical file line number

Any unrecognized CSV columns are retained as ordinary custom text fields with a `source.<provider>.` prefix. The original header spelling is kept. This aids auditability but may result in extra fields in the final vault; pruning or converting them requires a reviewed future mapping decision. Source-specific values may contain secrets and must never be logged.

## Unsupported or unavailable information

A source export is not proof that it contains all account information from its original manager. The following categories must be audited manually and are **not claimed as migrated**:

- Passkeys, including source-local passkeys that ordinary password CSV formats omit
- File attachments and other binary resources not contained in a Bitwarden JSON export
- Data excluded by Apple or browser exporters (for example certain device-specific secrets or service credentials)
- Google Authenticator accounts not supplied through these supported CSV/JSON export formats
- Live browser password changes made after the export snapshot
- Permissions, collections, organizational ownership, or sharing semantics not represented in an individual-vault export

These are **source limitations**, not secretly discarded fields. Where input actually supplies an unfamiliar column, the tool retains its value as an opaque custom field instead of guessing its meaning. The tool must surface a machine-readable unsupported-feature checklist before final real-data acceptance (M6-03).

## Conservative matching rules

- Password and TOTP secret values are exact, case-sensitive and never normalized.
- Full original objects must be byte-for-byte equivalent in represented JSON value to qualify for automatic removal in the current stage; different metadata or provenance keeps entries distinct.
- Unknown/non-login types pass through without automatic merging.
- Web-origin matching is conservative: scheme, subdomain, and non-default port remain distinct. Ambiguous, internationalized, or non-web identifiers retain their original string rather than being guessed at.
- Report files contain counts and fixed structural labels, not secrets. They do not provide interactive conflict resolution yet.
- No original export or source store is modified by these operations.

## Acceptance gates still outstanding

M3 must provide final canonical ordering and account-field semantics; M4/M5 must develop conservative cross-source field union and conflict review; M6 must prove real Bitwarden/Vaultwarden import and Passflick consumption. Every unmapped category must be either safely preserved or explicitly enumerated before approving a production migration.
