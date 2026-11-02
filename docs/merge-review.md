# M4 account candidates and conservative URI unions

**Status:** Partial M4 implementation. No general automatic credential merger and no reviewed conflict-resolution workflow yet.

## Read-only candidate discovery

When `--report report.json` is supplied, the tool reports candidate accounts with:
- identical, nonempty username (matched exactly and case-sensitively)
- one unambiguous web origin per login (all login URLs must resolve to one scheme/host/port)
- two or more candidate records from the source batch

The comparison preserves distinctions between HTTP/HTTPS, subdomains, nondefault ports, and different usernames. Ambiguous URLs, app identifiers and records with multiple distinct web origins are excluded from automatic candidate grouping, not discarded.

`account_groups` contains **only** counts, conflict flags, fixed labels, and references to source positions. `input_position` is a 1-based position in the concatenated input batch **before cleanup**, not a permanent ID. `provider` is a fixed allowlisted name or `unlabeled`, and `source_record` is the original CSV row ordinal if available. These references change when inputs are reordered. Group identities (origin/username), passwords, notes, TOTP secrets, and custom-field values are never included in the report.

Password conflicts and TOTP conflicts are flagged independently, including different capitalization. Each group has `decision: unresolved-preserve-all`. **No decision is automatically made**, and all distinct entries remain present for the later conflict-review workflow. A report contains enough context to locate candidates in the original batch, not enough to disclose the accounts' identities.

## Optional exact-metadata URI union

`--merge-compatible-uris` is an **explicit opt-in**, separate from the baseline exact-record deduplication.

A union is allowed only when the items:
- are both well-formed login entries and have exactly the same web origin and username
- have **identical remaining JSON data**, including passwords, TOTP, notes, field arrays, source provenance, item title, folder/organization scope, custom fields, password history, timestamps, and all unknown data
- differ only in the `login.uris` array
- do not specify the same URL with conflicting URI match metadata

The program then retains the **complete union** of the original URL objects. It does not choose newer or older passwords. It doesn't merge records with different notes or provenance. Existing names and fields are preserved because they must be identical. A separate report count, `compatible_uri_merges`, records this conservative operation.

This intentionally means that two otherwise-identical accounts imported from different browsers often remain distinct: their `migration.source` fields differ. That's correct for now; lossless provenance reconciliation and metadata union are M4-02 and M5 work.

Example with fictional test data:

```sh
cargo run --locked -- --input synthetic-bitwarden.json \
  --output output.json --report report.json --merge-compatible-uris
```

`--dry-run` prevents all file writes; `--report` is intentionally disallowed with dry-run, so test with temporary synthetic inputs first.

## Opt-in nonconflicting field union (verified synthetically)

`--merge-compatible-fields` is a separate **opt-in** intended to reconcile metadata that can be combined without choosing a winner. It requires the same unambiguous web origin and exact username, and it compares all fields except `login.uris`, `fields`, and `notes` for equality. That means passwords, OTP seeds, name, favorite status, IDs, folder/organization ownership, timestamps, and opaque future fields must already match. The rules then:

- Union URI objects while refusing conflicting match options for the same URL.
- Retain every distinct custom-field object; refuse two different values under the same ordinary custom-field name.
- Retain separate `migration.source` + `migration.record` provenance pairs in original order. These duplicate field names still require actual Vaultwarden import/round-trip verification in M6.
- Allow one nonempty note to fill an empty, missing, or null note; refuse two different nonempty notes.
- Preserve explicit `fields: null` when both input items contain null, and refuse mismatched null-versus-missing field representations.

Conflicting favorites, item names, organizations, unrecognized properties and password histories are **not** silently reconciled. The source references and exact field-merge counts are included in the redacted reconciliation ledger. The operation is **not enabled by default**.

## Verification and next steps

All five M4 tasks passed their scoped synthetic checks. The private reconciliation ledger tracks **every original source position** across automatic identical-record removal and compatible URI/field unions, with fixed reason codes for each merge. Inconsistent input-to-output accounting aborts export.

These synthetic results do **not** certify production readiness. In particular, repeatable user decisions and stale-input rejection belong to M5; actual import compatibility for combined provenance fields and independent Passflick consumption belong to M6; complete migration and security acceptance belong to M7/M8. See [the review inventory](review-workflow.md) and [the decision safety contract](decision-contract.md).

Do not run a real password migration or delete original password stores until M5–M8 acceptance and recovery checks are complete.
