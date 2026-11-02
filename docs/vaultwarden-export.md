# Vaultwarden/Bitwarden JSON export preflight

**Status:** Static schema checks implemented, actual isolated Vaultwarden import **not yet verified**. No real credentials have been processed.

## Supported target format

Bitwarden's official [custom JSON import format](https://bitwarden.com/help/condition-bitwarden-import/) documents an individual-vault `items` array with item types 1 (login), 2 (secure note), 3 (card), and 4 (identity), each containing the corresponding `login`, `secureNote`, `card`, or `identity` object. The optional `folders` array can describe destination folders. JSON field names are case sensitive.

The CLI's standard output remains a conservative representation of all input data, even when fields and types are not known to be importable. **Nothing is silently dropped to satisfy the importer.**

To request a strict, opt-in individual-vault schema preflight with synthetic exports:

```sh
cargo run --locked -- --input ./synthetic-export.json \
  --output ./synthetic-validated.json \
  --validate-vaultwarden-import
```

The validation checks:
- Plaintext JSON (`encrypted` absent or `false`) with typed items and known type-specific objects
- Nonempty item names, fields and URI data with documented JSON shapes
- Any supplied folders, duplicate folder IDs and unresolved folder references
- Organization ownership and collection structures that cannot be safely treated as an individual-vault import
- Unknown item types, rather than dropping future record types

Unsupported or malformed output **fails before writing**; the original source remains untouched. The flag performs *no* server calls and does not prove actual import behavior. A normal export without this opt-in validation continues preserving unknown fields/types and can therefore be incompatible with the target importer.

## Known missing export coverage

The tool cannot recreate information that the original source files omitted. Independently check:

- Passkeys and other device-only credentials omitted from ordinary CSV exports
- Binary attachments, organization permissions, Sends and data excluded from individual-vault exports
- External authenticator accounts or TOTP seeds not included in the exported input
- Wi-Fi accounts and Sign in with Apple credentials absent from Apple password CSV
- New passwords or revisions made after the source export snapshot

The redacted `--report` includes fixed `unavailable_data_notice` entries and a count-based `reconciliation` ledger. Source-specific field mappings are in [source-mapping.md](source-mapping.md). The static validator cannot infer whether a missing credential exists in the original browser, so it does not misreport unavailable data as successfully imported.

## Acceptance still needed (M6-01, M6-02)

1. Import a fully synthetic valid JSON file to an **isolated** Vaultwarden instance, then export it back and compare every supported field, including folder references, notes, TOTP, URI match rules and custom fields.
2. Specifically determine whether duplicate `migration.source`/`migration.record` custom-field names are retained by the actual importer; do not assume the target preserves array multiplicity.
3. Verify Passflick's existing local CSV importer against an appropriate consolidated snapshot without rewriting the provenance as an unrelated browser, and without modifying the Passflick project unless separately authorized.
4. Test migration rollback and detect re-import duplicates before any real-data use.

The real password stores and the original exported files are never modified by this static preflight.
