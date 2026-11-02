# Synthetic regression matrix — M7-01

**Status:** The core unit and CLI regression fixtures below passed in strict Linux CI. They test the deduplicator itself, not a real password migration, independent security audit, or Vaultwarden server import.

The assertions describe unsafe behavior that would cause a regression test to fail; they are not claims that every historical version was actually executed and observed to fail. Fixtures contain only fictional credentials.

| Risk or historical unsafe behavior | Focused regression coverage | Expected invariant |
| --- | --- | --- |
| Case-insensitive or policy-driven password/TOTP collapsing | `secret_case_is_never_normalized`, `secret_equality_cannot_be_disabled_by_policy`, `full_record_matching_does_not_lowercase_secrets` | Differently capitalized secrets always remain distinct |
| Old `--keep last/newest/oldest` choosing an arbitrary account | `destructive_keep_mode_fails_closed` | Unsafe implicit choices are rejected, with no output |
| Different notes, custom fields or provenance discarded by deduplication | `preserve_distinct_metadata_and_2fa`, `field_conflicts_never_trigger_automatic_selection`, `field_union_keeps_both_provenance_pairs_and_reconciles` | Only explicitly compatible fields union, and every source contribution is recorded |
| Scheme, subdomain, port or ambiguous URI collision | `safe_origin_matching_preserves_ports_subdomains_and_schemes`, `ambiguous_uris_are_never_broadly_normalized`, `incompatible_uri_match_metadata_is_not_collapsed` | Ambiguous or different web origins and matching policies remain separate |
| Cards, notes, identities or future types dropped | `typed_bitwarden_items_and_folders_roundtrip_unchanged`, `unknown_item_type_does_not_deduplicate`, `unrecognized_items_and_organization_scopes_are_preserved_in_audit` | Type-specific and unknown records remain byte-equivalent JSON values |
| Overwrites, input aliases, interrupted writes or stale reports | `original_input_cannot_be_overwritten`, `rejects_output_alias_of_original_input`, `interrupted_force_replacement_preserves_old_data`, `existing_report_aborts_before_creating_export` | Original files and existing destinations survive rejected writes |
| Source export ambiguity, malformed fields, excessive input | `malformed_csv_and_ambiguous_headers_fail_closed`, `bad_provider_export_prevents_partial_consolidation`, `bounded_input_rejects_sparse_oversize_file` | Import fails before clean output appears |
| Unsafe replay of stale decisions or altered secrets | `sealed_decisions_reject_changed_sources_or_wrong_key_without_writes`, `changing_totp_or_manifest_schema_fails_without_export`, `bound_review_rejects_reordered_sources_changed_policy_and_tampered_groups` | Authenticated source binding and exact group membership required before decisions execute |
| Secret values or URLs leaked to reports | `redacted_report_never_contains_secrets`, `merge_audit_reconciles_chained_merges_without_leaking_secrets`, `five_source_fixture_preserves_case_secrets_totp_and_consumer_provenance` | Redacted audit contains count/position labels, not site names, passwords, TOTP seeds, or usernames |
| Browser source misattribution and Passflick-incompatible data | `passflick_projection_filters_by_provenance_and_retains_distinct_passwords`, `passflick_projection_refuses_empty_or_duplicate_browser_destinations_without_writes`, `five_source_fixture_preserves_case_secrets_totp_and_consumer_provenance` | Only correctly attributed provider snapshots are projected; Vaultwarden-only items stay separate |
| Unsupported target import limits and item kinds | `unsupported_vaultwarden_item_fails_validation_without_losing_source`, `import_limits_are_stricter_than_general_source_limits` | Explicit import-format preflight refuses oversized/unsupported items, while normal lossless output retains originals |

## Composite five-source fixture

`five_source_fixture_preserves_case_secrets_totp_and_consumer_provenance` combines:
- Bitwarden JSON containing a login and a secure note
- Edge, Chrome, Firefox and Apple CSV snapshots
- Distinct case-sensitive passwords for the same origin/username
- Apple OTPAuth and notes data
- Redacted reconciliation and a strict static Bitwarden JSON format check
- Passflick exports for Edge and Apple, without misattributing the Bitwarden-only login
- Assertions that every source file remains unchanged

The composite test proves **file-level input/output preservation**, not success against a live Vaultwarden server. Separate consumer smoke tests at [Passflick CI run 41466926259](https://github.com/sguzman/bw-password-dedup/actions/runs/41466926259) use Passflick's actual CLI but only fictional source-attributed credentials.

## Verification

Strict rustfmt, Clippy (`-D warnings`), compilation and all tests passed on [GitHub Actions run 41468033489](https://github.com/sguzman/bw-password-dedup/actions/runs/41468033489): **62 unit + 30 integration tests**. This meets the scoped synthetic regression-fixture gate M7-01, but not M7-02/M7-03/M7-04.

## Outstanding acceptance

- Actual isolated Vaultwarden import/export comparison, especially duplicate migration-source custom fields and item/folder/TOTP preservation
- Full adversarial security review of file replacement, filesystem races, failure atomicity and secret retention in memory
- EndeavourOS target-host CLI acceptance, documented rollback and production release validation
- A deliberate Passflick adapter if unified Vaultwarden-only account coverage becomes required

Never substitute these synthetic fixtures for verification using supported tools against an isolated vault.
