# Synthetic regression matrix — M7-01

**Status:** Core synthetic regression tests and isolated real-consumer integration tests have passed. These are disposable Vaultwarden and Passflick test instances, not a real user migration or independent security audit.

The assertions describe unsafe behavior that would cause a regression test to fail; they are not claims that every historical version was actually executed and observed to fail. Fixtures contain only fictional credentials.

| Risk or historical unsafe behavior | Focused regression coverage | Expected invariant |
| --- | --- | --- |
| Case-insensitive or policy-driven password/TOTP collapsing | `secret_case_is_never_normalized`, `secret_equality_cannot_be_disabled_by_policy`, `full_record_matching_does_not_lowercase_secrets` | Differently capitalized secrets always remain distinct |
| Old `--keep last/newest/oldest` choosing an arbitrary account | `destructive_keep_mode_fails_closed` | Unsafe implicit choices are rejected, with no output |
| Different notes, custom fields or provenance discarded by deduplication | `preserve_distinct_metadata_and_2fa`, `field_conflicts_never_trigger_automatic_selection`, `field_union_keeps_both_provenance_pairs_and_reconciles` | Only explicitly compatible fields union, and every source contribution is recorded |
| Scheme, subdomain, port or ambiguous URI collision | `safe_origin_matching_preserves_ports_subdomains_and_schemes`, `ambiguous_uris_are_never_broadly_normalized`, `incompatible_uri_match_metadata_is_not_collapsed` | Ambiguous or different web origins and matching policies remain separate |
| Cards, notes, identities or future types dropped | `typed_bitwarden_items_and_folders_roundtrip_unchanged`, `unknown_item_type_does_not_deduplicate`, `unrecognized_items_and_organization_scopes_are_preserved_in_audit` | Type-specific and unknown records remain byte-equivalent JSON values |
| Overwrites, input aliases, interrupted writes or stale reports | `original_input_cannot_be_overwritten`, `rejects_output_alias_of_original_input`, `interrupted_force_replacement_preserves_old_data`, `existing_report_aborts_before_creating_export` | Original files and existing destinations survive rejected writes |
| Pre-open symlink/FIFO substitution of a checked source or forced backup; in-place mutation during backup | `preopen_symlink_swap_is_rejected_without_reading_target`, `preopen_fifo_swap_fails_without_blocking`, `forced_backup_rejects_in_place_change_after_copy`, `forced_backup_rejects_preopen_symlink_swap_without_reading_victim` | Reject unsafe pathname substitutions before blocking or following symlinks; reject changed backup sources without replacing the old output |
| Interrupted export, stale marker or marker-name collision | `incomplete_marker_survives_interrupted_bundle_and_blocks_retry`, `verified_bundle_clears_write_ahead_marker`, `marker_collision_with_output_fails_without_writes`, `stale_incomplete_marker_blocks_cli_publication_until_inspected`, `real_sigkill_leaves_recovery_marker_and_partial_companion`, `real_sigkill_after_forced_primary_preserves_backup_and_marker`, `incomplete_marker_refuses_processing_before_malformed_source_parsing` | Fsync a private incomplete warning before writing outputs; reject stale markers without side effects, never claim a cross-file transaction, clear marker after verified publication |
| Published bundle file corruption, post-primary companion mutation or permissions changes | `silent_companion_corruption_cannot_claim_success_or_publish_primary`, `late_companion_mutation_after_primary_publication_revokes_bundle`, `changed_companion_permissions_cannot_claim_private_bundle` | No successful publication status for content or permission mismatch; clean only newly published outputs retaining original inode ownership |
| Source export ambiguity, malformed fields, excessive input | `malformed_csv_and_ambiguous_headers_fail_closed`, `bad_provider_export_prevents_partial_consolidation`, `bounded_input_rejects_sparse_oversize_file` | Import fails before clean output appears |
| Unsafe replay of stale decisions or altered secrets | `sealed_decisions_reject_changed_sources_or_wrong_key_without_writes`, `changing_totp_or_manifest_schema_fails_without_export`, `bound_review_rejects_reordered_sources_changed_policy_and_tampered_groups` | Authenticated source binding and exact group membership required before decisions execute |
| Secret values or URLs leaked to reports | `redacted_report_never_contains_secrets`, `merge_audit_reconciles_chained_merges_without_leaking_secrets`, `five_source_fixture_preserves_case_secrets_totp_and_consumer_provenance` | Redacted audit contains count/position labels, not site names, passwords, TOTP seeds, or usernames |
| Browser source misattribution and Passflick-incompatible data | `passflick_projection_filters_by_provenance_and_retains_distinct_passwords`, `passflick_projection_refuses_empty_or_duplicate_browser_destinations_without_writes`, `five_source_fixture_preserves_case_secrets_totp_and_consumer_provenance` | Only correctly attributed provider snapshots are projected; Vaultwarden-only items stay separate |
| Private review key/manifest mutation, pathname swaps, late file growth or interrupted key initialization | `review_key_changed_in_place_after_read_is_rejected`, `manifest_replaced_after_read_is_rejected`, `oversized_private_manifest_is_rejected_before_parsing`, `failed_review_key_initialization_cleans_up_owned_partial_file`, `failed_review_key_initialization_preserves_replacement_file` | Reject changed private files after bounded reads; clean owned partial keys on error, never unlink a replaced pathname or execute an unstable manifest |
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

## M7-02: isolated five-source consumer acceptance

- **Vaultwarden:** [Run 41472026629](https://github.com/sguzman/bw-password-dedup/actions/runs/41472026629), commit `3867a8f3d3f3eb68b8df37bc29a2eaa97c5afb9e`, passed against disposable Docker Vaultwarden **1.37.4** and official native GPL Bitwarden CLI **2026.9.1**. This uses **Bitwarden JSON (secure note/folder) + Edge + Chrome + Firefox + Apple CSV**, with Edge/Chrome compatible login field union. The real decrypted import/export round trip checked item count, folder link, login secrets, Apple TOTP/notes, Firefox URI and provenance, and two ordered Edge/Chrome migration-source custom fields. Re-importing the same file created duplicate entries (four to eight).
- **Passflick:** [Run 41472122315](https://github.com/sguzman/bw-password-dedup/actions/runs/41472122315), commit `ff6b34edfa16dc17d21787489f5a2f27191c86df`, passed with pinned Passflick commit `7fd71fde7c4debb1683d8d2a2e2fb28f8ca41712`. A combined **Bitwarden JSON + Edge + Chrome + Firefox + Apple** synthetic batch produced source-attributed CSV snapshots for four browsers; a repeated run generated byte-identical JSON and CSV outputs. The actual independent Passflick CLI imported all four browser snapshots into an isolated encrypted test vault and listed all four fictional usernames without disclosing passwords. **Vaultwarden-only records remained in consolidated JSON and were intentionally excluded from browser-labeled Passflick imports**; this is an explicit existing-consumer limitation, not missing migration data.
- **Core CI:** [Run 41472122200](https://github.com/sguzman/bw-password-dedup/actions/runs/41472122200) passed formatting, Clippy, compilation, and all synthetic Rust tests.

Together, these independently verified M7-02's *scoped* five-source-to-both-consumers acceptance; tests do not show an automatic continuous synchronization service or real production migration. No user's password files, Passflick vault, or Vaultwarden instance were accessed.

## Outstanding acceptance

- Full adversarial security review of residual same-user filesystem races, cross-output crash atomicity and secret retention in memory (private review-file mutation controls passed in [strict CI run 41498508202](https://github.com/sguzman/bw-password-dedup/actions/runs/41498508202))
- EndeavourOS target-host CLI acceptance, documented rollback and production release validation
- A deliberate Passflick adapter if unified Vaultwarden-only account coverage becomes required

Never substitute these synthetic fixtures for verification using supported tools against an isolated vault.
