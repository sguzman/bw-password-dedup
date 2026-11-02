# Private conflict-review inventory (M5)

The CLI can now write a private, **non-executable** conflict-review template. This is only the first stage of the review workflow. It cannot approve, reject, choose, or overwrite any credentials.

## How to generate a fictional test review

```sh
cargo run --locked -- \
  --source edge=./fictional-edge.csv \
  --source firefox=./fictional-firefox.csv \
  --output ./fictional-clean.json \
  --review-template ./fictional-review.json
```

`--review-template PATH` can be combined with `--report PATH`, provided each output has a unique path. It creates a new file with private Linux mode `0600`, refuses existing outputs, and is incompatible with `--dry-run`. Destination aliases to input, output, and report files are rejected before processing.

The template includes only:

- `schema_version` and the fixed `kind: review-template-not-executable`
- total input record count and unresolved account groups
- fixed conflict flags for passwords, TOTP, and other metadata
- 1-based input positions, allowlisted provider labels, and source record ordinals
- `decision: defer` for all groups and an explicit warning

It **never contains** account names, URLs, usernames, passwords, TOTP secrets, notes, raw custom field values, or secret-derived hashes. Open the original *local* exported data to review records by position; don't upload real exports to chat or GitHub.

## Critical warning: no replay or approvals yet

Input positions are **relative to the current concatenated batch**. Reordering sources, changing a file, or adding a login can change the meaning of a position. Therefore **the version-1 template has no executable decision semantics**.

M5-02 must add explicit, safe choose/keep-both/defer behavior with stale-snapshot rejection, and M5-03 must establish repeatable decisions before the program will apply user choices from any file. Until then, all conflicting candidates are preserved; the template is an offline review inventory only.

Vaultwarden and Passflick integration are separate M6 acceptance gates. Do not migrate or delete real password stores using this unfinished tool.
