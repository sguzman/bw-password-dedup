# bw-passport-dedup

`bw-passport-dedup` currently groups Bitwarden JSON export items using configurable comparison keys. **It is experimental and must not be used to destructively clean real credential collections yet.**

## Intent

Evolve this existing Rust CLI into a safe, offline consolidation and deduplication workflow for browser and Bitwarden exports, with conservative conflict handling and verified Vaultwarden/Passflick outputs.

## Ambition

The current implementation is a narrow Bitwarden-JSON maintenance utility. The [roadmap](ROADMAP.md) specifies the expanded import, preservation, review and verification work; Passflick and Vaultwarden retain separate responsibilities.

See [the full project roadmap](ROADMAP.md) for milestones, acceptance criteria, security work, source formats and verified progress.

## Current Status

The existing CLI has an implemented but **unverified** deduplication path. Security fixes are now committed to preserve case-sensitive secrets, keep nonidentical records, redact reports, and write private outputs with backups. **The Rust build and tests have not yet been observed passing**, so use only synthetic test data until the roadmap's security and QA gates pass.

## Core Capabilities Or Focus Areas

- Read Bitwarden JSON exports.
- Group potential matches by configurable normalized identity fields without normalizing password or TOTP secret values.
- Preserve every nonidentical record; remove only byte-for-byte identical login records.
- Reject legacy destructive keep strategies pending explicit conflict review.
- Write a private local export (mode 0600 on Linux), keeping a backup before intentional overwrite, and optionally a redacted duplicate summary.

## Project Layout

- `src/`: Rust source for the main crate or application entrypoint.
- `Cargo.toml`: crate or workspace manifest and the first place to check for package structure.

## Setup And Requirements

- Rust toolchain.
- A Bitwarden JSON export to process.
- A reviewed duplicate policy in `config.toml` or an alternative config file.

## Build / Run / Test Commands

```bash
cargo build
cargo test
cargo run -- --input input.json --config config.toml
```

## Notes, Limitations, Or Known Gaps

- Because this project rewrites vault exports, the practical workflow should always include keeping the original export untouched.
- Duplicate semantics are policy-driven rather than universal.

## Next Steps Or Roadmap Hints

- Keep the duplicate policy explicit and reviewable as new Bitwarden export shapes appear.
- Add more fixtures if you want stronger confidence across export variants.
