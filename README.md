# bw-passport-dedup

`bw-passport-dedup` currently groups Bitwarden JSON export items using configurable comparison keys. **It is experimental and must not be used to destructively clean real credential collections yet.**

## Intent

Evolve this existing Rust CLI into a safe, offline consolidation and deduplication workflow for browser and Bitwarden exports, with conservative conflict handling and verified Vaultwarden/Passflick outputs.

## Ambition

The current implementation is a narrow Bitwarden-JSON maintenance utility. The [roadmap](ROADMAP.md) specifies the expanded import, preservation, review and verification work; Passflick and Vaultwarden retain separate responsibilities.

See [the full project roadmap](ROADMAP.md) for milestones, acceptance criteria, security work, source formats and verified progress.

## Current Status

The existing CLI has an implemented but **unverified** deduplication path. Known safety defects include case-insensitive secret matching under the checked-in configuration, discard-on-duplicate behavior, and secret-bearing JSON reports. Use only synthetic test data until the roadmap's safety and QA gates pass.

## Core Capabilities Or Focus Areas

- Read Bitwarden JSON exports.
- Normalize records by removing unstable fields.
- Hash records for duplicate detection.
- Apply configurable duplicate rules.
- Write a cleaned export for re-import.

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
cargo run -- input.json --config config.toml
```

## Notes, Limitations, Or Known Gaps

- Because this project rewrites vault exports, the practical workflow should always include keeping the original export untouched.
- Duplicate semantics are policy-driven rather than universal.

## Next Steps Or Roadmap Hints

- Keep the duplicate policy explicit and reviewable as new Bitwarden export shapes appear.
- Add more fixtures if you want stronger confidence across export variants.
