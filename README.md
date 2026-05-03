# bw-passport-dedup

`bw-passport-dedup` deduplicates Bitwarden JSON exports by hashing normalized items after removing volatile fields.

## Intent

Create a safe cleanup pass for password-vault exports so duplicate items can be removed deterministically before re-import.

## Ambition

The project appears intentionally narrow: a focused maintenance utility that favors deterministic cleanup rules and transparent configuration over broad vault-management scope.

## Current Status

The repo is a compact single-binary CLI with a checked-in config file and usage-oriented documentation. It looks substantially complete for its current scope.

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
