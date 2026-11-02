# 🗺️ Password Deduplication — Project Roadmap

**Repository:** sguzman/bw-password-dedup (existing project; Cargo package currently named bw-passport-dedup)  
**Owner's objective:** Safely consolidate and deduplicate exported credentials from Edge, Chrome/Chromium, Firefox, Apple Passwords, and Bitwarden/Vaultwarden, preserving meaningful data and conflicts, then produce clean import data for Vaultwarden and a local dataset consumable by Passflick.  
**Target:** Local, offline Rust CLI on EndeavourOS/Linux; no mandatory server or hosted service.  
**Established scope:** This repository is the consolidation/cleanup utility, not a password manager or password picker. Vaultwarden remains authoritative after migration; Passflick remains a separate local consumer.  
**Status as of 2026-11-01:** Static source audit and roadmap complete; build, tests, source-format validation, integration and real-credential acceptance remain unverified.

## 🎯 Definition of done

A clean local import/export/deduplicate/review cycle must be demonstrably safe, deterministic, repeatable, and understandable. It must preserve all recognized information or produce an explicit per-field loss/unsupported-feature manifest; never silently treat different secrets as identical; never remove conflicting credentials without user review; and never publish secrets through diagnostics, logs, fixtures, or public files. The Bitwarden-compatible output must import successfully into a test vault; Passflick must be able to consume a tested local output through a documented compatibility path. Acceptance requires build, automated checks, end-to-end synthetic migration, failure-path tests, and an owner-reviewed local-data workflow. Do not claim completion based only on compilation or having a CLI command.

### 🚧 Scope boundaries

- In scope: offline exported CSV/JSON files from the five named sources; login credentials, names, URLs, notes, custom fields, folders where representable, password history and TOTP secrets when already contained in supported exports; safe treatment of cards, identities and secure notes in Bitwarden JSON; dry-run and manual conflict review; source provenance; validated outputs; secure local operation.
- In scope: migration assessment of unexported or unsupported data (for example passkeys, file attachments, some Apple items), with explicit warnings and manual follow-up instructions. Do not invent or silently discard unavailable data.
- Out of scope unless separately authorized: Vaultwarden installation/hosting or server-side automation; remote sync/Tailscale; changing the original browser stores; automatically fetching passwords from browser databases; automatic Google Authenticator QR migration or OTP enrollment; a new GUI/TUI; direct Passflick repository changes; changing repository licensing or branding; cloud credential uploads; password-strength checking or credential-breach services.
- The tool is not an unattended continuous synchronizer. Repeated imports must be deliberate, auditable, and safe. Exported vault JSON/CSV is plaintext unless encrypted explicitly by the originating format; the tool must not suggest otherwise.
- Never use real user secrets in public CI, GitHub issues, sample files, reports, screenshots, or ChatGPT attachments.

## 🔍 Evidence from repository reconnaissance

- Exists in main: single Rust binary, Cargo edition 2024, Clap CLI; Bitwarden JSON item-array parsing; selectable match policy; ordering and keep-first/last/newest/oldest; configurable normalization; a dry-run flag; JSON duplicate reports; file-output handling.
- Safety defect: checked-in config sets lowercase_strings=true. The key-normalization implementation lowercases password and TOTP values when those fields are selected, so distinct secrets can collapse into one dedup group.
- Safety defect: duplicate selection retains one whole item rather than merging metadata, so different notes, URLs, history, TOTP or other fields can be lost.
- Safety defect: report fields named key and policy_value may contain raw secret values. Even dry-run can write a report file before returning.
- Correctness risks: broad text normalization, simplistic URI host parsing and match policies that do not first distinguish item types; unsafe output/report permissions and interrupted-write handling are not verified.
- Validation: no standalone tests or CI workflow were found at the inspected conventional paths; no source build/test run has been performed in this adoption session. Existing functionality is implemented but not yet acceptance-verified.
- Related project: Passflick already supports explicit Edge, Chrome, Firefox, Apple CSV snapshots; its source contract excludes importing Apple notes/OTPAuth into its password projection. Reuse compatible logic where licensed and justified; do not conflate that projection with a lossless master export.
- Current README calls the operation “hashing,” but build_key constructs canonical JSON strings. Documentation must be reconciled with implementation.

## ⚖️ Completion accounting and continuation rules

Weights measure comparable full-lifecycle effort and risk, not task count. **100 weighted points total.** A task receives its entire weight only when its written acceptance criteria are verified; partial implementation without evidence remains uncredited. Every task has a stable identifier, identifying emoji, deliverable, acceptance criteria, dependency, weight, and status. Allowed statuses: pending, active, blocked, verified complete. Keep historic statuses and evidence in this file or a concise linked verification record. Never manufacture progress, claim untested work is verified, or hide significant validation in the last 10%.

**Initial audited baseline: 5/100 verified weighted points (5%).** This is a new, expanded-goal measurement, **not a +5 pp change** from any prior project percentage. Pre-existing functionality is acknowledged above but not credited under the expanded acceptance criteria until tested. Previous comparable percentage: unknown; delta: N/A (no comparable previous baseline).

| Milestone | Weight | Verified | Status |
| --- | ---: | ---: | --- |
| M0 🔍 Adoption, scope and roadmap | 5 | 5 | verified complete |
| M1 🛡️ Safety-critical hardening | 15 | 0 | active |
| M2 📥 Multi-source ingestion | 15 | 0 | pending |
| M3 🧱 Canonical model and normalization | 12 | 0 | pending |
| M4 🧩 Conservative matching and merging | 18 | 0 | pending |
| M5 🧑‍⚖️ Conflict review and repeatability | 10 | 0 | pending |
| M6 📤 Vaultwarden and Passflick outputs | 10 | 0 | pending |
| M7 🧪 QA, adversarial tests and end-to-end acceptance | 10 | 0 | pending |
| M8 📚 Documentation, packaging and handoff | 5 | 0 | pending |
| **Total** | **100** | **5** | **5% verified** |

## Milestones and acceptance criteria

### M0 🔍 Adoption, scope and roadmap — 5 points

- **M0-01 🔬 Existing-code reconnaissance** — **2 pt; verified complete; deps: none.** Deliverable: source/config/README/manifest review and recorded capabilities/risks. Accept: existing behavior distinguished from verified behavior; dangerous comparison/reporting paths identified; no real secrets handled. Evidence: reviewed main src/main.rs, config.toml, Cargo.toml, README.md and related Passflick source contract on 2026-11-01.
- **M0-02 🗺️ Scope, full-lifecycle roadmap and baseline** — **3 pt; verified complete; deps: M0-01.** Deliverable: this owner-aligned durable roadmap, weights, acceptance gates, integration boundaries, conservative baseline. Accept: all foreseeable implementation/verification/migration/release work accounted for and no unrelated work added. Evidence: ROADMAP.md committed to main. Reopen only for a genuine omitted requirement or corrected evidence.

### M1 🛡️ Safety-critical hardening — 15 points

- **M1-01 🔤 Secret-preserving comparison** — **4 pt; active; deps: M0.** Deliverable: split identity normalization from secret comparison; password, TOTP, recovery material and unrecognized fields remain byte-exact; prohibit lowercase/trim on secrets even under legacy config. Accept: synthetic differing-case passwords/TOTP never auto-collapse; compatibility behavior and migration warning tested.
- **M1-02 🕵️ Redacted output and true dry-run** — **4 pt; active; deps: M0.** Deliverable: redacted CLI/report schema and read-only dry-run. Accept: reports, errors and default terminal output contain no passwords, TOTP, notes or secret-bearing keys; dry-run creates/modifies no files including report; synthetic secret canary test passes.
- **M1-03 🧷 Non-destructive, private durable writes** — **4 pt; active; deps: M0.** Deliverable: no-overwrite default, explicit intentional overwrite, private output permissions, safe temporary-file/atomic replacement and recovery behavior. Accept: simulated interruption leaves original intact, collisions fail closed, file permissions verified on Linux; input files never modified.
- **M1-04 🚦 Validate unsafe legacy modes** — **3 pt; active; deps: M1-01–03.** Deliverable: audited defaults, reject dangerous policy combinations and ambiguous item types, bound input/report sizes, safe failure diagnostics. Accept: known risky config modes cannot silently discard records; malformed/oversize inputs fail before output side effects.

### M2 📥 Multi-source ingestion — 15 points

- **M2-01 🟦 Edge and Chrome/Chromium CSV** — **3 pt; pending; deps: M1-02.** Deliverable: validated source adapters, provenance and explicit source labeling. Accept: documented header variants, quotes/newlines/UTF-8, empty values and malformed rows tested; no undocumented interchange assumptions.
- **M2-02 🦊 Firefox CSV** — **3 pt; pending; deps: M1-02.** Deliverable: Firefox export adapter retaining all useful represented fields including time metadata as provenance when safe. Accept: synthetic Firefox fixtures preserve credentials and report deliberately unmappable fields.
- **M2-03 🍎 Apple Passwords CSV** — **3 pt; pending; deps: M1-02.** Deliverable: Apple adapter including Notes/OTPAuth preservation where present. Accept: no silent loss of TOTP/notes, unsupported passkeys and excluded items explicitly reported; synthetic fixtures validated.
- **M2-04 🗝️ Bitwarden/Vaultwarden JSON** — **3 pt; pending; deps: M1-04.** Deliverable: reliable individual-vault JSON support with typed items, folders, field variants and explicit encrypted-vs-plaintext format handling. Accept: supported JSON round trips with loss accounting; unsupported exports rejected without misleading success.
- **M2-05 📚 Multi-input ingest and provenance** — **3 pt; pending; deps: M2-01–04, M3-01.** Deliverable: repeated --source/--input CLI or manifest-based batch ingestion with per-file labels. Accept: source counts, input identity, order-independent semantics and no partial commit on one bad source; duplicate inputs detected.

### M3 🧱 Canonical model and normalization — 12 points

- **M3-01 🧬 Typed canonical record model** — **3 pt; pending; deps: M1-01.** Deliverable: typed representation for logins, cards, identities, secure notes, metadata, provenance and opaque unknown fields. Accept: distinct item types cannot accidentally merge; no recognized source values silently disappear.
- **M3-02 🌐 Safe URL and account identity handling** — **3 pt; pending; deps: M3-01.** Deliverable: conservative URI parsing for subdomains, ports, schemes, IP/localhost, Unicode and mobile app identifiers. Accept: unrelated hosts and distinct usernames never silently merge; parser edge-case fixtures pass.
- **M3-03 🧾 Field-level preservation and mapping inventory** — **3 pt; pending; deps: M3-01, M2-01–04.** Deliverable: source-to-canonical field map and explicit loss/unsupported-feature records. Accept: notes, custom fields, URIs, folders, password history and exported TOTP survive where representable; absent data isn't fabricated.
- **M3-04 🧮 Deterministic canonicalization** — **3 pt; pending; deps: M3-01–03.** Deliverable: stable canonical ordering and matching keys separated from exact retained values. Accept: shuffled input order yields equivalent merged records and stable conflict sets; identity rules are documented and configurable without weakening safety.

### M4 🧩 Conservative matching and merging — 18 points

- **M4-01 🧲 Exact-duplicate grouping** — **4 pt; pending; deps: M3-04.** Deliverable: byte-exact secret matching plus conservative identity equivalence. Accept: true duplicate records group across sources; same-site distinct username/password, secure notes and cards are never incorrectly dropped.
- **M4-02 🧷 Lossless field union** — **4 pt; pending; deps: M4-01, M3-03.** Deliverable: merge compatible URLs, notes, metadata, favorites and other representable fields while preserving source evidence. Accept: union preserves all nonconflicting information; conflicts within nonsecret fields remain reviewable rather than arbitrarily discarded.
- **M4-03 ⚔️ Conflicting passwords and 2FA** — **4 pt; pending; deps: M4-01.** Deliverable: explicit unresolved alternatives for same-site/user with different password/TOTP, including blank-vs-nonblank distinctions. Accept: every candidate remains recoverable until an affirmative decision, and timestamps never auto-decide which secret is valid.
- **M4-04 🛡️ Type, organization and special-item isolation** — **3 pt; pending; deps: M3-01, M4-02.** Deliverable: safe handling of nonlogin items and special fields; quarantine or pass through unsupported structures. Accept: different types, ownership scopes and special metadata aren't coalesced accidentally; limitations surfaced.
- **M4-05 🔍 Explainable matching audit** — **3 pt; pending; deps: M4-01–04.** Deliverable: local report of why candidates matched or conflicted, without exposing secrets. Accept: each automatic merge has a reviewable reason and provenance; stable summary counts reconcile to all input records.

### M5 🧑‍⚖️ Conflict review and repeatability — 10 points

- **M5-01 📋 Review inventory** — **3 pt; pending; deps: M4-03, M4-05.** Deliverable: safe CLI review summary and optional private decision manifest based on opaque record references. Accept: conflicts identified without printed secrets by default; review report creation requires explicit action and protects file permissions.
- **M5-02 ✍️ Explicit resolution decisions** — **3 pt; pending; deps: M5-01.** Deliverable: choose/keep-both/merge-nonsecret-fields/defer per conflict, with safe validation. Accept: no unresolved conflict is silently resolved or discarded; stale or ambiguous decisions fail closed; source records remain unchanged.
- **M5-03 🔁 Idempotent reruns** — **2 pt; pending; deps: M5-02, M3-04.** Deliverable: reusable decision records and repeatable exports. Accept: re-running identical source snapshots and approved decisions gives equivalent results; new conflicts invalidate only affected decisions.
- **M5-04 📊 Reconciliation ledger** — **2 pt; pending; deps: M5-01–03.** Deliverable: input/output counts and loss/retention summary. Accept: every input record accounted for as retained, merged with provenance, explicitly resolved, or flagged unsupported; no unexplained drops.

### M6 📤 Vaultwarden and Passflick outputs — 10 points

- **M6-01 🏦 Bitwarden/Vaultwarden JSON export** — **4 pt; pending; deps: M4, M5.** Deliverable: import-compatible typed JSON with folders/fields where supported and declared limitations. Accept: synthetic clean output imports into isolated test vault, values round trip correctly, and repeated import behavior is documented (Bitwarden does not deduplicate imported items).
- **M6-02 🪶 Passflick local consumption** — **3 pt; pending; deps: M4, M5.** Deliverable: documented offline snapshot contract compatible with Passflick's current CSV import interface, or a separately approved Passflick adapter if necessary. Accept: synthetic consolidated passwords can be found through an installed/test Passflick consumer; metadata/TOTP excluded by that consumer is explicitly declared; no assumption of live synchronization.
- **M6-03 📦 Export completeness and migration warnings** — **3 pt; pending; deps: M6-01–02, M3-03.** Deliverable: final export validator and unsupported-feature checklist (passkeys, attachments, excluded source fields, etc.). Accept: output/schema validation and counts match the reconciliation ledger; incomplete unsupported records trigger actionable warnings; no claim that plain exports include inaccessible data.

### M7 🧪 QA, adversarial tests and end-to-end acceptance — 10 points

- **M7-01 🧪 Unit and regression fixtures** — **2 pt; pending; deps: M1–M4.** Deliverable: synthetic coverage for case-sensitive secrets, unsafe previous defaults, typed items, URI collisions, metadata merging and conflict choices. Accept: reproductions of all identified safety defects fail on legacy behavior and pass after repair.
- **M7-02 🔗 End-to-end multi-source migration** — **3 pt; pending; deps: M5–M6.** Deliverable: synthetic Edge + Chrome + Firefox + Apple + Bitwarden ingest through both outputs and repeat runs. Accept: no missing records, round-trip checks pass in isolated Vaultwarden/Passflick targets; exact test versions and commands recorded.
- **M7-03 🔐 Security and resilience assessment** — **3 pt; pending; deps: M1–M6.** Deliverable: audit for secret disclosure, temp files, permissions, crash/debug logs, malformed/oversized input, interrupted writes and report safety. Accept: no known release-blocking information disclosure or data-loss defect; failures and their tested handling documented.
- **M7-04 ✅ Toolchain and CI gates** — **2 pt; pending; deps: M7-01–03.** Deliverable: cargo fmt/check/clippy/test and appropriate GitHub Actions on supported platforms. Accept: relevant gates pass on final candidate; CI conclusion recorded, not assumed; local CLI smoke test on EndeavourOS documented or flagged as outstanding.

### M8 📚 Documentation, packaging and handoff — 5 points

- **M8-01 📖 User documentation and accurate help** — **1 pt; pending; deps: M1–M6.** Deliverable: concise README, CLI help, format mapping and full guide under docs/, including correction of “hashing” wording and Cargo/repository naming discrepancy. Accept: instructions match verified flags, outputs and limitations.
- **M8-02 🧭 Migration/recovery runbook** — **1 pt; pending; deps: M6, M7.** Deliverable: preflight/export/dry-run/review/import/verify/rollback guide; emphasize keeping originals and avoiding cloud/public plaintext. Accept: synthetic dry-run through clean import and rollback exercises the published steps.
- **M8-03 📜 Licensing and release hygiene** — **1 pt; pending; deps: M7.** Deliverable: preserve existing license or obtain approval before any change; appropriate notices, changelog/version and release checklist; secret-safe fixture ignores. Accept: public artifacts pass privacy review, filenames/version match reality.
- **M8-04 🚀 Packaged CLI and acceptance handoff** — **2 pt; pending; deps: M8-01–03, M7.** Deliverable: reproducible Linux release artifact or documented installation method, checksums where applicable, smoke-tested binary and final acceptance evidence. Accept: owner can run tool locally against authorized exports, resolve conflicts and generate both consumers' files; exact commit and remaining limitations recorded. Any public release/tag requires separate owner authorization.

## 🔗 Dependency and execution order

M0 → M1 (security blockers) → M3-01 + source adapters (M2) → remaining M3 → M4 → M5 → M6 → M7 → M8. Parallelize only independent safe work. The first coding priority is M1-01 and M1-02, **before using the existing deduplicator with real credentials**. Regression tests should accompany each repair; do not defer all testing until M7.

## 📝 Reporting template

At each development round:
- Overall: previous % → current %, visual bar representing current verified %, and signed Δ in percentage points. For newly rebaselined/noncomparable percentages, state “previous unknown; Δ N/A” instead of inventing a comparison.
- Only currently touched, unfinished milestones and tasks: stable IDs, emoji, prior/current % + corresponding visual bar where defensible, and newly verified completions; suppress reannouncing tasks already reported at 100%.
- Tests: exact command/results or “not run.” Commit SHA and branch only after confirming the actual commit. Remaining blockers, smallest actionable next work, and explicit owner-action needs (say “none” if none).
- “Continue” means continue unfinished in-scope work if warranted, otherwise stop. Never create new work to fill a round.
- At material milestones and before 80–90%, reassess full remaining workload. Preserve completed evidence; disclose any genuine scope/weight change and prohibit misleading cross-baseline Δ calculations.

## 📌 External format references

- Bitwarden custom CSV/JSON format: https://bitwarden.com/help/condition-bitwarden-import/
- Bitwarden import behavior (duplicate items may be created on re-import): https://bitwarden.com/help/import-data/
- Passflick import/source contract: https://github.com/sguzman/passflick/blob/main/docs/sources.md

**2026-11-01 implementation checkpoint:** M1-01 through M1-04 are active, not verified complete. Code changes now force exact password/TOTP matching, preserve all nonidentical records, leave non-login records untouched, redact duplicate reports, reject report writes on dry-run, reject destructive legacy keep strategies, and use private atomic output plus automatic backup before a forced overwrite. Ten synthetic Rust test functions are committed. GitHub Actions build/test workflow added. **Build/test/CI passing status and target-host runtime are unverified:** this session had no local Rust compiler and no successful GitHub check result surfaced. Do not process real credentials yet. Relevant commits include d380e30e, 91bc70d9, 540b4b3d, 9ba6c4cf. No M1 weight is credited until its acceptance criteria are exercised. Next: obtain passing CI/target build, repair issues, run adversarial tests and inspect output permissions. Reassess M1 completion only with evidence.

**Last planning update:** 2026-11-01. **Next development action:** verify, repair, and complete M1-01 through M1-04; then begin M3 canonical typed model and M2 import adapters.