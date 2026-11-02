# 2026-11-02 — Owner EndeavourOS synthetic acceptance

**Source:** Owner-provided terminal output, observed on the actual EndeavourOS
workstation on 2026-11-02 around 14:45 local time (America/Mexico_City).
No real credential, user account, path, vault or password was collected or
published. The exact Rust toolchain patch version and local binary hash were
not present in the transcript; do not infer them.

**Repository:** `sguzman/bw-password-dedup`, `main`, based on the verified
`cff8f85d39def86159230af15ca2637a1c6c9b8f` engineering candidate
(no source-code changes to the CLI after that checkpoint).

Commands reported as executed from the repository root:

```fish
cargo +stable build --release --locked
fish scripts/synthetic-host-smoke.fish
```

Observed results:
- Optimized cargo build: `Finished release profile [optimized]` in **18.26 s**.
- Local mbx/sccache reporting: 5 cache hits, 0 misses (context only).
- Fish smoke: **`PASS: Synthetic local CLI smoke with private output and unchanged source.`**

The smoke script creates a disposable fictional JSON record and verifies
CLI help flags, static import validation, mode-0600 output, unchanged source,
and expected fixture contents, then cleans up. It does **not** test real
credentials, a live Vaultwarden server, user data restoration, malicious
same-user races, or actual power loss.

The owner's subsequent **explicit approval on 2026-11-02** authorizes the
project's MIT license and one public v0.1.0 release. It does not authorize
touching real credential stores.
