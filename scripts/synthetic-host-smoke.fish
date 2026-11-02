#!/usr/bin/env fish
# Local, synthetic-only acceptance check for the existing built Rust CLI.
# This script never reads actual password exports or changes existing vaults.

set -l binary "target/release/bw-passport-dedup"
if set -q CARGO_TARGET_DIR
    set binary "$CARGO_TARGET_DIR/release/bw-passport-dedup"
end
if not test -x "$binary"
    echo "Missing optimized executable. Run: cargo +stable build --release --locked" >&2
    exit 2
end

set -l scratch (mktemp -d)
or exit 2
chmod 700 -- "$scratch"
set -gx BW_DEDUP_SMOKE_DIR "$scratch"
function __bw_dedup_cleanup --on-event fish_exit
    if set -q BW_DEDUP_SMOKE_DIR
        command rm -rf -- "$BW_DEDUP_SMOKE_DIR"
    end
end

printf '%s\n' '{"encrypted":false,"folders":[],"items":[{"type":1,"name":"Fictional Host Smoke","login":{"username":"synthetic-only","password":"SYNTHETIC_NOT_REAL","uris":[{"uri":"https://example.test/synthetic"}]}}]}' > "$scratch/source.json"
cp -- "$scratch/source.json" "$scratch/untouched.json"

"$binary" --help > "$scratch/help.txt"
or exit 1
grep -Fq -- '--validate-vaultwarden-import' "$scratch/help.txt"
or exit 1
grep -Fq -- '--passflick-export' "$scratch/help.txt"
or exit 1

"$binary" --input "$scratch/source.json" --output "$scratch/clean.json" --validate-vaultwarden-import > "$scratch/stdout.log" 2> "$scratch/stderr.log"
or exit 1
test -s "$scratch/clean.json"
or exit 1
test (stat -c %a "$scratch/clean.json") = 600
or exit 1
cmp -s -- "$scratch/source.json" "$scratch/untouched.json"
or exit 1
grep -Fq -- 'SYNTHETIC_NOT_REAL' "$scratch/clean.json"
or exit 1

echo "PASS: Synthetic local CLI smoke with private output and unchanged source."
