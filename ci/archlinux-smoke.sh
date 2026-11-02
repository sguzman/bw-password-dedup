#!/usr/bin/env bash
# Runs ONLY inside an ephemeral, official Arch Linux CI container.
# No real credentials, system vaults, user accounts, or public build artifacts.
set -euo pipefail
umask 077

pacman -Syu --noconfirm --needed base-devel rustup jq fish ca-certificates
rustup toolchain install stable --profile minimal
export CARGO_HOME=/tmp/bw-dedup-cargo
export CARGO_TARGET_DIR=/tmp/bw-dedup-target
cargo +stable build --release --locked

binary="$CARGO_TARGET_DIR/release/bw-passport-dedup"
test -x "$binary"
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch" "$CARGO_HOME" "$CARGO_TARGET_DIR"' EXIT
chmod 700 "$scratch"
export BIN_PATH="$binary"
export WORK_DIR="$scratch"
fish -c '$BIN_PATH --help > "$WORK_DIR/help.txt"'
grep -Fq -- '--validate-vaultwarden-import' "$scratch/help.txt"
grep -Fq -- '--passflick-export' "$scratch/help.txt"

cat > "$scratch/synthetic.json" <<'JSON'
{"encrypted":false,"folders":[],"items":[
{"type":1,"name":"Fictional Arch Smoke","login":{"username":"synthetic-user","password":"SyntheticOnlyPassword","uris":[{"uri":"https://example.test/synthetic"}]}}
]}
JSON
fish -c '$BIN_PATH --input "$WORK_DIR/synthetic.json" --output "$WORK_DIR/clean.json" --validate-vaultwarden-import > "$WORK_DIR/stdout.log" 2> "$WORK_DIR/stderr.log"'

jq -e '.items | length == 1' "$scratch/clean.json" >/dev/null
jq -e '.items[0].login.password == "SyntheticOnlyPassword"' "$scratch/clean.json" >/dev/null
test "$(stat -c %a "$scratch/clean.json")" = 600
fish scripts/synthetic-host-smoke.fish
echo "PASS: Official Arch Linux container, fish invocation, fictional import and private output."
sha256sum "$binary"
