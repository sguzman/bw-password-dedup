#!/usr/bin/env bash
# Test ONLY synthetic data through the real Passflick CLI in a private temp vault.
# All source labels are preserved; no user's Passflick installation is touched.
set -euo pipefail

dedup_bin="${1:?path to bw-passport-dedup binary}"
passflick_bin="${2:?path to passflick binary}"
tmpdir="$(mktemp -d)"
trap 'rm -rf -- "$tmpdir"' EXIT
chmod 700 "$tmpdir"
export PASSFLICK_VAULT="$tmpdir/passflick.passvault"
export XDG_DATA_HOME="$tmpdir/data"
export XDG_CONFIG_HOME="$tmpdir/config"
export XDG_CACHE_HOME="$tmpdir/cache"
mkdir -m 700 -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"

cat > "$tmpdir/edge.csv" <<'CSV'
name,url,username,password
Synthetic Edge,https://edge.example.test/login,synthetic-edge-user,synthetic-edge-password
CSV
cat > "$tmpdir/chrome.csv" <<'CSV'
name,url,username,password
Synthetic Chrome,https://chrome.example.test/login,synthetic-chrome-user,synthetic-chrome-password
CSV
chmod 600 "$tmpdir/edge.csv" "$tmpdir/chrome.csv"

"$dedup_bin" \
  --source "edge=$tmpdir/edge.csv" \
  --source "chrome=$tmpdir/chrome.csv" \
  --output "$tmpdir/merged.json" \
  --passflick-export "edge=$tmpdir/for-passflick-edge.csv" \
  --passflick-export "chrome=$tmpdir/for-passflick-chrome.csv" > "$tmpdir/dedup.log"

test -s "$tmpdir/merged.json"
test -s "$tmpdir/for-passflick-edge.csv"
test -s "$tmpdir/for-passflick-chrome.csv"
test "$(stat -c %a "$tmpdir/for-passflick-edge.csv")" = 600
test "$(stat -c %a "$tmpdir/for-passflick-chrome.csv")" = 600
grep -Fq "synthetic-edge-password" "$tmpdir/for-passflick-edge.csv"
grep -Fq "synthetic-chrome-password" "$tmpdir/for-passflick-chrome.csv"
if grep -Fq "synthetic-chrome-password" "$tmpdir/for-passflick-edge.csv"; then
  echo "Other source incorrectly attributed to Edge" >&2
  exit 1
fi
if grep -Fq "synthetic-edge-password" "$tmpdir/for-passflick-chrome.csv"; then
  echo "Other source incorrectly attributed to Chrome" >&2
  exit 1
fi

# Existing Passflick CLI requires a tty for its passphrase reader.
# Feed only fictional CI passphrases; suppress tty echo and secret output.
fictional_passphrase="fictional-CI-passphrase-for-isolated-vault-2026"
printf '%s\n%s\n' "$fictional_passphrase" "$fictional_passphrase" \
  | script -q -e -c "$passflick_bin init" /dev/null > "$tmpdir/init.log"
test -s "$PASSFLICK_VAULT"
printf '%s\n' "$fictional_passphrase" \
  | script -q -e -c "$passflick_bin import edge $tmpdir/for-passflick-edge.csv" /dev/null > "$tmpdir/edge.log"
printf '%s\n' "$fictional_passphrase" \
  | script -q -e -c "$passflick_bin import chrome $tmpdir/for-passflick-chrome.csv" /dev/null > "$tmpdir/chrome.log"
printf '%s\n' "$fictional_passphrase" \
  | script -q -e -c "$passflick_bin list" /dev/null > "$tmpdir/list.log"
grep -Fq "synthetic-edge-user" "$tmpdir/list.log"
grep -Fq "synthetic-chrome-user" "$tmpdir/list.log"
if grep -Fq "synthetic-edge-password" "$tmpdir/list.log"; then
  echo "Passflick revealed a password in list labels" >&2
  exit 1
fi
if grep -Fq "synthetic-chrome-password" "$tmpdir/list.log"; then
  echo "Passflick revealed a password in list labels" >&2
  exit 1
fi
echo "Isolated Passflick CLI consumed both synthetic source-preserving CSV projections."
