#!/usr/bin/env bash
# Test ONLY fictional five-source consolidation using real isolated Passflick.
# Passflick is a browser-attributed local consumer, not a Vaultwarden replacement.
set -euo pipefail
umask 077

dedup_bin="${1:?missing absolute deduplicator binary}"
passflick_bin="${2:?missing absolute Passflick binary}"
tmpdir="$(mktemp -d)"
trap 'rm -rf -- "$tmpdir"' EXIT
chmod 700 "$tmpdir"
export PASSFLICK_VAULT="$tmpdir/passflick.passvault"
export XDG_DATA_HOME="$tmpdir/data"
export XDG_CONFIG_HOME="$tmpdir/config"
export XDG_CACHE_HOME="$tmpdir/cache"
mkdir -m 700 -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"

cat > "$tmpdir/bitwarden.json" <<'JSON'
{"encrypted":false,"folders":[],"items":[
  {"type":1,"name":"Synthetic Vaultwarden only",
   "login":{"username":"unattributed-user","password":"unattributed-secret",
            "uris":[{"uri":"https://vaultonly.example.test"}]}},
  {"type":2,"name":"Synthetic Secure Note","notes":"Fictional note","secureNote":{"type":0}}
]}
JSON
cat > "$tmpdir/edge.csv" <<'CSV'
name,url,username,password
Synthetic Edge,https://edge.example.test/login,synthetic-edge-user,synthetic-edge-password
CSV
cat > "$tmpdir/chrome.csv" <<'CSV'
name,url,username,password
Synthetic Chrome,https://chrome.example.test/login,synthetic-chrome-user,synthetic-chrome-password
CSV
cat > "$tmpdir/firefox.csv" <<'CSV'
url,username,password,guid
https://firefox.example.test/login,synthetic-firefox-user,synthetic-firefox-password,synthetic-guid
CSV
cat > "$tmpdir/apple.csv" <<'CSV'
Title,URL,Username,Password,Notes,OTPAuth
Synthetic Apple,https://apple.example.test/login,synthetic-apple-user,synthetic-apple-password,Synthetic Apple note,otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP
CSV

args=(
  --input "$tmpdir/bitwarden.json"
  --source "edge=$tmpdir/edge.csv"
  --source "chrome=$tmpdir/chrome.csv"
  --source "firefox=$tmpdir/firefox.csv"
  --source "apple=$tmpdir/apple.csv"
)
outputs=()
for provider in edge chrome firefox apple; do
  outputs+=(--passflick-export "$provider=$tmpdir/for-passflick-$provider.csv")
done
"$dedup_bin" "${args[@]}" --output "$tmpdir/merged.json" "${outputs[@]}" > "$tmpdir/dedup.log"
test "$(jq '.items | length' "$tmpdir/merged.json")" = 6
for provider in edge chrome firefox apple; do
  test -s "$tmpdir/for-passflick-$provider.csv"
  test "$(stat -c %a "$tmpdir/for-passflick-$provider.csv")" = 600
  grep -Fq "synthetic-$provider-password" "$tmpdir/for-passflick-$provider.csv"
  if grep -Fq 'unattributed-secret' "$tmpdir/for-passflick-$provider.csv"; then
    echo "Vaultwarden-only password was falsely attributed to a browser" >&2
    exit 1
  fi
  for other in edge chrome firefox apple; do
    if [ "$provider" != "$other" ] &&
       grep -Fq "synthetic-$other-password" "$tmpdir/for-passflick-$provider.csv"; then
      echo "Cross-provider password leakage in generated snapshot" >&2
      exit 1
    fi
  done
done
test "$(jq '[.items[] | select(.name=="Synthetic Vaultwarden only")] | length' "$tmpdir/merged.json")" = 1

# Replay with the same source order must produce byte-identical JSON and CSV
# snapshots even when the destination filenames differ.
repeat_outputs=()
for provider in edge chrome firefox apple; do
  repeat_outputs+=(--passflick-export "$provider=$tmpdir/repeat-$provider.csv")
done
"$dedup_bin" "${args[@]}" --output "$tmpdir/merged-repeat.json" "${repeat_outputs[@]}" > "$tmpdir/repeat.log"
cmp -s "$tmpdir/merged.json" "$tmpdir/merged-repeat.json"
for provider in edge chrome firefox apple; do
  cmp -s "$tmpdir/for-passflick-$provider.csv" "$tmpdir/repeat-$provider.csv"
done

# Existing Passflick CLI prompts over a terminal; all inputs are fictional
# and each operation runs against this private disposable encrypted vault.
fictional_passphrase="fictional-CI-passphrase-for-isolated-vault-2026"
printf '%s\n%s\n' "$fictional_passphrase" "$fictional_passphrase" \
  | script -q -e -c "$passflick_bin init" /dev/null > "$tmpdir/init.log"
test -s "$PASSFLICK_VAULT"
for provider in edge chrome firefox apple; do
  printf '%s\n' "$fictional_passphrase" \
    | script -q -e -c "$passflick_bin import $provider $tmpdir/for-passflick-$provider.csv" \
        /dev/null > "$tmpdir/import-$provider.log"
done
printf '%s\n' "$fictional_passphrase" \
  | script -q -e -c "$passflick_bin list" /dev/null > "$tmpdir/list.log"

for provider in edge chrome firefox apple; do
  grep -Fq "synthetic-$provider-user" "$tmpdir/list.log"
  if grep -Fq "synthetic-$provider-password" "$tmpdir/list.log"; then
    echo "Passflick exposed a fictional password in list labels" >&2
    exit 1
  fi
done
if grep -Fq "unattributed-user" "$tmpdir/list.log"; then
  echo "Passflick incorrectly claimed to import the Vaultwarden-only account" >&2
  exit 1
fi
echo "PASS: Five source snapshots consolidated reproducibly; real Passflick consumed all four browser-attributed projections in an isolated encrypted vault."
