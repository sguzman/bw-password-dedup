# Isolated Vaultwarden + official Bitwarden CLI integration smoke.
# Only synthetic credentials; no local user vaults, network-facing server,
# GitHub artifacts, or real password-manager data. Run via bash.
set -euo pipefail
umask 077

DEDUP_BIN="${1:?missing absolute deduplicator executable}"
BW_BIN="${2:?missing absolute Bitwarden CLI executable}"
CRYPTO_LIB="${3:?missing pinned synthetic bootstrap crypto helper}"
TEST_ROOT="${4:?missing dedicated temp directory}"
VW_URL="https://127.0.0.1:8443"
export VW_URL
export NODE_EXTRA_CA_CERTS="$TEST_ROOT/tls/cert.pem"
export BITWARDENCLI_APPDATA_DIR="$TEST_ROOT/bitwarden-cli"
export BW_NOINTERACTION=true
mkdir -m 700 -p "$BITWARDENCLI_APPDATA_DIR"
source "$CRYPTO_LIB"

for command in openssl curl jq xxd base64 docker; do
    command -v "$command" >/dev/null || { echo "Missing required test command: $command" >&2; exit 1; }
done

# Validate the same PBKDF2 vector published for Bitwarden before registration.
key_check=$(bw_master_key "p4ssw0rd" "nobody@example.com" 5000)
test "${key_check^^}" = "13886A60996DE3464194EE27F0B21A21B63E5C29F4D5CA23E51BA666356F7BAA"

# No real account, no real secret, no persistent credential state.
email="synthetic-smoke@example.test"
password="FictionalOnly-CI-Bitwarden-Password-2026!"
iter=600000
mk=$(bw_master_key "$password" "$email" "$iter")
mph=$(bw_master_password_hash "$mk" "$password")
subkeys=$(bw_derive_subkeys "$mk")
enc=$(printf '%s\n' "$subkeys" | sed -n '1p')
mac=$(printf '%s\n' "$subkeys" | sed -n '2p')
gsk=$(bw_generate_symmetric_key)
printf '%s' "$gsk" | xxd -r -p > "$TEST_ROOT/generated-key.bin"
key_cipher=$(bw_cipherstring_encrypt "$TEST_ROOT/generated-key.bin" "$enc" "$mac")
bw_generate_rsa_keypair "$TEST_ROOT/private-original.der"
openssl pkcs8 -topk8 -inform DER -outform DER -nocrypt -in "$TEST_ROOT/private-original.der" -out "$TEST_ROOT/private.der"
public_key=$(bw_extract_public_key "$TEST_ROOT/private.der")
private_cipher=$(bw_cipherstring_encrypt "$TEST_ROOT/private.der" "${gsk:0:64}" "${gsk:64:64}")

# Current Vaultwarden requires a verification-token registration transaction.
# No SMTP is configured on this sealed synthetic server; the token is returned.
verification_body=$(jq -n --arg email "$email" '{email:$email,name:"Synthetic CI Account"}')
verification_response=$(curl --fail --silent --show-error --cacert "$NODE_EXTRA_CA_CERTS" \
    -H 'Accept: application/json' -H 'Content-Type: application/json' \
    --data "$verification_body" "$VW_URL/identity/accounts/register/send-verification-email")
verification_token=$(printf '%s' "$verification_response" |
    jq -r 'if type=="string" then . else (.token // .verificationToken // .emailVerificationToken // empty) end')
test -n "$verification_token" || { echo "Registration verification token missing" >&2; exit 1; }

jq -n --arg email "$email" --arg mph "$mph" --arg key "$key_cipher" \
    --arg pub "$public_key" --arg priv "$private_cipher" \
    --arg verification "$verification_token" --argjson iterations "$iter" \
    '{
        email:$email, name:"Synthetic CI Account",
        masterPasswordHash:$mph, key:$key, kdf:0,
        kdfIterations:$iterations,
        emailVerificationToken:$verification,
        keys:{publicKey:$pub,encryptedPrivateKey:$priv}
    }' > "$TEST_ROOT/register.json"
curl --fail --silent --show-error --cacert "$NODE_EXTRA_CA_CERTS" \
    -H 'Content-Type: application/json' \
    --data-binary "@$TEST_ROOT/register.json" \
    "$VW_URL/identity/accounts/register/finish" > "$TEST_ROOT/registration-response.json"

# No --apikey secrets or password key stored in repository or logs.
"$BW_BIN" config server "$VW_URL" > /dev/null
session=$("$BW_BIN" login "$email" "$password" --raw)
test -n "$session" || { echo "Official Bitwarden CLI did not return a login session" >&2; exit 1; }
export BW_SESSION="$session"
state=$("$BW_BIN" status | jq -r '.status')
if [ "$state" != "unlocked" ]; then
    export BW_TEST_PASSWORD="$password"
    session=$("$BW_BIN" unlock --passwordenv BW_TEST_PASSWORD --raw)
    test -n "$session" || { echo "The synthetic account cannot be unlocked" >&2; exit 1; }
    export BW_SESSION="$session"
    unset BW_TEST_PASSWORD
fi
test "$("$BW_BIN" status | jq -r '.status')" = "unlocked" || {
    echo "CLI state remains locked after synthetic account login" >&2
    exit 1
}
"$BW_BIN" sync > /dev/null
"$BW_BIN" list items | jq -e 'length == 0' > /dev/null || {
    echo "Fresh synthetic vault is not empty or cannot decrypt" >&2
    exit 1
}

# Exercise the real importer with browser provenance merging, typed
# secure notes and folder references. Synthetic only, in a throwaway vault.
cat > "$TEST_ROOT/bitwarden.json" <<'JSON'
{
  "encrypted":false,
  "folders":[{"id":"11111111-1111-4111-8111-111111111111","name":"Synthetic Archive"}],
  "items":[{"type":2,"name":"Synthetic Secure Note","secureNote":{"type":0},
            "notes":"Fictional secure note body",
            "folderId":"11111111-1111-4111-8111-111111111111"}]
}
JSON
cat > "$TEST_ROOT/edge.csv" <<'CSV'
name,url,username,password,CustomEdge
Synthetic Migration,https://example.test/account,fictional-user,CaseSensitiveA,SyntheticMetadata
CSV
cat > "$TEST_ROOT/chrome.csv" <<'CSV'
name,url,username,password
Synthetic Migration,https://example.test/account,fictional-user,CaseSensitiveA
CSV
cat > "$TEST_ROOT/firefox.csv" <<'CSV'
url,username,password,guid
https://firefox.example.test/login,fictional-firefox,CaseSensitiveF,synthetic-guid
CSV
cat > "$TEST_ROOT/apple.csv" <<'CSV'
Title,URL,Username,Password,Notes,OTPAuth
Synthetic OTP,https://otp.example.test/signin,fictional-apple,CaseSensitiveB,Synthetic note,otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP
CSV

# Exercise documented no-write preflight before creating any import file.
"$DEDUP_BIN" \
    --input "$TEST_ROOT/bitwarden.json" \
    --source "edge=$TEST_ROOT/edge.csv" \
    --source "chrome=$TEST_ROOT/chrome.csv" \
    --source "firefox=$TEST_ROOT/firefox.csv" \
    --source "apple=$TEST_ROOT/apple.csv" \
    --merge-compatible-fields \
    --output "$TEST_ROOT/dry-run.json" \
    --dry-run > "$TEST_ROOT/dry-run.log"
test ! -e "$TEST_ROOT/dry-run.json"

"$DEDUP_BIN" \
    --input "$TEST_ROOT/bitwarden.json" \
    --source "edge=$TEST_ROOT/edge.csv" \
    --source "chrome=$TEST_ROOT/chrome.csv" \
    --source "firefox=$TEST_ROOT/firefox.csv" \
    --source "apple=$TEST_ROOT/apple.csv" \
    --merge-compatible-fields \
    --output "$TEST_ROOT/import.json" \
    --validate-vaultwarden-import > "$TEST_ROOT/preflight.log"

test "$(jq '.items | length' "$TEST_ROOT/import.json")" -eq 4
test "$(jq '.folders | length' "$TEST_ROOT/import.json")" -eq 1
test "$(jq '[.items[] | select(.name=="Synthetic Migration") | .fields[] | select(.name=="migration.source")] | length' "$TEST_ROOT/import.json")" -eq 2
"$BW_BIN" import bitwardenjson "$TEST_ROOT/import.json" > "$TEST_ROOT/import.log"
"$BW_BIN" sync > /dev/null
"$BW_BIN" export --format json --output "$TEST_ROOT/roundtrip.json" > "$TEST_ROOT/export.log"

# Inspect decrypted export ONLY in the runner's ephemeral private directory.
# Print fixed safe labels, not file contents or secret-bearing diagnostics.
jq -e '
  (.items | length) == 4 and
  (.folders | length) == 1 and
  (.folders[0].name == "Synthetic Archive") and
  ([.items[].login.password] | index("CaseSensitiveA") != null) and
  ([.items[].login.password] | index("CaseSensitiveB") != null) and
  ([.items[].login.password] | index("CaseSensitiveF") != null) and
  ([.items[].login.totp] | index("otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP") != null) and
  ([.items[].notes] | index("Synthetic note") != null) and
  ([.items[].notes] | index("Fictional secure note body") != null) and
  ([.items[].login.uris[]?.uri] | index("https://example.test/account") != null) and
  ([.items[].login.uris[]?.uri] | index("https://otp.example.test/signin") != null) and
  ([.items[].login.uris[]?.uri] | index("https://firefox.example.test/login") != null) and
  (.folders[0].id as $folder |
     [.items[] | select(.name=="Synthetic Secure Note") | .folderId] == [$folder]) and
  ([.items[] | select(.name=="Synthetic Migration") | .fields[] |
      select(.name=="migration.source") | .value] | length) == 2 and
  ([.items[] | select(.name=="Synthetic Migration") | .fields[] |
      select(.name=="migration.source") | .value] | index("edge") != null) and
  ([.items[] | select(.name=="Synthetic Migration") | .fields[] |
      select(.name=="migration.source") | .value] | index("chrome") != null) and
  ([.items[].fields[]? | select(.name=="migration.source") | .value] |
      index("apple") != null) and
  ([.items[].fields[]? | select(.name=="migration.source") | .value] |
      index("firefox") != null)
' "$TEST_ROOT/roundtrip.json" > /dev/null || {
    echo "Vaultwarden JSON round trip lost required synthetic fields" >&2
    exit 1
}

# Bitwarden import does not deduplicate repeated uploads. Prove the risk.
"$BW_BIN" import bitwardenjson "$TEST_ROOT/import.json" > "$TEST_ROOT/reimport.log"
"$BW_BIN" sync > /dev/null
count=$("$BW_BIN" list items | jq 'length')
test "$count" -eq 8 || {
    echo "Repeated import did not show expected duplicate entries" >&2
    exit 1
}
# Reversible rollback drill: identify exactly the synthetic items created
# in this fresh temporary test vault; send them to Trash without permanent
# deletion. Never automate this deletion against a real target vault.
"$BW_BIN" list items > "$TEST_ROOT/before-rollback.json"
test "$(jq 'length' "$TEST_ROOT/before-rollback.json")" -eq 8
jq -r '.[].id' "$TEST_ROOT/before-rollback.json" |
    while IFS= read -r id; do
        test -n "$id" || exit 1
        "$BW_BIN" delete item "$id" > /dev/null
    done
"$BW_BIN" sync > /dev/null
test "$("$BW_BIN" list items | jq 'length')" -eq 0 || {
    echo "Reversible rollback left active fictional vault items" >&2
    exit 1
}
test "$("$BW_BIN" list items --trash | jq 'length')" -eq 8 || {
    echo "Rollback did not preserve all synthetic records in Trash" >&2
    exit 1
}
"$BW_BIN" logout > /dev/null || true
unset BW_SESSION
echo "PASS: Isolated Vaultwarden five-source round trip and duplicate import checks, followed by reversible synthetic rollback to no active items."
