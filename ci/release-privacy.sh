#!/usr/bin/env bash
# Narrow, deterministic release hygiene check: forbid accidentally tracked
# plaintext exports, key material and generated vault data. Does not claim to
# detect secrets embedded in source text or past Git history.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
failed=0
while IFS= read -r -d '' tracked; do
  case "$tracked" in
    *.csv|*.json|*.passvault|*.key|*.pem|*.der|*.p12|*.pfx|*.sqlite|*.sqlite3|*.db|*.db-wal|*.db-shm|*.zip|*.bak|*.backup.*|*.log|*.env|.env|.env.*)
      printf 'Unsafe tracked artifact pathname: %s\n' "$tracked" >&2
      failed=1
      ;;
  esac
done < <(git ls-files -z)
if [ "$failed" -ne 0 ]; then
  echo "Release privacy gate rejected tracked credential-like artifacts." >&2
  exit 1
fi
echo "PASS: No prohibited credential-export or private-key file suffixes are tracked."
