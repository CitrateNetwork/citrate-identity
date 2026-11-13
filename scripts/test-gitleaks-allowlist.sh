#!/usr/bin/env bash
# Self-test for this repo's .gitleaks.toml allowlist.
#
# The blocking secret-scan (CitrateNetwork/.github reusable-secret-scan) scans
# FULL history, so a test fixture that trips gitleaks' generic-api-key rule in
# any past commit keeps main red until the value is allowlisted. Allowlist
# entries are EXACT values (anchored), never paths, so the allowlist cannot
# grow to hide a real secret placed in the same file. This test pins both:
#   1. each allowlisted fixture value is suppressed;
#   2. a secret of the same shape that is NOT one of those values is detected.
# Fixtures are written to a temp dir at runtime (never committed).
set -euo pipefail

CONFIG="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.gitleaks.toml"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# test/kyc-status-secrets.test.ts (#44): a deliberately shared webhook/status secret.
ALLOWED='same-secret-0123456789'
# Same shape, not allowlisted: must still be reported.
NEAR='same-secret-0123456780'
OTHER='Zq8Wm2Rk5Tp9Lx3Vb7Nc'

cat > "$WORK/fixture.ts" <<FIX
await mount({ KYC_WEBHOOK_SECRET: '$ALLOWED', KYC_STATUS_SECRET: '$ALLOWED' });
await mount({ KYC_WEBHOOK_SECRET: '$NEAR' });
await mount({ KYC_WEBHOOK_SECRET: '$OTHER' });
FIX

OUT="$WORK/out.json"
gitleaks detect --no-git --source "$WORK" --config "$CONFIG" \
  --report-format json --report-path "$OUT" >/dev/null 2>&1 || true

fail=0
if grep -q "\"$ALLOWED\"" "$OUT"; then
  echo "FAIL: allowlisted fixture value '$ALLOWED' is still reported"; fail=1
else
  echo "ok: '$ALLOWED' is suppressed"
fi
for v in "$NEAR" "$OTHER"; do
  if grep -q "\"$v\"" "$OUT"; then
    echo "ok: '$v' (not allowlisted) is detected"
  else
    echo "FAIL: '$v' was suppressed: the allowlist is wider than exact values"; fail=1
  fi
done
exit "$fail"
