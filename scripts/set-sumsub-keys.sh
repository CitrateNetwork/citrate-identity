#!/usr/bin/env bash
#
# Rotate ONLY the Sumsub App Token + Secret Key (the matching pair) — for when
# `app-token-not-found` (4001) means the token is stale/wrong. Leaves
# SUMSUB_WEBHOOK_SECRET, SUMSUB_LEVEL_NAME, KYC_WEBHOOK_SECRET, KYC_PROVIDER
# untouched (so the working Sumsub-dashboard webhook secret is NOT disturbed).
#
# Both values are read with `read -rs` (no echo, not in argv/history) and written
# to a 0600 file. Safe to run with an AI pair watching — it cannot see your input.
#
# Get the pair from the Sumsub dashboard → Dev Space → App Tokens (use the SANDBOX
# space that also holds your `basic-kyc-level` + the webhook). The App Token starts
# with `sbx:` (sandbox) or `prd:` (production); copy its matching Secret Key (shown
# once at creation — regenerate the pair if you no longer have it).
#
# Usage:
#   ./scripts/set-sumsub-keys.sh                 # writes ./.env.sumsub (0600)
#   ./scripts/set-sumsub-keys.sh --append <file> # upsert the two keys into <file>
set -euo pipefail
umask 077

MODE="write"; OUT="./.env.sumsub"
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--out) OUT="$2"; shift 2 ;;
    --append) MODE="append"; OUT="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

prompt_secret() {  # $1=var, $2=label
  local __v=""
  while [ -z "$__v" ]; do
    printf '  %s: ' "$2" >&2
    IFS= read -rs __v || true
    printf '\n' >&2
    [ -z "$__v" ] && printf '    (required)\n' >&2
  done
  printf -v "$1" '%s' "$__v"
}

echo "Rotate Sumsub App Token + Secret Key (hidden input; nothing echoed)." >&2
prompt_secret SUMSUB_APP_TOKEN  "SUMSUB_APP_TOKEN (sbx:… or prd:…)"
prompt_secret SUMSUB_SECRET_KEY "SUMSUB_SECRET_KEY (matching pair)"

case "$SUMSUB_APP_TOKEN" in
  sbx:*|prd:*) : ;;
  *) echo "  ⚠ token has no sbx:/prd: prefix — double-check you copied the App Token (not the secret)." >&2 ;;
esac

write_block() {
  printf 'SUMSUB_APP_TOKEN=%s\n'  "$SUMSUB_APP_TOKEN"
  printf 'SUMSUB_SECRET_KEY=%s\n' "$SUMSUB_SECRET_KEY"
}

if [ "$MODE" = "append" ] && [ -f "$OUT" ]; then
  tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
  grep -vE '^(SUMSUB_APP_TOKEN|SUMSUB_SECRET_KEY)=' "$OUT" > "$tmp" || true
  write_block >> "$tmp"
  mv "$tmp" "$OUT"; chmod 600 "$OUT"
else
  write_block > "$OUT"; chmod 600 "$OUT"
fi
echo "" >&2
echo "✓ wrote SUMSUB_APP_TOKEN + SUMSUB_SECRET_KEY → $OUT (0600). Values never printed." >&2
echo "  token env prefix: $(printf %s "$SUMSUB_APP_TOKEN" | cut -c1-4)  (sbx: = sandbox, prd: = production)" >&2
