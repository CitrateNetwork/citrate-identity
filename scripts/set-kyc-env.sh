#!/usr/bin/env bash
#
# Securely capture the Sumsub / KYC secrets for citrate-identity (COMP-S1).
#
# WHY THIS EXISTS: the operator (you) must enter live Sumsub credentials WITHOUT
# them ever being visible to an AI pair, in shell history, or in process args.
# This script reads each secret with `read -rs` (silent, no echo), holds it only
# in a shell variable, and writes it to a 0600 file via a heredoc — the value is
# never passed as a command argument and is never printed back.
#
# It is SAFE to run while an AI assistant is watching: nothing it prints reveals a
# secret. The assistant set this up; it cannot see what you type here.
#
# Usage:
#   ./scripts/set-kyc-env.sh                      # write a fresh ./.env.kyc (0600)
#   ./scripts/set-kyc-env.sh -o /path/to/.env     # write to a specific file
#   ./scripts/set-kyc-env.sh --append /opt/citrate-identity/.env
#                                                 # idempotently upsert the KYC keys
#                                                 # into an existing env file
#
# After writing locally, deploy to the droplet yourself (the secrets travel over
# your SSH, not through the assistant), e.g.:
#   scp ./.env.kyc root@157.230.55.191:/tmp/.env.kyc && \
#   ssh root@157.230.55.191 'cat /tmp/.env.kyc >> /opt/citrate-identity/.env && \
#       chmod 600 /opt/citrate-identity/.env && rm /tmp/.env.kyc && \
#       cd /opt/citrate-identity && docker compose up -d'
set -euo pipefail
umask 077   # any file we create is 0600

MODE="write"          # write | append
OUT="./.env.kyc"
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--out)    OUT="$2"; shift 2 ;;
    --append)    MODE="append"; OUT="$2"; shift 2 ;;
    -h|--help)   grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# --- prompt helpers (never echo secret input) --------------------------------
prompt_secret() {  # $1=var name, $2=label
  local __v=""
  while [ -z "$__v" ]; do
    printf '  %s: ' "$2" >&2
    IFS= read -rs __v || true
    printf '\n' >&2
    [ -z "$__v" ] && printf '    (required — try again)\n' >&2
  done
  printf -v "$1" '%s' "$__v"
}
prompt_plain() {   # $1=var name, $2=label, $3=default
  local __v=""
  printf '  %s [%s]: ' "$2" "${3:-}" >&2
  IFS= read -r __v || true
  [ -z "$__v" ] && __v="${3:-}"
  printf -v "$1" '%s' "$__v"
}

echo "Enter Sumsub / KYC secrets (input is hidden). Nothing you type is echoed or logged." >&2
echo "" >&2

prompt_plain  KYC_PROVIDER        "KYC_PROVIDER (sumsub|mock|clear)"      "sumsub"
prompt_secret SUMSUB_APP_TOKEN    "SUMSUB_APP_TOKEN"
prompt_secret SUMSUB_SECRET_KEY   "SUMSUB_SECRET_KEY"
prompt_secret SUMSUB_WEBHOOK_SECRET "SUMSUB_WEBHOOK_SECRET"
prompt_plain  SUMSUB_LEVEL_NAME   "SUMSUB_LEVEL_NAME (T3 basic level)"   "basic-kyc-level"
prompt_plain  SUMSUB_BASE_URL     "SUMSUB_BASE_URL (blank = default)"    ""

# KYC_WEBHOOK_SECRET: the /kyc/_set stand-in shared secret. Offer to generate.
printf '  Generate a random KYC_WEBHOOK_SECRET? [Y/n]: ' >&2
IFS= read -r GEN || true
if [ "${GEN:-Y}" = "Y" ] || [ "${GEN:-y}" = "y" ] || [ -z "${GEN:-}" ]; then
  KYC_WEBHOOK_SECRET="$(openssl rand -hex 32)"
  echo "    generated (64 hex chars; stored, not shown)." >&2
else
  prompt_secret KYC_WEBHOOK_SECRET "KYC_WEBHOOK_SECRET"
fi

# --- assemble the block (values only ever touch this file) -------------------
KEYS="KYC_PROVIDER SUMSUB_APP_TOKEN SUMSUB_SECRET_KEY SUMSUB_WEBHOOK_SECRET SUMSUB_LEVEL_NAME SUMSUB_BASE_URL KYC_WEBHOOK_SECRET"

write_block() {  # writes the KYC env block to stdout
  printf '# --- COMP-S1 KYC / Sumsub (written by set-kyc-env.sh; DO NOT COMMIT) ---\n'
  printf 'KYC_PROVIDER=%s\n'         "$KYC_PROVIDER"
  printf 'SUMSUB_APP_TOKEN=%s\n'     "$SUMSUB_APP_TOKEN"
  printf 'SUMSUB_SECRET_KEY=%s\n'    "$SUMSUB_SECRET_KEY"
  printf 'SUMSUB_WEBHOOK_SECRET=%s\n' "$SUMSUB_WEBHOOK_SECRET"
  printf 'SUMSUB_LEVEL_NAME=%s\n'    "$SUMSUB_LEVEL_NAME"
  [ -n "$SUMSUB_BASE_URL" ] && printf 'SUMSUB_BASE_URL=%s\n' "$SUMSUB_BASE_URL"
  printf 'KYC_WEBHOOK_SECRET=%s\n'   "$KYC_WEBHOOK_SECRET"
}

if [ "$MODE" = "append" ] && [ -f "$OUT" ]; then
  # Idempotent upsert: strip any existing KYC keys, then append the fresh block.
  tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
  grep -vE "^($(echo "$KEYS" | tr ' ' '|'))=" "$OUT" > "$tmp" || true
  printf '\n' >> "$tmp"
  write_block >> "$tmp"
  mv "$tmp" "$OUT"; chmod 600 "$OUT"
else
  write_block > "$OUT"; chmod 600 "$OUT"
fi

echo "" >&2
echo "✓ wrote KYC env → $OUT (mode 0600). Keys set: $KEYS" >&2
echo "  Values were never printed. The file is gitignored (.env.*)." >&2
echo "  Verify locally (without revealing secrets):  grep -c '=' \"$OUT\"" >&2
