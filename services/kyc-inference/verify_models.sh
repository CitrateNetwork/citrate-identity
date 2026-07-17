#!/usr/bin/env bash
# Boot-time model-integrity gate (AV-S1). Re-verifies every model file against
# $KYC_MODELS_DIR/MODELS.lock before the service serves. Fail-closed: a missing lock,
# a missing file, or ANY hash mismatch exits non-zero so the container does NOT start
# uvicorn. Wired as the Docker entrypoint (`verify_models.sh && exec uvicorn ...`).
#
# This defends the runtime volume: download_models.sh pins at fetch time, but a mounted
# /models volume could drift or be swapped afterward. This gate catches that at boot.
set -euo pipefail
DEST="${KYC_MODELS_DIR:-/models}"
LOCK="$DEST/MODELS.lock"

[ -f "$LOCK" ] || { echo "[verify] FATAL: no $LOCK — run download_models.sh first" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

rc=0
checked=0
while read -r expected rel; do
  case "$expected" in ''|\#*) continue ;; esac   # skip blanks + comments
  f="$DEST/$rel"
  if [ ! -f "$f" ]; then echo "[verify] MISSING  $rel" >&2; rc=1; continue; fi
  got="$(sha256_of "$f")"
  if [ "$got" != "$expected" ]; then
    echo "[verify] MISMATCH $rel" >&2
    echo "         expected $expected" >&2
    echo "         got      $got" >&2
    rc=1
  else
    echo "[verify] ok       $rel"
    checked=$((checked + 1))
  fi
done < "$LOCK"

if [ "$rc" -ne 0 ] || [ "$checked" -eq 0 ]; then
  echo "[verify] FATAL: model integrity check failed — refusing to start" >&2
  exit 1
fi
echo "[verify] all $checked model file(s) verified against MODELS.lock"
