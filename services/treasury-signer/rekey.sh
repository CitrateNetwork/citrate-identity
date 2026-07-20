#!/usr/bin/env bash
# rekey.sh — rotate the treasury-signer to a new grant signer + new pinned
# contracts, run ON THE DROPLET. Used at reroll PHASE 3.5 after the new
# CitrateMemberSBT + MembershipStakeVault are deployed (they must already have
# code on-chain, or /health broadcasts will later revert onlyOwner).
#
# WHY A REKEY IS NEEDED: every operator key is
#   keccak256(DEPLOYER_PRIVATE_KEY ‖ label)
# so the deployer-key leak transitively compromised the OLD grant signer
# (0x9aFFF274…). The reroll rotates the deployer, so the grant signer becomes
# 0xF42a19194fee89E71dC4b8631a71a9CeCf42B483 — the owner baked into the new
# SBT/vault CREATE2 addresses (DeployCoreMembership.FROZEN_OWNER). This rekey is
# PURELY an off-chain credential swap: it changes NO on-chain address, NO genesis,
# NO CREATE2 projection, NO node sync — the service is a downstream *consumer* of
# the addresses the build already froze.
#
# SECURITY: the private key is read from STDIN only — never passed on argv, never
# echoed, never written to a log. The env-file is chmod 600 and patched in place
# atomically.
#
# Usage (on the droplet):
#   NEW_VAULT=0x61E324cFd6B7Cb106AC0AD1dF163bdFef2b74268 \
#   NEW_SBT=0x3e0c2B1cD29a615E4eA2E263C8e7df3Aef243E42 \
#     bash rekey.sh < /secure/path/to/new_grant_signer_privkey.hex
#
# Secure key transfer from the DGX (key never hits a terminal/log):
#   grep -m1 '^GRANT_SIGNER_PRIVATE_KEY=' /home/saul/Projects/Citrate-Labs/.env.testnet \
#     | cut -d= -f2 | ssh root@<droplet> \
#       'NEW_VAULT=0x61E3… NEW_SBT=0x3e0c… bash /opt/citrate-treasury-signer/rekey.sh'
set -euo pipefail

ENV_FILE="${TREASURY_ENV_FILE:-/etc/citrate-treasury-signer.env}"
PORT="${PORT:-8790}"
CONTAINER="${TREASURY_CONTAINER:-citrate-treasury-signer}"
IMAGE="${TREASURY_IMAGE:-citrate-treasury-signer:latest}"
STATE_DIR="${TREASURY_STATE_DIR:-/var/lib/citrate-treasury-signer}"

[ -n "${NEW_VAULT:-}" ] || { echo "NEW_VAULT (new MembershipStakeVault) is required" >&2; exit 2; }
[ -n "${NEW_SBT:-}" ]   || { echo "NEW_SBT (new CitrateMemberSBT) is required" >&2; exit 2; }
[ -f "$ENV_FILE" ]      || { echo "env-file $ENV_FILE not found" >&2; exit 2; }

# read the new private key from stdin ONLY (never argv/env-echo)
if [ -t 0 ]; then echo "refusing: pipe the new grant-signer private key on STDIN" >&2; exit 2; fi
read -r NEW_KEY
[ -n "$NEW_KEY" ] || { echo "empty key on STDIN" >&2; exit 2; }
case "$NEW_KEY" in 0x*) : ;; *) NEW_KEY="0x$NEW_KEY" ;; esac

# --- patch env-file atomically (preserve perms/owner) ---------------------
umask 077
TMP="$(mktemp "${ENV_FILE}.rekey.XXXXXX")"
cp --preserve=mode,ownership "$ENV_FILE" "$TMP"
setk() { # key value  -> set-or-append in $TMP
  if grep -q "^$1=" "$TMP"; then
    # value may contain / and & — use a non-/ delimiter and escape & \ |
    local esc; esc=$(printf '%s' "$2" | sed -e 's/[\\&|]/\\&/g')
    sed -i "s|^$1=.*|$1=$esc|" "$TMP"
  else
    printf '%s=%s\n' "$1" "$2" >> "$TMP"
  fi
}
setk TREASURY_SIGNER_KEY "$NEW_KEY"
setk MEMBERSHIP_STAKE_VAULT_ADDRESS "$NEW_VAULT"
setk CITRATE_MEMBER_SBT_ADDRESS "$NEW_SBT"
NEW_KEY=""   # scrub from shell memory
mv "$TMP" "$ENV_FILE"
chmod 600 "$ENV_FILE"
echo "[rekey] env-file patched (key redacted): vault=$NEW_VAULT sbt=$NEW_SBT"

# --- recreate the container (docker) OR restart the unit (systemd) ---------
# GOTCHA: `docker restart` does NOT re-read --env-file — the container must be
# removed and re-run for new env to take effect.
if command -v docker >/dev/null 2>&1 && docker inspect "$CONTAINER" >/dev/null 2>&1; then
  echo "[rekey] recreating docker container $CONTAINER (restart won't re-read --env-file)"
  docker rm -f "$CONTAINER" >/dev/null
  docker run -d --name "$CONTAINER" --restart unless-stopped \
    -p 127.0.0.1:"$PORT":"$PORT" \
    --env-file "$ENV_FILE" \
    -v "$STATE_DIR":"$STATE_DIR" \
    "$IMAGE" >/dev/null
elif command -v systemctl >/dev/null 2>&1; then
  echo "[rekey] restarting systemd unit citrate-treasury-signer"
  systemctl restart citrate-treasury-signer
else
  echo "[rekey] WARNING: neither docker container nor systemd unit found — restart the service manually" >&2
fi

# --- verify /health reflects the new signer + pinned contracts -------------
sleep 3
HEALTH="$(curl -s -m5 "http://127.0.0.1:${PORT}/health" || true)"
echo "[rekey] /health: $HEALTH"
EXPECT_SIGNER="0xF42a19194fee89E71dC4b8631a71a9CeCf42B483"
lc() { printf '%s' "$1" | tr 'A-F' 'a-f'; }
ok=1
echo "$HEALTH" | grep -qi "$(lc "$EXPECT_SIGNER")" || { echo "[rekey] FAIL: signer != $EXPECT_SIGNER" >&2; ok=0; }
echo "$HEALTH" | grep -qi "$(lc "$NEW_VAULT")"     || { echo "[rekey] FAIL: vault != $NEW_VAULT" >&2; ok=0; }
echo "$HEALTH" | grep -qi "$(lc "$NEW_SBT")"       || { echo "[rekey] FAIL: sbt != $NEW_SBT" >&2; ok=0; }
[ "$ok" = 1 ] && echo "[rekey] ✅ signer=$EXPECT_SIGNER now owns vault=$NEW_VAULT sbt=$NEW_SBT" || { echo "[rekey] ✗ verification failed" >&2; exit 3; }
