#!/usr/bin/env bash
# Tripwire (2026-09-24 pre-bounty audit, PBA-L8-007 / PBA-L8-021): public docs in
# this repo must not carry operator topology or stale money-contract addresses.
#   - host paths, root SSH procedures, key-derivation formulas and incident notes
#     belong in the private operator runbook;
#   - pre-re-roll vault / SBT / signer addresses have no code on chain 40204, and an
#     operator who copies them points the grant signer at empty contracts.
# Usage: scripts/check-public-runbook.sh [repo-root]   (exit 1 on any hit)
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 || { echo "FAIL - not a git repository: $ROOT"; exit 2; }

PATTERN='/home/[a-z]+/|/Users/[A-Za-z]+/|ssh +root@|keccak256\( *DEPLOYER|DEPLOYER_PRIVATE_KEY *(\|\||\+\+|‖)|bash -x trace|0x61E324cF|0x3e0c2B1c|0x0aceb7B4|0x149E85A3|0x9aFFF274'
# Every tracked text file (docs, service code comments, Dockerfiles, package metadata).
hits=$(git -C "$ROOT" grep -I -n -i -E "$PATTERN" -- . \
    ':!scripts/check-public-runbook.sh' ':!**/node_modules/**' ':!scripts/vendor/**' ':!**/package-lock.json' 2>/dev/null)
if [[ -n "$hits" ]]; then
    echo "FAIL - operator topology or stale money-contract addresses in public docs:"
    echo "$hits" | sed 's/^/       /'
    exit 1
fi
echo "OK - public runbooks carry no ops topology or stale money-contract addresses"
