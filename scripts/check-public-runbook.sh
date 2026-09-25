#!/usr/bin/env bash
# Public-claims accuracy tripwire: public files in this repo must not carry operator
# topology or stale money-contract addresses.
#   - host paths, root SSH/SCP procedures and key-derivation formulas belong in the
#     private operator runbook;
#   - pre-re-roll vault / SBT / signer addresses have no code on chain 40204, and an
#     operator who copies them points the grant signer at empty contracts. They are
#     matched by the SHA-256 of their lowercase 10-character prefix, so this script
#     does not republish them.
# Usage: scripts/check-public-runbook.sh [repo-root]   (exit 1 on any hit)
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 || { echo "FAIL - not a git repository: $ROOT"; exit 2; }

EXCLUDES=(':!scripts/check-public-runbook.sh' ':!**/node_modules/**' ':!scripts/vendor/**' ':!**/package-lock.json')
PATTERN='/home/[a-z]+/|/Users/[A-Za-z]+/|(ssh|scp)[^|;]*root@|root@[a-z0-9.-]+:/root/|keccak256\( *DEPLOYER|DEPLOYER_PRIVATE_KEY *(\|\||\+\+|‖)|keccak\w*( hash)? (of|over) the deployer'
fail=0
hits=$(git -C "$ROOT" grep -I -n -i -E "$PATTERN" -- . "${EXCLUDES[@]}" 2>/dev/null)
if [[ -n "$hits" ]]; then
    echo "FAIL - operator topology in public files:"
    echo "$hits" | sed 's/^/       /'
    fail=1
fi

# Stale money-contract addresses, by hashed 10-char prefix.
STALE_HASHES="92ae0c0fb545461a 6d5a791dac330625 720b7e15f122f17f ee0cd300fa884372 7d7b42e09894f3dc"
stale=$(git -C "$ROOT" grep -I -n -o -i -E '0x[0-9a-f]{8}' -- . "${EXCLUDES[@]}" 2>/dev/null | python3 -c '
import hashlib, sys
bad = set(sys.argv[1].split())
for line in sys.stdin:
    loc, _, tok = line.rstrip("\n").rpartition(":")
    if hashlib.sha256(tok.lower().encode()).hexdigest()[:16] in bad:
        print(f"{loc}: stale pre-re-roll money-contract address")
' "$STALE_HASHES")
if [[ -n "$stale" ]]; then
    echo "FAIL - stale money-contract addresses in public files:"
    echo "$stale" | sed 's/^/       /'
    fail=1
fi
[[ $fail -eq 0 ]] && echo "OK - public files carry no ops topology or stale money-contract addresses"
exit $fail
