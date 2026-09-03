#!/usr/bin/env bash
# local-ci.sh — run the CI gates locally (GitHub Actions org-wide dead since ~2026-07-18).
# JS/TS gates: typecheck, lint, test, build (only those that exist as package.json scripts).
# --fast = typecheck+lint. Installed via install-hooks.sh. Exit 0 all pass / 1 a gate failed.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; cd "$ROOT"
FAST=0
while [ $# -gt 0 ]; do case "$1" in
  --fast) FAST=1; shift;; --list) echo "gates: deps, typecheck, lint, test, build"; exit 0;;
  -h|--help) sed -n '2,4p' "$0"; exit 0;; *) echo "unknown arg: $1" >&2; exit 1;; esac; done
B=$'\033[1m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; X=$'\033[0m'; [ -t 1 ] || { B=""; R=""; G=""; Y=""; X=""; }
PM=npm; [ -f pnpm-lock.yaml ] && PM=pnpm; [ -f yarn.lock ] && PM=yarn
declare -a N=() S=(); FAILED=0
gate(){ local n="$1"; shift; printf "%s▶ %s%s\n" "$B" "$n" "$X"; local o; o="$("$@" 2>&1)"; local rc=$?
  if [ $rc -eq 0 ]; then N+=("$n"); S+=("PASS"); printf "  %sPASS%s\n" "$G" "$X"
  else N+=("$n"); S+=("FAIL"); FAILED=1; printf "  %sFAIL%s\n" "$R" "$X"; echo "$o" | tail -25 | sed 's/^/    /'; fi; }
skip(){ N+=("$1"); S+=("SKIP"); printf "%s▶ %s%s\n  %sSKIP%s — %s\n" "$B" "$1" "$X" "$Y" "$X" "$2"; }
has(){ node -e "process.exit(require('./package.json').scripts?.['$1']?0:1)" 2>/dev/null; }
if [ ! -d node_modules ]; then skip "deps" "node_modules absent — run '$PM install' to enable gates"; else
  for g in typecheck lint; do has "$g" && gate "$g" $PM run "$g" || skip "$g" "no '$g' script"; done
  if [ "$FAST" -eq 0 ]; then
    for g in test build; do has "$g" && gate "$g" $PM run "$g" || skip "$g" "no '$g' script"; done
  fi
fi
echo; echo "──── local CI summary ────"
for i in "${!N[@]}"; do c="$G"; [ "${S[$i]}" = FAIL ] && c="$R"; [ "${S[$i]}" = SKIP ] && c="$Y"; printf "  %s%-6s%s %s\n" "$c" "${S[$i]}" "$X" "${N[$i]}"; done
[ "$FAILED" -eq 0 ] && { echo "${G}LOCAL CI PASSED${X}"; exit 0; } || { echo "${R}LOCAL CI FAILED${X}"; exit 1; }
