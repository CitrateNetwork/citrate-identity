#!/usr/bin/env bash
# Regenerate the self-hosted, same-origin browser vendor bundles served from
# /vendor/* by the interaction page. This removes all runtime third-party CDN
# (esm.sh) imports from the auth origin — see ID-B-004. Run after bumping
# @noble/hashes or @walletconnect/ethereum-provider.
#
#   @walletconnect/ethereum-provider is NOT a runtime dependency of the server;
#   install it transiently only to build the bundle:
#     npm install --no-save @walletconnect/ethereum-provider@2.24.0
#     scripts/vendor/build.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
ESBUILD=node_modules/.bin/esbuild
mkdir -p public/vendor

# keccak-256 (EIP-55 checksum) — pure JS, no shims needed.
"$ESBUILD" scripts/vendor/noble-sha3-entry.mjs \
  --bundle --format=esm --minify --target=es2020 \
  --outfile=public/vendor/noble-sha3.mjs

# WalletConnect Ethereum provider — browser platform + node global shims.
"$ESBUILD" scripts/vendor/walletconnect-entry.mjs \
  --bundle --format=esm --minify --target=es2020 --platform=browser \
  --define:process.env.NODE_ENV='"production"' \
  --inject:scripts/vendor/node-shims.mjs \
  --outfile=public/vendor/walletconnect-ethereum-provider.mjs

echo "vendored: public/vendor/noble-sha3.mjs public/vendor/walletconnect-ethereum-provider.mjs"
