// Vendor entry: re-export only keccak_256 from @noble/hashes so esbuild
// produces a single self-contained, same-origin ESM module for the
// browser interaction page (no runtime esm.sh / CDN import). See
// scripts/vendor/build.sh. Regenerate after bumping @noble/hashes.
export { keccak_256 } from '@noble/hashes/sha3';
