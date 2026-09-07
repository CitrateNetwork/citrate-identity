// Vendor entry: re-export EthereumProvider so esbuild produces a single
// self-contained, same-origin ESM module for the browser interaction page
// (no runtime esm.sh / CDN import). Regenerate via scripts/vendor/build.sh.
export { EthereumProvider } from '@walletconnect/ethereum-provider';
