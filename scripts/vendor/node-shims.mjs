// esbuild --inject shim: supplies the Node globals the WalletConnect browser
// build still references (Buffer/process/global) so the vendored bundle is
// self-contained and needs no runtime CDN polyfill. Injected only into the
// WalletConnect bundle (see scripts/vendor/build.sh).
import { Buffer as _Buffer } from 'buffer';
export { _Buffer as Buffer };
export const global = globalThis;
export const process = {
  env: { NODE_ENV: 'production' },
  browser: true,
  version: '',
  nextTick: (fn, ...args) => queueMicrotask(() => fn(...args)),
};
