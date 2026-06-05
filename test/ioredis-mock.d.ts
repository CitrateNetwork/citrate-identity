/**
 * Ambient types for `ioredis-mock` (it ships none).
 *
 * The mock is an in-process, drop-in `ioredis` replacement, so we type its
 * default export as the real `ioredis` `Redis` constructor — the surface the
 * authority's stores/adapter consume (`RedisLike`) is a subset of it, so a mock
 * instance is assignable wherever a real client is. Tests use it to exercise the
 * Redis nonce store / session bus / panva adapter fully offline.
 */
declare module 'ioredis-mock' {
  import type { Redis } from 'ioredis';
  const RedisMock: new (...args: unknown[]) => Redis;
  export default RedisMock;
}
