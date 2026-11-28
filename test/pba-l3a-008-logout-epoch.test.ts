/**
 * PBA-L3a-008 on `POST /logout` and `GET /sessions/events` (#52, PR #54 review).
 *
 * Both routes read the bearer straight from the AccessToken adapter. Under test:
 * a token issued before the account's revocation epoch is refused 401 on both
 * (and /logout publishes nothing), a token issued after it still works, and the
 * check fails closed (epoch-store error, or no iat on a stamped account -> 401).
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type Provider from 'oidc-provider';
import { createProvider } from '../src/server.js';
import {
  InMemoryAccountEpochStore,
  getAccountEpochStore,
  setAccountEpochStore,
} from '../src/auth/account-epoch.js';
import {
  SessionBus,
  getSessionBus,
  setSessionBus,
  type SessionEvent,
} from '../src/session-bus.js';

let server: Server;
let baseUrl: string;
let provider: Provider;

beforeAll(async () => {
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const { port } = probe.address() as AddressInfo;
  probe.close();
  baseUrl = `http://127.0.0.1:${port}`;
  provider = await createProvider(baseUrl, { googleEnabled: false });
  server = createServer(provider.callback());
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
});
afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});
afterEach(() => {
  setAccountEpochStore(new InMemoryAccountEpochStore());
  setSessionBus(new SessionBus());
  vi.restoreAllMocks();
});

const nowSec = () => Math.floor(Date.now() / 1000);

/** A real access token in the authority's adapter, authenticated at `iat`. */
async function mint(accountId: string, iat?: number): Promise<string> {
  const client = await provider.Client.find('citrate-explorer');
  if (!client) throw new Error('client citrate-explorer not registered');
  const at = new provider.AccessToken({
    accountId,
    client,
    scope: 'openid wallet',
    ...(iat !== undefined ? { iat } : {}),
  } as never);
  return at.save();
}

/** Status of GET /sessions/events for this bearer; the stream is closed at once. */
async function subscribeStatus(token: string): Promise<number> {
  const ac = new AbortController();
  const res = await fetch(`${baseUrl}/sessions/events`, {
    headers: { accept: 'text/event-stream', authorization: `Bearer ${token}` },
    signal: ac.signal,
  });
  const status = res.status;
  ac.abort();
  await res.body?.cancel().catch(() => {});
  return status;
}

async function logout(token: string): Promise<Response> {
  return fetch(`${baseUrl}/logout`, { method: 'POST', headers: { authorization: `Bearer ${token}` } });
}

/** Run `fn` while recording every session-bus event. */
async function recording<T>(fn: () => Promise<T>): Promise<{ result: T; events: SessionEvent[] }> {
  const events: SessionEvent[] = [];
  const off = getSessionBus().subscribe((e) => events.push(e));
  try {
    return { result: await fn(), events };
  } finally {
    off();
  }
}

const failingStore = {
  get: async (): Promise<number | undefined> => {
    throw new Error('redis down');
  },
  bump: async (): Promise<number> => {
    throw new Error('redis down');
  },
};

/** Make the adapter hand back tokens without `iat` / `iiat`. */
function stripIat(): void {
  const realFind = provider.AccessToken.find.bind(provider.AccessToken);
  vi.spyOn(provider.AccessToken, 'find').mockImplementation(async (...args: Parameters<typeof realFind>) => {
    const found = await realFind(...args);
    if (found) {
      Object.defineProperty(found, 'iat', { value: undefined });
      Object.defineProperty(found, 'iiat', { value: undefined });
    }
    return found;
  });
}

describe('PBA-L3a-008: GET /sessions/events honours the account epoch', () => {
  it('a token issued before the epoch is refused 401', async () => {
    const old = await mint('sse-epoch-old', nowSec() - 60);
    expect(await subscribeStatus(old)).toBe(200);
    await getAccountEpochStore().bump('sse-epoch-old', nowSec());
    expect(await subscribeStatus(old)).toBe(401);
  });

  it('a token issued after the epoch still subscribes', async () => {
    await getAccountEpochStore().bump('sse-epoch-fresh', nowSec() - 30);
    const fresh = await mint('sse-epoch-fresh');
    expect(await subscribeStatus(fresh)).toBe(200);
  });

  it('fails closed: an epoch-store error refuses 401', async () => {
    const t = await mint('sse-epoch-store-down');
    setAccountEpochStore(failingStore);
    expect(await subscribeStatus(t)).toBe(401);
  });

  it('fails closed: a token with no iat on a stamped account is refused 401', async () => {
    const t = await mint('sse-epoch-no-iat');
    stripIat();
    expect(await subscribeStatus(t)).toBe(200);
    await getAccountEpochStore().bump('sse-epoch-no-iat', nowSec() - 30);
    expect(await subscribeStatus(t)).toBe(401);
  });
});

describe('PBA-L3a-008: POST /logout honours the account epoch', () => {
  it('a token issued before the epoch is refused 401 and publishes nothing', async () => {
    const old = await mint('logout-epoch-old', nowSec() - 60);
    await getAccountEpochStore().bump('logout-epoch-old', nowSec());
    const { result, events } = await recording(() => logout(old));
    expect(result.status).toBe(401);
    expect(await result.json()).toMatchObject({ error: 'invalid_grant' });
    expect(events).toHaveLength(0);
  });

  it('a token issued after the epoch still logs out', async () => {
    await getAccountEpochStore().bump('logout-epoch-fresh', nowSec() - 30);
    const fresh = await mint('logout-epoch-fresh');
    const { result, events } = await recording(() => logout(fresh));
    expect(result.status).toBe(200);
    expect(await result.json()).toMatchObject({ ok: true, sub: 'logout-epoch-fresh' });
    expect(events.map((e) => e.sub)).toEqual(['logout-epoch-fresh']);
  });

  it('fails closed: an epoch-store error refuses 401 and publishes nothing', async () => {
    const t = await mint('logout-epoch-store-down');
    setAccountEpochStore(failingStore);
    const { result, events } = await recording(() => logout(t));
    expect(result.status).toBe(401);
    expect(events).toHaveLength(0);
  });

  it('fails closed: a token with no iat on a stamped account is refused 401', async () => {
    const t = await mint('logout-epoch-no-iat');
    stripIat();
    await getAccountEpochStore().bump('logout-epoch-no-iat', nowSec() - 30);
    const { result, events } = await recording(() => logout(t));
    expect(result.status).toBe(401);
    expect(events).toHaveLength(0);
  });
});
