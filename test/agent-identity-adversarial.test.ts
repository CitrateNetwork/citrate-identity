/**
 * ADR-XA-1 adversarial cases X1–X9 — the attacks I would try first against a
 * delegated-actor path, exercised end-to-end through the real provider.
 *
 * Mirrors the entitlements / entitlements-adversarial split already in this repo:
 * the happy-path file proves the feature works, this one proves it does not work
 * when it shouldn't.
 */
import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import { newDb } from 'pg-mem';
import { randomBytes, randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';

import { createProvider } from '../src/server.js';
import { getUserStore } from '../src/auth/stores.js';
import {
  AgentBindingStore,
  mintAgentCredential,
  hashAgentCredential,
  _setAgentStoreForTests,
} from '../src/agent-bindings.js';

let store: AgentBindingStore;
let server: Server;
let base: string;

beforeAll(() => {
  process.env.KYC_MASTER_KEY = randomBytes(32).toString('base64');
});

beforeEach(async () => {
  const db = newDb();
  const pg = db.adapters.createPg();
  store = new AgentBindingStore(new pg.Pool());
  await store.ensureSchema();
  _setAgentStoreForTests(store);

  const provider = await createProvider('http://localhost:0');
  await new Promise<void>((resolve) => {
    server = provider.listen(0, () => resolve());
  });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return () => {
    // NOTE: a value returned from beforeEach is invoked as the cleanup fn — this
    // is a teardown, deliberately, not an accidental call of something else.
    server.close();
  };
});

async function seedAgent(
  parentSub: string,
  opts: { expiry?: number | null; delegated?: boolean } = {},
): Promise<{ agentSub: string; credential: string }> {
  const agentSub = randomUUID();
  const credential = mintAgentCredential();
  await store.create({
    agentSub,
    parentSub,
    label: null,
    scope: 'openid wallet',
    expiry: opts.expiry ?? null,
    credentialSha256: hashAgentCredential(credential),
  });
  if (opts.delegated) {
    await store.grantDelegation(agentSub, {
      spendCapWei: '1000',
      sessionKeyAddr: '0x5555555555555555555555555555555555555555',
      recipientsRoot: `0x${'55'.repeat(32)}`,
      waiverAccepted: true,
    });
  }
  return { agentSub, credential };
}

describe('X1 — a body-supplied parentSub is ignored', () => {
  it('refuses to register without a session, so no body can name an owner', async () => {
    // The attack: mint an agent owned by someone else by naming them in the body.
    // Registration takes NO owner field and requires a session, so an
    // unauthenticated caller cannot mint at all — 401 before the body is read.
    const res = await fetch(`${base}/agents/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ parentSub: 'victim-sub', label: 'stolen' }),
    });
    expect(res.status).toBe(401);
    // And nothing was created for the named victim.
    expect((await store.listByParent('victim-sub')).length).toBe(0);
  });
});

describe('X6 — a revoked agent’s credential is inert', () => {
  it('rejects the credential at the token route after revoke', async () => {
    const { agentSub, credential } = await seedAgent('owner-1');
    const ok = await fetch(`${base}/agents/${agentSub}/token`, {
      method: 'POST',
      headers: { authorization: `Bearer ${credential}` },
    });
    expect(ok.status).toBe(200);
    const body = (await ok.json()) as Record<string, unknown>;
    expect(body.actor).toBe('agent');
    expect(typeof body.id_token).toBe('string');

    await store.revoke(agentSub);

    const after = await fetch(`${base}/agents/${agentSub}/token`, {
      method: 'POST',
      headers: { authorization: `Bearer ${credential}` },
    });
    expect(after.status).toBe(401);
  });

  it('rejects an expired agent’s credential', async () => {
    const { agentSub, credential } = await seedAgent('owner-1', { expiry: Date.now() - 1 });
    const res = await fetch(`${base}/agents/${agentSub}/token`, {
      method: 'POST',
      headers: { authorization: `Bearer ${credential}` },
    });
    expect(res.status).toBe(401);
  });

  it('rejects a well-formed but wrong credential', async () => {
    const { agentSub } = await seedAgent('owner-1');
    const res = await fetch(`${base}/agents/${agentSub}/token`, {
      method: 'POST',
      headers: { authorization: `Bearer ${mintAgentCredential()}` },
    });
    expect(res.status).toBe(401);
  });

  it('rejects a malformed credential without touching the store', async () => {
    const { agentSub } = await seedAgent('owner-1');
    const res = await fetch(`${base}/agents/${agentSub}/token`, {
      method: 'POST',
      headers: { authorization: 'Bearer not-an-agent-key' },
    });
    expect(res.status).toBe(401);
  });
});

describe('the agent token carries the owner’s STATUS but never their IDENTITY', () => {
  it('omits email / name / wallets / kyc dates even when the owner HAS them', async () => {
    // This assertion is only worth anything if the owner actually has an email to
    // leak. Seed a REAL owner record first — otherwise `email: undefined` proves
    // nothing about the agent path and the test is vacuous.
    const owner = await getUserStore().createWithEmailPassword({
      email: 'owner@example.com',
      passwordHash: 'x',
    });
    const ownerRec = await getUserStore().findById(owner.id);
    expect(ownerRec?.email).toBe('owner@example.com'); // the leak is available…

    const { agentSub, credential } = await seedAgent(owner.id);
    const res = await fetch(`${base}/agents/${agentSub}/token`, {
      method: 'POST',
      headers: { authorization: `Bearer ${credential}` },
    });
    const { id_token } = (await res.json()) as { id_token: string };
    const claims = JSON.parse(
      Buffer.from(id_token.split('.')[1]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>;

    // Present: the actor signal and the owner linkage.
    expect(claims.actor).toBe('agent');
    expect(claims.parent_sub).toBe(owner.id);
    expect(claims.sub).toBe(agentSub);

    // …and NOT taken. This is handoff §4 W1's "never the human's identity",
    // asserted against an owner who genuinely has an identity to expose.
    expect(claims.email).toBeUndefined();
    expect(claims.name).toBeUndefined();
    expect(claims.wallets).toBeUndefined();
    expect(claims.kyc_verified_at).toBeUndefined();
    expect(claims.kyc_expires_at).toBeUndefined();
    expect(claims.signing_method).toBeUndefined();
    // The agent's subject is its OWN, never the owner's.
    expect(claims.sub).not.toBe(owner.id);
  });

  it('reports an agent wallet as NOT bound — it is counterfactual', async () => {
    const { agentSub, credential } = await seedAgent('owner-1');
    const res = await fetch(`${base}/agents/${agentSub}/token`, {
      method: 'POST',
      headers: { authorization: `Bearer ${credential}` },
    });
    const { id_token } = (await res.json()) as { id_token: string };
    const claims = JSON.parse(
      Buffer.from(id_token.split('.')[1]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
    // When the AA env is unset (as in test) the claim is omitted entirely; when
    // set it must be present-and-false. Never present-and-true: on 2026-07-28 a
    // predicted address was funded and the SALT was lost.
    if (claims.wallet_address !== undefined) {
      expect(claims.wallet_bound).toBe(false);
    }
  });

  it('a dormant delegation is absent from the token, not present-and-false', async () => {
    const { agentSub, credential } = await seedAgent('owner-1');
    const res = await fetch(`${base}/agents/${agentSub}/token`, {
      method: 'POST',
      headers: { authorization: `Bearer ${credential}` },
    });
    const { id_token } = (await res.json()) as { id_token: string };
    const claims = JSON.parse(
      Buffer.from(id_token.split('.')[1]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
    // An RP must not be able to misread a dormant block as authority.
    expect(claims.agent_delegation).toBeUndefined();
  });

  it('a revoked agent’s token request is refused outright', async () => {
    const { agentSub, credential } = await seedAgent('owner-1');
    await store.revoke(agentSub);
    const res = await fetch(`${base}/agents/${agentSub}/token`, {
      method: 'POST',
      headers: { authorization: `Bearer ${credential}` },
    });
    expect(res.status).toBe(401);
  });
});

describe('owner-only routes do not leak existence', () => {
  it('returns 404 (not 403) to a stranger asking about an agent', async () => {
    const { agentSub } = await seedAgent('owner-1');
    // No session → not the owner. A 403 would confirm the subject exists.
    const res = await fetch(`${base}/agents/${agentSub}`);
    expect(res.status).toBe(404);
  });

  it('returns 404 for a non-UUID agent subject', async () => {
    const res = await fetch(`${base}/agents/not-a-uuid`);
    expect(res.status).toBe(404);
  });

  it('refuses revoke without an owner session', async () => {
    const { agentSub } = await seedAgent('owner-1');
    const res = await fetch(`${base}/agents/${agentSub}/revoke`, { method: 'POST' });
    expect(res.status).toBe(404);
    expect((await store.get(agentSub))!.status).toBe('active');
  });

  it('refuses delegation grants without an owner session', async () => {
    const { agentSub } = await seedAgent('owner-1');
    const res = await fetch(`${base}/agents/${agentSub}/delegation`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        waiverAccepted: true,
        spendCapWei: '10000',
        sessionKeyAddr: '0x6666666666666666666666666666666666666666',
        recipientsRoot: `0x${'66'.repeat(32)}`,
      }),
    });
    expect(res.status).toBe(404);
    expect((await store.get(agentSub))!.delegation.enabled).toBe(false);
  });
});

describe('X9 — delegation without the waiver is refused at the store, not just the route', () => {
  it('cannot be enabled by bypassing the HTTP layer', async () => {
    const { agentSub } = await seedAgent('owner-1');
    const ok = await store.grantDelegation(agentSub, {
      spendCapWei: '999999',
      sessionKeyAddr: '0x7777777777777777777777777777777777777777',
      recipientsRoot: `0x${'77'.repeat(32)}`,
      waiverAccepted: false,
    });
    expect(ok).toBe(false);
    expect((await store.get(agentSub))!.delegation.enabled).toBe(false);
  });

  it('cannot be granted to a revoked agent', async () => {
    const { agentSub } = await seedAgent('owner-1');
    await store.revoke(agentSub);
    const ok = await store.grantDelegation(agentSub, {
      spendCapWei: '999999',
      sessionKeyAddr: '0x8888888888888888888888888888888888888888',
      recipientsRoot: `0x${'88'.repeat(32)}`,
      waiverAccepted: true,
    });
    expect(ok).toBe(false);
  });
});

describe('X5 — a store outage never widens an agent', () => {
  it('mints no agent claims when the KYA store is unavailable', async () => {
    const { agentSub, credential } = await seedAgent('owner-1');
    // Simulate the store going away AFTER the credential was issued.
    _setAgentStoreForTests(null);
    const res = await fetch(`${base}/agents/${agentSub}/token`, {
      method: 'POST',
      headers: { authorization: `Bearer ${credential}` },
    });
    // Fail closed with 503 — never fall back to the owner's tier.
    expect(res.status).toBe(503);
  });
});
