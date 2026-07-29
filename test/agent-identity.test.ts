/**
 * ADR-XA-1 / handoff W1 — agent identity + KYA, acceptance A1–A4.
 *
 * A5 (Rule-8 external security review) is a human/process gate and is recorded in
 * the sprint, not asserted here.
 *
 * These are STORE + CLAIMS-level assertions. The on-chain half of A3 (the N+1
 * spend rejected by the validator) is a Forge test in citrate-chain — it cannot be
 * proven from TypeScript, and asserting a client-side cap here would prove exactly
 * the wrong thing.
 */
import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import { newDb } from 'pg-mem';
import { randomBytes, randomUUID } from 'node:crypto';

import {
  AgentBindingStore,
  mintAgentCredential,
  hashAgentCredential,
  looksLikeAgentCredential,
  effectiveAgentStatus,
  agentCanAct,
  agentCanSpend,
  scopeViolations,
  _setAgentStoreForTests,
} from '../src/agent-bindings.js';
import type { PgLike } from '../src/entitlements.js';

let store: AgentBindingStore;

beforeAll(() => {
  // Label sealing needs the master key; the rest of the store works without it.
  process.env.KYC_MASTER_KEY = randomBytes(32).toString('base64');
});

beforeEach(async () => {
  const db = newDb();
  const pg = db.adapters.createPg();
  store = new AgentBindingStore(new pg.Pool());
  await store.ensureSchema();
  _setAgentStoreForTests(store);
});

async function register(
  parentSub: string,
  opts: { label?: string; scope?: string; expiry?: number | null } = {},
): Promise<{ agentSub: string; credential: string }> {
  const agentSub = randomUUID();
  const credential = mintAgentCredential();
  await store.create({
    agentSub,
    parentSub,
    label: opts.label ?? null,
    scope: opts.scope ?? 'openid wallet',
    expiry: opts.expiry ?? null,
    credentialSha256: hashAgentCredential(credential),
  });
  return { agentSub, credential };
}

describe('A1 — an owner registers an agent', () => {
  it('mints a binding owned by the authenticated parent', async () => {
    const { agentSub } = await register('owner-uuid-1');
    const b = await store.get(agentSub);
    expect(b).not.toBeNull();
    expect(b!.parentSub).toBe('owner-uuid-1');
    expect(b!.status).toBe('active');
    expect(agentCanAct(b!)).toBe(true);
  });

  it('grants NO spending authority at registration (ADR-2026-06-04 keyless default)', async () => {
    const { agentSub } = await register('owner-uuid-1');
    const b = await store.get(agentSub);
    // This is the single most important assertion in the file: identity must not
    // imply authority, or the "discouraged" delegation path becomes the default.
    expect(b!.delegation.enabled).toBe(false);
    expect(b!.delegation.spendCapWei).toBeNull();
    expect(b!.delegation.waiverAcceptedAt).toBeNull();
    expect(agentCanSpend(b!)).toBe(false);
  });

  it('seals the label at rest and opens it on read', async () => {
    const { agentSub } = await register('owner-uuid-1', { label: "Larry's trading bot" });
    const b = await store.get(agentSub);
    expect(b!.label).toBe("Larry's trading bot");
  });

  it('persists only the credential HASH — a DB dump cannot be replayed', async () => {
    const { agentSub, credential } = await register('owner-uuid-1');
    const raw = await (store as unknown as { pool: PgLike }).pool.query(
      'SELECT credential_sha256 FROM agent_bindings WHERE agent_sub = $1',
      [agentSub],
    );
    const stored = String(raw.rows[0]!.credential_sha256);
    expect(stored).toBe(hashAgentCredential(credential));
    expect(stored).not.toContain(credential);
    expect(credential).toMatch(/^ag_/);
    expect(looksLikeAgentCredential(credential)).toBe(true);
  });

  it('lists an owner’s agents without leaking another owner’s', async () => {
    await register('owner-A');
    await register('owner-A');
    await register('owner-B');
    expect((await store.listByParent('owner-A')).length).toBe(2);
    expect((await store.listByParent('owner-B')).length).toBe(1);
  });
});

describe('A2 — the owner’s verification gates the agent', () => {
  it('scopeViolations reports over-asking instead of silently trimming', () => {
    // D9: a silent trim teaches callers that over-asking is free and hides an
    // escalation attempt that should surface as a 403.
    expect(scopeViolations('openid wallet', 'openid wallet kyc')).toEqual([]);
    expect(scopeViolations('openid profile', 'openid wallet kyc')).toEqual(['profile']);
    expect(scopeViolations('openid agent', 'openid wallet kyc')).toEqual(['agent']);
  });
});

describe('A3 — delegation is bounded and waiver-gated (authority-side half)', () => {
  it('refuses delegation without the liability waiver', async () => {
    const { agentSub } = await register('owner-uuid-1');
    const ok = await store.grantDelegation(agentSub, {
      spendCapWei: '1000',
      sessionKeyAddr: '0x1111111111111111111111111111111111111111',
      recipientsRoot: `0x${'11'.repeat(32)}`,
      waiverAccepted: false,
    });
    expect(ok).toBe(false);
    const b = await store.get(agentSub);
    expect(b!.delegation.enabled).toBe(false);
  });

  it('records the bound and the waiver timestamp when granted', async () => {
    const { agentSub } = await register('owner-uuid-1');
    const ok = await store.grantDelegation(agentSub, {
      spendCapWei: '25000000000000000000',
      sessionKeyAddr: '0x2222222222222222222222222222222222222222',
      recipientsRoot: `0x${'22'.repeat(32)}`,
      waiverAccepted: true,
    });
    expect(ok).toBe(true);
    const b = await store.get(agentSub);
    expect(b!.delegation.enabled).toBe(true);
    expect(b!.delegation.spendCapWei).toBe('25000000000000000000');
    expect(b!.delegation.waiverAcceptedAt).not.toBeNull();
    expect(agentCanSpend(b!)).toBe(true);
  });

  it('revoking delegation keeps identity — the D1 asymmetry', async () => {
    const { agentSub } = await register('owner-uuid-1');
    await store.grantDelegation(agentSub, {
      spendCapWei: '1000',
      sessionKeyAddr: '0x3333333333333333333333333333333333333333',
      recipientsRoot: `0x${'33'.repeat(32)}`,
      waiverAccepted: true,
    });
    expect(await store.revokeDelegation(agentSub)).toBe(true);
    const b = await store.get(agentSub);
    expect(agentCanSpend(b!)).toBe(false);
    // Identity survives — revoking spend must never be mistaken for revoking the agent.
    expect(agentCanAct(b!)).toBe(true);
    expect(b!.delegation.spendCapWei).toBeNull();
  });
});

describe('A4 — revoke fails closed, prior records survive', () => {
  it('revokes identity and authority together', async () => {
    const { agentSub } = await register('owner-uuid-1');
    await store.grantDelegation(agentSub, {
      spendCapWei: '1000',
      sessionKeyAddr: '0x4444444444444444444444444444444444444444',
      recipientsRoot: `0x${'44'.repeat(32)}`,
      waiverAccepted: true,
    });
    expect(await store.revoke(agentSub)).toBe(true);
    const b = await store.get(agentSub);
    expect(effectiveAgentStatus(b!)).toBe('revoked');
    expect(agentCanAct(b!)).toBe(false);
    expect(agentCanSpend(b!)).toBe(false);
    expect(b!.revokedAt).not.toBeNull();
  });

  it('is idempotent', async () => {
    const { agentSub } = await register('owner-uuid-1');
    expect(await store.revoke(agentSub)).toBe(true);
    expect(await store.revoke(agentSub)).toBe(false);
  });

  it('rejects the credential after revoke', async () => {
    const { agentSub, credential } = await register('owner-uuid-1');
    expect(await store.verifyCredential(agentSub, credential)).not.toBeNull();
    await store.revoke(agentSub);
    expect(await store.verifyCredential(agentSub, credential)).toBeNull();
  });

  it('keeps the KYA decision id after revoke so prior actions stay attributable', async () => {
    const { agentSub } = await register('owner-uuid-1');
    await store.setKyaDecisionId(agentSub, '42');
    await store.revoke(agentSub);
    const b = await store.get(agentSub);
    expect(b!.kyaDecisionId).toBe('42');
  });
});

describe('expiry is derived, not stored', () => {
  it('reports expired once the instant passes, without a sweeper', async () => {
    const { agentSub } = await register('owner-uuid-1', { expiry: Date.now() - 1000 });
    const b = await store.get(agentSub);
    // status column still says 'active' — the DERIVED status is what gates.
    expect(b!.status).toBe('active');
    expect(effectiveAgentStatus(b!)).toBe('expired');
    expect(agentCanAct(b!)).toBe(false);
  });

  it('a future expiry is still active', async () => {
    const { agentSub } = await register('owner-uuid-1', { expiry: Date.now() + 60_000 });
    const b = await store.get(agentSub);
    expect(agentCanAct(b!)).toBe(true);
  });

  it('rejects an expired agent’s credential', async () => {
    const { agentSub, credential } = await register('owner-uuid-1', {
      expiry: Date.now() - 1,
    });
    expect(await store.verifyCredential(agentSub, credential)).toBeNull();
  });
});
