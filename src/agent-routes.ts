/**
 * Agent identity routes (ADR-XA-1 §4 / handoff W1).
 *
 * `POST   /agents/register`               owner → mint an agent identity
 * `GET    /agents`                        owner → list their agents
 * `GET    /agents/:sub`                   owner or that agent → status
 * `POST   /agents/:sub/delegation`        owner + waiver → grant bounded authority
 * `DELETE /agents/:sub/delegation`        owner → revoke authority, keep identity
 * `POST   /agents/:sub/revoke`            owner → revoke the agent entirely
 * `POST   /agents/:sub/token`             `ag_` credential → agent ID token
 *
 * Auth model mirrors the Account Hub: owner routes read the authority's OIDC
 * session (`provider.Session.get`). The token route is the one exception — an
 * agent runs unattended and has no session, so it presents the `ag_` credential
 * minted at registration.
 *
 * Two invariants are load-bearing and both are enforced here rather than left to
 * a caller:
 *
 *   1. `parent_sub` comes from the AUTHENTICATED principal, never from the request
 *      body. A body-supplied parent would let anyone mint an agent owned by
 *      someone else — that is the whole attack, and it is why registration takes
 *      no owner field at all.
 *   2. Delegation is refused without an explicit liability waiver
 *      (ADR-2026-06-04). The store refuses too, so bypassing this route does not
 *      bypass the waiver.
 */
import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';
import { SignJWT, importJWK, type JWK } from 'jose';
import { isAddress, getAddress } from 'viem';

import {
  getAgentStore,
  mintAgentCredential,
  hashAgentCredential,
  agentCanAct,
  effectiveAgentStatus,
  scopeViolations,
  type AgentBinding,
} from './agent-bindings.js';
import { predictedWalletForAccount } from './aa/wallet-claims.js';
import { findAccount } from './config.js';
import { attestAgentBinding, attestAgentRevoke } from './agent-attest.js';
import type { Account } from 'oidc-provider';

/**
 * The OIDC scopes an owner may grant to an agent.
 *
 * Deliberately NOT the full `scopes_supported`:
 *   - `profile` is excluded — it carries `name`/`email`, i.e. the human's identity,
 *     which handoff §4 W1 forbids an agent token from ever carrying.
 *   - `agent` is excluded — an agent granted `agent` could register sub-agents,
 *     and privilege trees are an explicit non-goal in v1 (ADR-XA-1 §9 / X2).
 *   - `offline_access` is excluded — refresh tokens for an unattended actor
 *     lengthen the blast radius of a leaked credential for no gain; the agent
 *     re-presents its credential instead.
 *
 * This is ADR-XA-1 D9's "scope can only narrow", made concrete without inventing
 * an owner-scope concept the authority does not otherwise model.
 */
export const AGENT_GRANTABLE_SCOPES = ['openid', 'wallet', 'kyc'] as const;

const DEFAULT_AGENT_SCOPE = 'openid wallet';

async function readJson(req: IncomingMessage, maxBytes = 16 * 1024): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const b = chunk as Buffer;
    size += b.length;
    if (size > maxBytes) throw new Error('payload too large');
    chunks.push(b);
  }
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(JSON.stringify(body));
}

/** The `ag_` credential, from `Authorization: Bearer` or `x-citrate-agent-key`. */
function presentedAgentKey(req: IncomingMessage): string | undefined {
  const auth = req.headers['authorization'];
  if (typeof auth === 'string' && auth.startsWith('Bearer ')) return auth.slice(7).trim();
  const h = req.headers['x-citrate-agent-key'];
  if (typeof h === 'string' && h.length > 0) return h;
  return undefined;
}

/** Public projection of a binding — never the credential hash, never the sealed label ciphertext. */
function publicBinding(b: AgentBinding): Record<string, unknown> {
  return {
    agentSub: b.agentSub,
    parentSub: b.parentSub,
    label: b.label,
    scope: b.scope,
    status: effectiveAgentStatus(b),
    expiry: b.expiry,
    walletAddress: predictedWalletForAccount(b.agentSub) ?? null,
    // Always false for a counterfactual address: no key exists for it and no
    // contract is deployed there. An RP that PAYS an agent must require true.
    walletBound: false,
    delegation: {
      enabled: b.delegation.enabled,
      spendCapWei: b.delegation.spendCapWei,
      sessionKeyAddr: b.delegation.sessionKeyAddr,
      recipientsRoot: b.delegation.recipientsRoot,
      waiverAcceptedAt: b.delegation.waiverAcceptedAt,
    },
    kyaDecisionId: b.kyaDecisionId,
    createdAt: b.createdAt,
    revokedAt: b.revokedAt,
  };
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface AgentRouteOptions {
  /** Issuer for minted agent tokens (the authority's own issuer URL). */
  issuer: string;
  /** The ACTIVE signing JWK — same key the authority publishes at /jwks. */
  signingJwk: JWK;
  /** Audience for agent tokens. Defaults to `citrate-agent`. */
  audience?: string;
  /** Agent token TTL in seconds. Defaults to 15 minutes. */
  tokenTtlSeconds?: number;
}

/**
 * Mint an agent ID token signed by the authority's JWKS key.
 *
 * Short-lived by default (15 min vs the 1 h human token): an unattended
 * credential-bearing actor should re-derive its token often, so a revoke lands
 * quickly even for a token already in flight. Revocation is still authoritative
 * at `claims()` time — this just narrows the window.
 */
async function mintAgentToken(
  opts: AgentRouteOptions,
  claims: Record<string, unknown>,
): Promise<{ token: string; expiresIn: number }> {
  const key = await importJWK(opts.signingJwk, 'RS256');
  const now = Math.floor(Date.now() / 1000);
  const ttl = opts.tokenTtlSeconds ?? 15 * 60;
  const token = await new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: opts.signingJwk.kid, typ: 'JWT' })
    .setIssuer(opts.issuer)
    .setAudience(opts.audience ?? 'citrate-agent')
    .setSubject(String(claims.sub))
    .setIssuedAt(now)
    .setExpirationTime(now + ttl)
    .setJti(`${String(claims.sub)}-${now}-${randomUUID()}`)
    .sign(key);
  return { token, expiresIn: ttl };
}

/** Claims for an agent subject, via the same `findAccount` seam humans use. */
async function agentTokenClaims(
  agentSub: string,
  scope: string,
): Promise<Record<string, unknown>> {
  const account = (await findAccount(undefined as never, agentSub, undefined)) as
    | Account
    | undefined;
  if (!account) throw new Error('findAccount did not resolve the agent subject');
  return (await account.claims('id_token', scope, {}, [])) as unknown as Record<
    string,
    unknown
  >;
}

export function mountAgentRoutes(provider: Provider, options: AgentRouteOptions): void {
  provider.use(async (ctx, next) => {
    const path = ctx.path;
    if (!path.startsWith('/agents')) return next();

    const store = await getAgentStore();
    if (!store) {
      // Fail closed, matching how the KYC/entitlement surfaces behave without a
      // DATABASE_URL. Never mint an identity we cannot durably bind or revoke.
      sendJson(ctx.res, 503, {
        error: 'no_store',
        reason: 'agent bindings store not configured (no DATABASE_URL)',
      });
      return;
    }

    /** The authenticated OWNER, or undefined. */
    const ownerSub = async (): Promise<string | undefined> => {
      try {
        const session = await provider.Session.get(ctx);
        return session?.accountId;
      } catch {
        return undefined;
      }
    };

    // ---- POST /agents/register ------------------------------------------
    if (ctx.method === 'POST' && path === '/agents/register') {
      const owner = await ownerSub();
      if (!owner) {
        sendJson(ctx.res, 401, { error: 'unauthorized', reason: 'sign in first' });
        return;
      }

      // X2: an agent may not register sub-agents. Checked against the KYA store
      // rather than the token, so a stolen agent token cannot mint a tree either.
      if (await store.get(owner)) {
        sendJson(ctx.res, 403, {
          error: 'forbidden',
          reason: 'an agent cannot register agents (no delegation trees in v1)',
        });
        return;
      }

      let body: Record<string, unknown>;
      try {
        body = (await readJson(ctx.req)) as Record<string, unknown>;
      } catch {
        sendJson(ctx.res, 400, { error: 'invalid_request', reason: 'bad_body' });
        return;
      }

      // NOTE: no `parentSub` is read from the body — by design. Any such field is
      // ignored rather than honoured (adversarial X1).
      const label = typeof body.label === 'string' ? body.label.slice(0, 200) : null;
      const requestedScope =
        typeof body.scope === 'string' && body.scope.trim() !== ''
          ? body.scope.trim()
          : DEFAULT_AGENT_SCOPE;

      const bad = scopeViolations(requestedScope, AGENT_GRANTABLE_SCOPES.join(' '));
      if (bad.length > 0) {
        // 403 rather than a silent trim (D9): over-asking must be visible.
        sendJson(ctx.res, 403, {
          error: 'scope_not_grantable',
          reason: `these scopes cannot be granted to an agent: ${bad.join(', ')}`,
          grantable: AGENT_GRANTABLE_SCOPES,
        });
        return;
      }

      let expiry: number | null = null;
      if (body.expiry != null) {
        const t = new Date(String(body.expiry)).getTime();
        if (Number.isNaN(t)) {
          sendJson(ctx.res, 400, {
            error: 'invalid_request',
            reason: 'expiry must be an ISO-8601 string',
          });
          return;
        }
        expiry = t;
      }

      const agentSub = randomUUID();
      const credential = mintAgentCredential();
      try {
        await store.create({
          agentSub,
          parentSub: owner,
          label,
          scope: requestedScope,
          expiry,
          credentialSha256: hashAgentCredential(credential),
        });
      } catch (err) {
        // The one expected failure is a label with no master key configured —
        // agent-bindings throws rather than silently dropping the caller's data.
        sendJson(ctx.res, 500, {
          error: 'create_failed',
          reason: err instanceof Error ? err.message : 'unknown',
        });
        return;
      }

      // KYA attestation is best-effort and reports HONESTLY: `registerDecision`
      // is onlyAuthorizedRecorder, and until governance authorizes our signer it
      // cannot write. Never claim an attestation that did not happen.
      const attested = await attestAgentBinding({
        agentSub,
        parentSub: owner,
        scope: requestedScope,
        expiry,
      });
      if (attested) await store.setKyaDecisionId(agentSub, attested);

      const created = await store.get(agentSub);
      sendJson(ctx.res, 201, {
        ...(created ? publicBinding(created) : { agentSub }),
        // Returned EXACTLY once — only the SHA-256 is persisted.
        credential,
        credentialNote:
          'Store this now. It is shown once and cannot be recovered; only its hash is kept.',
        kyaAttested: attested != null,
        ...(attested == null
          ? {
              kyaNote:
                'Binding recorded off-chain. On-chain KYA attestation is pending: the ' +
                'identity signer is not yet an authorized recorder on AgentDecisionRegistry.',
            }
          : {}),
      });
      return;
    }

    // ---- GET /agents -----------------------------------------------------
    if (ctx.method === 'GET' && path === '/agents') {
      const owner = await ownerSub();
      if (!owner) {
        sendJson(ctx.res, 401, { error: 'unauthorized', reason: 'sign in first' });
        return;
      }
      const list = await store.listByParent(owner);
      sendJson(ctx.res, 200, { agents: list.map(publicBinding) });
      return;
    }

    // ---- /agents/:sub[/...] ---------------------------------------------
    const m = /^\/agents\/([^/]+)(\/[a-z]+)?$/.exec(path);
    if (!m) return next();
    const agentSub = decodeURIComponent(m[1]!);
    const leaf = m[2] ?? '';

    if (!UUID_RE.test(agentSub)) {
      sendJson(ctx.res, 404, { error: 'not_found' });
      return;
    }

    // ---- POST /agents/:sub/token (credential-authenticated) --------------
    if (ctx.method === 'POST' && leaf === '/token') {
      const key = presentedAgentKey(ctx.req);
      if (!key) {
        sendJson(ctx.res, 401, {
          error: 'unauthorized',
          reason: 'present the agent credential as a bearer token',
        });
        return;
      }
      // verifyCredential fails closed on a revoked/expired binding BEFORE the
      // hash compare, so a leaked credential for a revoked agent is inert (X6).
      const binding = await store.verifyCredential(agentSub, key);
      if (!binding) {
        sendJson(ctx.res, 401, { error: 'unauthorized', reason: 'invalid agent credential' });
        return;
      }
      const claims = await agentTokenClaims(agentSub, `${binding.scope} agent`);
      const { token, expiresIn } = await mintAgentToken(options, claims);
      sendJson(ctx.res, 200, {
        id_token: token,
        token_type: 'Bearer',
        expires_in: expiresIn,
        actor: 'agent',
        scope: binding.scope,
      });
      return;
    }

    // Everything below is OWNER-only. Load the binding, then check ownership.
    const binding = await store.get(agentSub);
    if (!binding) {
      sendJson(ctx.res, 404, { error: 'not_found' });
      return;
    }
    const owner = await ownerSub();

    // ---- GET /agents/:sub (owner OR that agent) --------------------------
    if (ctx.method === 'GET' && leaf === '') {
      const key = presentedAgentKey(ctx.req);
      const selfAuthenticated =
        key != null && (await store.verifyCredential(agentSub, key)) != null;
      if (!selfAuthenticated && owner !== binding.parentSub) {
        // 404 rather than 403: a caller who is neither the owner nor the agent
        // should not learn that this subject exists.
        sendJson(ctx.res, 404, { error: 'not_found' });
        return;
      }
      sendJson(ctx.res, 200, publicBinding(binding));
      return;
    }

    if (!owner || owner !== binding.parentSub) {
      sendJson(ctx.res, 404, { error: 'not_found' });
      return;
    }

    // ---- POST /agents/:sub/revoke ---------------------------------------
    if (ctx.method === 'POST' && leaf === '/revoke') {
      const changed = await store.revoke(agentSub);
      // Attest the revoke so the audit trail shows authority ending, not just
      // beginning. Prior actions stay attributable — the registry is append-only.
      const attested = changed ? await attestAgentRevoke({ agentSub }) : null;
      sendJson(ctx.res, 200, {
        agentSub,
        status: 'revoked',
        changed,
        kyaAttested: attested != null,
      });
      return;
    }

    // ---- POST /agents/:sub/delegation -----------------------------------
    if (ctx.method === 'POST' && leaf === '/delegation') {
      let body: Record<string, unknown>;
      try {
        body = (await readJson(ctx.req)) as Record<string, unknown>;
      } catch {
        sendJson(ctx.res, 400, { error: 'invalid_request', reason: 'bad_body' });
        return;
      }

      // ADR-2026-06-04: delegation is permitted ONLY behind an explicit
      // liability waiver. Refused here AND in the store (X9).
      if (body.waiverAccepted !== true) {
        sendJson(ctx.res, 400, {
          error: 'waiver_required',
          reason:
            'Delegating spend authority to an agent requires accepting the ' +
            'liability waiver (ADR-2026-06-04). Send waiverAccepted: true.',
        });
        return;
      }

      const cap = String(body.spendCapWei ?? '');
      if (!/^[0-9]+$/.test(cap) || cap === '0') {
        sendJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'spendCapWei must be a positive integer string (wei)',
        });
        return;
      }
      const sk = String(body.sessionKeyAddr ?? '');
      if (!isAddress(sk)) {
        sendJson(ctx.res, 400, {
          error: 'invalid_request',
          reason: 'sessionKeyAddr must be a 20-byte address',
        });
        return;
      }
      const root = String(body.recipientsRoot ?? '');
      if (!/^0x[0-9a-fA-F]{64}$/.test(root)) {
        sendJson(ctx.res, 400, {
          error: 'invalid_request',
          reason:
            'recipientsRoot must be a 32-byte hex merkle root of the recipient allow-list',
        });
        return;
      }

      if (!agentCanAct(binding)) {
        sendJson(ctx.res, 409, {
          error: 'not_active',
          reason: `agent is ${effectiveAgentStatus(binding)}`,
        });
        return;
      }

      const ok = await store.grantDelegation(agentSub, {
        spendCapWei: cap,
        sessionKeyAddr: getAddress(sk),
        recipientsRoot: root,
        waiverAccepted: true,
      });
      if (!ok) {
        sendJson(ctx.res, 409, { error: 'not_active', reason: 'agent is not active' });
        return;
      }
      const updated = await store.get(agentSub);
      sendJson(ctx.res, 200, {
        ...(updated ? publicBinding(updated) : { agentSub }),
        // The authority records the bound; the VALIDATOR enforces it. Say so, so
        // nobody reads this response as "the cap is now in force on-chain".
        enforcementNote:
          'This records the delegation bound. It is enforced on-chain by ' +
          'AgentSessionKeyValidator once installed on the wallet — install it, or ' +
          'the cap is advisory only.',
      });
      return;
    }

    // ---- DELETE /agents/:sub/delegation ---------------------------------
    if (ctx.method === 'DELETE' && leaf === '/delegation') {
      const changed = await store.revokeDelegation(agentSub);
      sendJson(ctx.res, 200, {
        agentSub,
        delegation: { enabled: false },
        changed,
        note: 'Spend authority revoked. The agent keeps its identity (ADR-XA-1 D1). ' +
          'Uninstall the on-chain validator to end authority on-chain as well.',
      });
      return;
    }

    return next();
  });
}
