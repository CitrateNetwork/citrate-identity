/**
 * Exact callbacks across the relay rows: each provider accepts only its
 * registered redirect (GitHub the loopback, Notion and Slack the hosted bounce,
 * LinkedIn its own route), and a callback registered for one provider is
 * refused by every other provider's exchange.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { CORE_LOOPBACK_CALLBACK } from '../src/oauth-bounce.js';
import { HOSTED_BOUNCE_REDIRECT, RELAY_PROVIDERS } from '../src/oauth-relay/providers.js';
import {
  mintAccessToken,
  post,
  seamFetch,
  startAuthority,
  startUpstream,
  stop,
  VERIFIER,
  type Authority,
  type Upstream,
} from './helpers/oauth-relay.js';

const ENV = {
  GITHUB_CLIENT_ID: 'gh-id',
  GITHUB_CLIENT_SECRET: 'fixture-gh-' + 'g'.repeat(24),
  NOTION_CLIENT_ID: 'notion-id',
  NOTION_CLIENT_SECRET: 'fixture-notion-' + 'n'.repeat(24),
  SLACK_CLIENT_ID: 'slack-id',
  SLACK_CLIENT_SECRET: 'fixture-slack-' + 's'.repeat(24),
};

/** The one registered redirect per relay row (L6 WP21 runbook rows 1, 3, 4). */
const REGISTERED: Record<string, string> = {
  github: CORE_LOOPBACK_CALLBACK,
  notion: HOSTED_BOUNCE_REDIRECT,
  slack: HOSTED_BOUNCE_REDIRECT,
};

/** LinkedIn's own callback route (citrate-core LINKEDIN_RELAY_SPEC.md); never a relay row. */
const LINKEDIN_CALLBACK = 'https://auth.citrate.ai/oauth/linkedin/callback';

const ALL_CALLBACKS = [CORE_LOOPBACK_CALLBACK, HOSTED_BOUNCE_REDIRECT, LINKEDIN_CALLBACK];

let up: Upstream;
let auth: Authority;
let member: string;

beforeAll(async () => {
  up = await startUpstream();
  auth = await startAuthority({ fetch: seamFetch(up), env: ENV });
  member = await mintAccessToken(auth.provider, 'member-callbacks');
});

afterAll(async () => {
  await stop(auth.server);
  await stop(up.server);
});

afterEach(() => {
  up.seen.length = 0;
});

describe('exact callbacks per provider row', () => {
  it('the provider table is exactly github, notion, slack, each with one registered redirect', () => {
    expect([...RELAY_PROVIDERS.keys()].sort()).toEqual(Object.keys(REGISTERED).sort());
    for (const [id, p] of RELAY_PROVIDERS) expect(p.redirectUris, id).toEqual([REGISTERED[id]]);
  });

  it('linkedin is not a relay row (404 unknown_provider, no outbound call)', async () => {
    const r = await post(auth, '/oauth/relay/v1/linkedin/token', { code: 'c', code_verifier: VERIFIER, redirect_uri: LINKEDIN_CALLBACK }, member);
    expect(r.status).toBe(404);
    expect(up.seen).toHaveLength(0);
  });

  for (const [id, registered] of Object.entries(REGISTERED)) {
    it(`${id}: accepts only ${registered}; every other provider's callback is refused`, async () => {
      for (const redirect_uri of ALL_CALLBACKS.filter((c) => c !== registered)) {
        const r = await post(auth, `/oauth/relay/v1/${id}/token`, { code: 'c', code_verifier: VERIFIER, redirect_uri }, member);
        expect(r.status, `${id} <- ${redirect_uri}`).toBe(400);
        expect(await r.json()).toMatchObject({ error: 'bad_request' });
      }
      expect(up.seen).toHaveLength(0);

      up.reply = () => ({
        status: 200,
        body: JSON.stringify({ ok: true, access_token: 'xoxp-1', token_type: 'user', authed_user: { id: 'U', scope: 'users:read' } }),
      });
      const ok = await post(auth, `/oauth/relay/v1/${id}/token`, { code: 'c', code_verifier: VERIFIER, redirect_uri: registered }, member);
      expect(ok.status, id).toBe(200);
      expect(up.seen).toHaveLength(1);
      expect(up.seen[0].requestedUrl).toBe(RELAY_PROVIDERS.get(id)!.tokenUrl);
    });
  }
});
