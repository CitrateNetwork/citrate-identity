/**
 * Provider table for the OAuth token relay (L6-WP04, AR-E8.1 / F-20).
 *
 * Every outbound URL the relay can ever call lives HERE, as a frozen constant.
 * No URL, host, path or header from an incoming request is ever used outbound:
 * the request names a provider id, and the id selects one row of this table.
 * That is what makes the relay "not a proxy to anywhere".
 *
 * The token endpoints are the same values citrate-core uses
 * (`src-tauri/src/connections.rs`, `Service::token_endpoint`).
 *
 * Secrets: each provider reads `{ENV_PREFIX}_CLIENT_ID` and
 * `{ENV_PREFIX}_CLIENT_SECRET` from the identity deployment's environment. A
 * provider with either value unset is "not configured": the relay answers 503
 * and never calls it.
 */
import { CORE_LOOPBACK_CALLBACK } from '../oauth-bounce.js';

/**
 * The hosted https redirect providers that reject an http loopback are
 * registered against (Notion, Slack). It is this authority's own bounce
 * (`src/oauth-bounce.ts`), which 302s the browser to the same loopback.
 */
export const HOSTED_BOUNCE_REDIRECT = 'https://auth.citrate.ai/oauth/callback';

/** How the client credentials are presented to the provider's token endpoint. */
export type ClientAuthStyle =
  /** `client_id` + `client_secret` as form fields in the request body. */
  | 'body'
  /** HTTP Basic `client_id:client_secret`; the body carries no secret. */
  | 'basic';

/** How the token/refresh request body is encoded. */
export type BodyEncoding = 'form' | 'json';

export interface RevokeEndpoint {
  /** Builds the fixed revoke URL; only the configured client id is substituted. */
  url: (clientId: string) => string;
  method: 'DELETE' | 'POST';
  /**
   * `basic`: client_id:client_secret as HTTP Basic. `none`: the token itself
   * is the credential (Slack `auth.revoke`); no client secret is sent.
   */
  auth: 'basic' | 'none';
  /** The body field name the provider expects the token under. */
  tokenField: string;
  encoding: BodyEncoding;
  headers: Readonly<Record<string, string>>;
}

export interface RelayProvider {
  /** Path segment: `/oauth/relay/v1/{id}/...`. */
  readonly id: string;
  /** Env prefix: `{envPrefix}_CLIENT_ID`, `{envPrefix}_CLIENT_SECRET`. */
  readonly envPrefix: string;
  readonly tokenUrl: string;
  /** Refresh endpoint; absent means the provider issues no refresh tokens. */
  readonly refreshUrl?: string;
  readonly revoke?: RevokeEndpoint;
  readonly authStyle: ClientAuthStyle;
  readonly encoding: BodyEncoding;
  /** Extra fixed request headers for token + refresh calls. */
  readonly headers: Readonly<Record<string, string>>;
  /** The ONLY redirect_uri values accepted for this provider. */
  readonly redirectUris: readonly string[];
  /**
   * Answer policy checked before a token/refresh answer is passed through.
   * Absent: the provider's answer passes through unchanged (GitHub, Notion).
   */
  readonly answerPolicy?: SlackUserAnswerPolicy;
}

/**
 * Slack answers HTTP 200 with `ok:false` on errors, and one exchange can mint
 * bot and user tokens together. The relay only passes on an `ok:true` answer
 * that carries user tokens alone, with every granted scope in the approved set.
 */
export interface SlackUserAnswerPolicy {
  readonly kind: 'slack_user';
  readonly approvedUserScopes: ReadonlySet<string>;
}

const GITHUB: RelayProvider = Object.freeze({
  id: 'github',
  envPrefix: 'GITHUB',
  tokenUrl: 'https://github.com/login/oauth/access_token',
  // GitHub App user-to-server tokens refresh at the same endpoint.
  refreshUrl: 'https://github.com/login/oauth/access_token',
  revoke: Object.freeze({
    // DELETE /applications/{client_id}/token, Basic client_id:client_secret,
    // JSON body { access_token }. Answers 204 on success.
    url: (clientId: string) =>
      `https://api.github.com/applications/${encodeURIComponent(clientId)}/token`,
    method: 'DELETE' as const,
    auth: 'basic' as const,
    tokenField: 'access_token',
    encoding: 'json' as const,
    headers: Object.freeze({
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
    }),
  }),
  authStyle: 'body',
  encoding: 'form',
  // Without this GitHub answers application/x-www-form-urlencoded.
  headers: Object.freeze({ accept: 'application/json' }),
  redirectUris: Object.freeze([CORE_LOOPBACK_CALLBACK]),
});

const NOTION: RelayProvider = Object.freeze({
  id: 'notion',
  envPrefix: 'NOTION',
  tokenUrl: 'https://api.notion.com/v1/oauth/token',
  refreshUrl: 'https://api.notion.com/v1/oauth/token',
  authStyle: 'basic',
  encoding: 'json',
  headers: Object.freeze({ accept: 'application/json' }),
  // Notion rejects a plaintext-http redirect, so core registers and sends the
  // hosted bounce (connections.rs `redirect_uri` for Service::Notion).
  redirectUris: Object.freeze([HOSTED_BOUNCE_REDIRECT]),
});

/**
 * Core Slack MCP user app (App ID A0CM5JALP3R, token rotation on). Read-only
 * user scopes; no bot scopes. Changing this set is a reviewed code change.
 */
export const SLACK_APPROVED_USER_SCOPES: ReadonlySet<string> = new Set([
  'search:read.public',
  'channels:read',
  'channels:history',
  'users:read',
]);

/** Slack user OAuth v2 token method; the MCP server's documented token endpoint. */
const SLACK_USER_TOKEN_URL = 'https://slack.com/api/oauth.v2.user.access';

const SLACK: RelayProvider = Object.freeze({
  id: 'slack',
  envPrefix: 'SLACK',
  // Code exchange and rotation refresh (grant_type=refresh_token) both use
  // oauth.v2.user.access, which returns the user token at the top level.
  tokenUrl: SLACK_USER_TOKEN_URL,
  refreshUrl: SLACK_USER_TOKEN_URL,
  revoke: Object.freeze({
    // auth.revoke takes the token as a POST form parameter and answers
    // {"ok":true,"revoked":true}; it needs no client credentials.
    url: () => 'https://slack.com/api/auth.revoke',
    method: 'POST' as const,
    auth: 'none' as const,
    tokenField: 'token',
    encoding: 'form' as const,
    headers: Object.freeze({ accept: 'application/json' }),
  }),
  authStyle: 'body',
  encoding: 'form',
  headers: Object.freeze({ accept: 'application/json' }),
  // Slack requires an https redirect; core uses the hosted bounce.
  redirectUris: Object.freeze([HOSTED_BOUNCE_REDIRECT]),
  answerPolicy: Object.freeze({ kind: 'slack_user' as const, approvedUserScopes: SLACK_APPROVED_USER_SCOPES }),
});

export const RELAY_PROVIDERS: ReadonlyMap<string, RelayProvider> = new Map(
  [GITHUB, NOTION, SLACK].map((p) => [p.id, p] as const),
);

/** Exact-match lookup; anything else (case variants, `__proto__`) is unknown. */
export function findRelayProvider(id: string): RelayProvider | undefined {
  return RELAY_PROVIDERS.get(id);
}

export interface ProviderCredentials {
  clientId: string;
  clientSecret: string;
}

/** The configured credentials, or null when either value is unset or blank. */
export function providerCredentials(
  p: RelayProvider,
  env: Readonly<Record<string, string | undefined>>,
): ProviderCredentials | null {
  const clientId = env[`${p.envPrefix}_CLIENT_ID`]?.trim();
  const clientSecret = env[`${p.envPrefix}_CLIENT_SECRET`]?.trim();
  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret };
}
