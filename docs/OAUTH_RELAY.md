---
created: 2026-11-27T00:00:00Z
last_updated: 2026-11-27
branch: feat/v60-l6-relay-slack-linkedin
author: Larry Klosowski
status: active
planset: 2026-11-07-v060 (L6-WP04, AR-E8.1 / F-20)
---

# OAuth token relay (`/oauth/relay/v1`)

Citrate Core connects members to GitHub, Notion, Slack and other providers whose token
endpoint needs a client secret. A desktop binary cannot keep a secret, so the
code exchange runs here: the app sends the authorization code and PKCE
verifier, this authority adds the client secret, calls the provider's fixed
token endpoint, and returns the provider's answer unchanged. Nothing is stored.

Source: [`src/oauth-relay/routes.ts`](../src/oauth-relay/routes.ts),
provider table [`src/oauth-relay/providers.ts`](../src/oauth-relay/providers.ts),
tests [`test/oauth-relay.test.ts`](../test/oauth-relay.test.ts). The interface
is frozen in the v0.6.0 planset, lane L6 section 3.1; this page does not restate
the lane design.

## Endpoints

All three are `POST`, `Content-Type: application/json`, body at most 8 KiB, and
`Authorization: Bearer <auth.citrate.ai access token>` issued to the
`citrate-core` or `citrate-gui-native` client (owner decision L6-Q5: signed-in
members only).

| Path | Body | Upstream call |
|---|---|---|
| `/oauth/relay/v1/{provider}/token` | `code`, `code_verifier` (RFC 7636), `redirect_uri`, optional `resource` (https, RFC 8707) | provider token endpoint, `grant_type=authorization_code` |
| `/oauth/relay/v1/{provider}/refresh` | `refresh_token`, optional `resource` | provider token endpoint, `grant_type=refresh_token` |
| `/oauth/relay/v1/{provider}/revoke` | `token` | provider revocation endpoint, where one exists |

Answers:

- `token` and `refresh`: the provider's status, body and content type, byte for
  byte. No token length or shape is checked. GitHub answers some errors with 200
  and an `error` field; those pass through as well.
- `revoke`: `200 {"revoked":true,"upstream_status":N}` or
  `502 {"error":"provider_rejected","revoked":false,"upstream_status":N}`
  (Slack adds `provider_error` when `auth.revoke` answers `ok:false`).
- Slack `token` and `refresh` are checked before they pass through; see
  [Slack](#slack-core-slack-mcp-user-app).
- Every answer, relayed or the relay's own, carries `Cache-Control: no-store`
  and `X-Content-Type-Options: nosniff`.
- Relay errors:

| Status | `error` | When |
|---|---|---|
| 400 | `bad_request` | missing field, bad `code_verifier`, unregistered `redirect_uri`, non-JSON body |
| 400 | `unsupported_operation` | refresh or revoke on a provider without that endpoint |
| 401 | `not_signed_in` | no bearer, unknown or expired bearer, or a bearer issued before the account's revocation epoch (see below) |
| 403 | `client_not_permitted` | bearer issued to another relying party |
| 404 | `unknown_provider` / `unknown_operation` | provider or operation not in the table |
| 413 | `bad_request` | body over 8 KiB |
| 429 | `rate_limited` | per-IP or per-account budget spent (`Retry-After` set) |
| 502 | `provider_rejected` | upstream unreachable, redirected, oversized, or echoed the secret |
| 503 | `not_configured` | `{PROVIDER}_CLIENT_ID` or `{PROVIDER}_CLIENT_SECRET` unset; provider never called |
| 503 | `relay_disabled` | `OAUTH_RELAY=0` |

## Providers

| id | Token and refresh | Revoke | Client auth | Accepted `redirect_uri` |
|---|---|---|---|---|
| `github` | `https://github.com/login/oauth/access_token` (form body, `Accept: application/json`) | `DELETE https://api.github.com/applications/{client_id}/token`, Basic, JSON `{access_token}` | secret in form body | `http://127.0.0.1:8975/oauth/callback` |
| `notion` | `https://api.notion.com/v1/oauth/token` (JSON body) | none | Basic | `https://auth.citrate.ai/oauth/callback` (the hosted bounce, because Notion rejects an http loopback) |
| `slack` | `https://slack.com/api/oauth.v2.user.access` (form body) | `POST https://slack.com/api/auth.revoke`, form `token`, no client credentials | secret in form body | `https://auth.citrate.ai/oauth/callback` (the hosted bounce) |

Each row accepts exactly one `redirect_uri`, compared as a whole string (no
trailing slash, case or query variants). LinkedIn is not a row: it has its own
callback route (below) and its token never reaches the desktop, so
`/oauth/relay/v1/linkedin/*` answers 404. Notion and Slack share the hosted
bounce; the relay cannot tell their codes apart by redirect, and each provider
refuses a code it did not issue.

### Slack (Core Slack MCP user app)

App ID `A0CM5JALP3R` (informational, not read by the relay), token rotation on,
MCP on. User scopes only: `search:read.public`, `channels:read`,
`channels:history`, `users:read`. No bot scopes.

- The desktop opens `https://slack.com/oauth/v2_user/authorize` with
  `client_id`, `user_scope` (the four scopes above), `redirect_uri` (the hosted
  bounce), `state` and an S256 `code_challenge`.
- `token`: `oauth.v2.user.access` with `grant_type=authorization_code`, `code`,
  `code_verifier`, `redirect_uri`, `client_id`, `client_secret`.
- `refresh` (token rotation): the same method with
  `grant_type=refresh_token`. Rotated tokens (`xoxe.xoxp-...`, refresh
  `xoxe-1-...`) are long; they pass through byte for byte, untruncated.
- `revoke`: `auth.revoke` with the token as a form field.

Slack answers HTTP 200 with `ok:false` on errors, and one exchange can mint a
bot token beside the user token, so the relay reads a Slack answer before
passing it on (`src/oauth-relay/slack.ts`):

| Slack answer | Relay answer |
|---|---|
| `ok:true`, user tokens only (`xoxp-` / `xoxe.xoxp-`), every granted scope (top-level `scope` and `authed_user.scope`) in the approved set | Slack's answer, byte for byte |
| `ok:false` with a plain error code | `400 {"error":"provider_rejected","provider_error":"<code>"}`; nothing else from the answer |
| `ok:false` with any other error value, or not JSON, or no token | `502 provider_rejected`, no detail |
| any bot or app token (`token_type` not `user`, `bot_user_id`, `bot`, `incoming_webhook`, or a token not `xoxp-`) | every access token revoked at `auth.revoke`, then `502 {"error":"provider_rejected","provider_error":"bot_token_refused","revoked":true}` |
| a granted scope outside the approved set | revoked, then `502 ... "provider_error":"scope_not_approved"` |
| no granted scope reported | revoked, then `502 ... "provider_error":"scope_missing"` (fail closed) |

`revoked` is `false` when a revocation call failed. The same checks run on
`refresh` answers.

Slack docs used (checked 2026-11-27):

- MCP server, confidential OAuth, `oauth/v2_user/authorize` and `oauth.v2.user.access`: https://docs.slack.dev/ai/mcp-server
- `oauth.v2.user.access` arguments (`code_verifier`, `grant_type`, `refresh_token`), response and `ok:false` shape: https://docs.slack.dev/reference/methods/oauth.v2.user.access
- User and bot scopes, `oauth.v2.access` versus `oauth.v2.user.access`: https://docs.slack.dev/authentication/installing-with-oauth
- Token rotation (`grant_type=refresh_token`, `xoxe.` prefixes, 12 hour expiry): https://docs.slack.dev/authentication/using-token-rotation
- `auth.revoke` (token as POST parameter, `{"ok":true,"revoked":true}`): https://docs.slack.dev/reference/methods/auth.revoke

## LinkedIn (`/oauth/linkedin/start`, `/oauth/linkedin/callback`)

Implements citrate-core `docs/LINKEDIN_RELAY_SPEC.md` section 2. Source
[`src/oauth-relay/linkedin.ts`](../src/oauth-relay/linkedin.ts), tests
[`test/oauth-relay-linkedin.test.ts`](../test/oauth-relay-linkedin.test.ts).

- `GET /oauth/linkedin/start?state=<16 to 128 unreserved chars>&rd=http://127.0.0.1:8975/oauth/callback[&challenge=<S256>]`:
  `rd` must be that exact loopback. The relay stores `state` (single use, 5
  minute TTL, Redis when wired) and 302s to
  `https://www.linkedin.com/oauth/v2/authorization` with `response_type=code`,
  `client_id`, `redirect_uri=https://auth.citrate.ai/oauth/linkedin/callback`,
  `scope=openid profile`, `state`. 400 on a bad or reused state or `rd`, 503 when
  not configured, 429 over the per-IP budget.
- `GET /oauth/linkedin/callback?code&state` (exact path only): an unknown,
  used or expired state gets a 400 page, no redirect and no outbound call.
  Otherwise the relay posts the code with the secret to
  `https://www.linkedin.com/oauth/v2/accessToken`, reads
  `https://api.linkedin.com/v2/userinfo`, drops the LinkedIn token and 302s to
  `http://127.0.0.1:8975/oauth/callback?state=<state>&handle=<preferred_username or name>&sub=<sub>`.
  A LinkedIn error or a failed exchange returns `state` plus a fixed
  `error=access_denied | invalid_request | server_error` instead.
- Not yet done: the planset (L6-WP16) asks for a signed assertion in place of
  the bare `handle` query value; this route follows the spec as written.

Adding a provider is a code change to `providers.ts` with tests. No URL from a
request is ever used outbound.

## Guarantees

- Never logs a request body, response body, code, verifier, token, secret or
  account id. A log line is `[oauth-relay] provider=<id> op=<op> outcome=<x> status=<n>`.
- Only whitelisted fields go upstream. A client-supplied `client_id` or
  `client_secret` is dropped. The member's bearer never goes upstream.
- Upstream redirects are not followed.
- A provider answer containing the client secret (raw, percent-encoded,
  form-encoded with `+` for space, or inside the Basic credential) is replaced
  by `502 provider_rejected`.
- Account epoch (PBA-L3a-008, `src/auth/account-epoch.ts`): a password reset or
  "sign out everywhere" stamps the account with the second it happened. A bearer
  whose `iat` is before that second is refused `401 not_signed_in` with no
  upstream call, from that moment on rather than at its expiry. A token issued
  in the same second as the stamp survives (the reset's own new sign-in). The
  app signs in again and retries. The same check applies to the other bearer
  routes on this authority (`/kyc/handoff`, `/identity/:sub/wallets`,
  `/identity/:sub/orchard-proof`, `/aa/enroll-validator`, `/aa/register-wallet`,
  `/aa/guardians`, `POST /logout`, `GET /sessions/events`). Provider tokens the
  app already holds are not touched; the epoch revokes the member's Citrate
  credential, not their GitHub or Notion grant. A token with no `iat` on a
  stamped account, or an epoch-store error, is refused too (fail closed).
  Clock skew: the stamp comes from the clock of the instance that wrote it and
  `iat` from the clock of the instance that issued the token, so a token issued
  just after the stamp by a host lagging the epoch writer is refused for up to
  that skew (the app signs in again); keep instances on NTP.
- Rate limits: 120 per IP and 40 per account per 15 minutes, shared through
  Redis in production (`src/auth/rate-limit.ts`).

## Environment

| Var | Effect |
|---|---|
| `OAUTH_RELAY` | `0` turns every relay route off. Unset means on. |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | GitHub connections app. Not the `CITRATE_AA_GITHUB_*` login federation app. |
| `NOTION_CLIENT_ID`, `NOTION_CLIENT_SECRET` | Notion public integration. |
| `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET` | Core Slack MCP user app. `SLACK_APP_ID` is informational and not read. |
| `LINKEDIN_CLIENT_ID`, `LINKEDIN_CLIENT_SECRET` | LinkedIn app ("Sign In with LinkedIn using OpenID Connect"). |

The compose file passes these names through; `.env` holds the values. Values
live in 1Password only:

- `op://citrate-infra/identity.oauth-relay/GITHUB_CLIENT_ID`
- `op://citrate-infra/identity.oauth-relay/GITHUB_CLIENT_SECRET`
- `op://citrate-infra/identity.oauth-relay/NOTION_CLIENT_ID`
- `op://citrate-infra/identity.oauth-relay/NOTION_CLIENT_SECRET`
- `op://citrate-infra/identity.oauth-relay/SLACK_CLIENT_ID`
- `op://citrate-infra/identity.oauth-relay/SLACK_CLIENT_SECRET`
- `op://citrate-infra/identity.linkedin-relay/LINKEDIN_CLIENT_ID`
- `op://citrate-infra/identity.linkedin-relay/LINKEDIN_CLIENT_SECRET`

## Deploy checklist (operator)

Secrets never pass through a terminal, a chat, a file on the operator machine or
the shell history. They move from 1Password straight into the droplet `.env`.

1. Register the provider apps (connections runbook, L6-WP21). GitHub callback
   URL: `http://127.0.0.1:8975/oauth/callback`. Notion and Slack redirect URI:
   `https://auth.citrate.ai/oauth/callback`. LinkedIn Authorized redirect URL:
   `https://auth.citrate.ai/oauth/linkedin/callback`. Store the values in the
   1Password items above.
2. Write a template on the operator machine that holds references only, for
   example `oauth-relay.env.tpl`:

   ```
   GITHUB_CLIENT_ID={{ op://citrate-infra/identity.oauth-relay/GITHUB_CLIENT_ID }}
   GITHUB_CLIENT_SECRET={{ op://citrate-infra/identity.oauth-relay/GITHUB_CLIENT_SECRET }}
   NOTION_CLIENT_ID={{ op://citrate-infra/identity.oauth-relay/NOTION_CLIENT_ID }}
   NOTION_CLIENT_SECRET={{ op://citrate-infra/identity.oauth-relay/NOTION_CLIENT_SECRET }}
   SLACK_CLIENT_ID={{ op://citrate-infra/identity.oauth-relay/SLACK_CLIENT_ID }}
   SLACK_CLIENT_SECRET={{ op://citrate-infra/identity.oauth-relay/SLACK_CLIENT_SECRET }}
   LINKEDIN_CLIENT_ID={{ op://citrate-infra/identity.linkedin-relay/LINKEDIN_CLIENT_ID }}
   LINKEDIN_CLIENT_SECRET={{ op://citrate-infra/identity.linkedin-relay/LINKEDIN_CLIENT_SECRET }}
   ```

3. Pipe the injected result into the droplet `.env`, replacing any earlier
   relay lines and keeping the file mode 0600 (the `^` anchor leaves the
   `CITRATE_AA_GITHUB_*` lines alone):

   ```
   op inject -i oauth-relay.env.tpl | ssh <deploy-host> \
     'cd <deploy-dir> && umask 077 && \
      grep -Ev "^(GITHUB|NOTION|SLACK|LINKEDIN)_CLIENT_(ID|SECRET)=" .env > .env.new && \
      cat >> .env.new && chmod 600 .env.new && mv .env.new .env'
   ```

   Omit the Notion lines from the template until Notion is registered; the relay
   then answers 503 for Notion and never calls it.
4. Deploy the reviewed commit:
   `GIT_SHA="$(git rev-parse HEAD)" docker compose up -d --build identity`.
5. Verify without printing a value:
   - `docker compose exec identity node -e "process.exit(process.env.GITHUB_CLIENT_SECRET ? 0 : 1)"` exits 0.
   - `curl -s -o /dev/null -w '%{http_code}' -X POST https://auth.citrate.ai/oauth/relay/v1/github/token` prints `401` (same for `slack`).
   - `curl -s -o /dev/null -w '%{http_code}' 'https://auth.citrate.ai/oauth/linkedin/start?state=probe-0123456789abcdef&rd=https://x.example/'` prints `400` (rejected `rd`; a 503 would mean LinkedIn is not configured).
   - `GET /health` is still 200 and the OAuth bounce still answers
     `GET /oauth/callback` with 302.
6. Runtime proof is a recorded GitHub connect from a release build of Citrate
   Core (L6-WP05 test plan).

Rollback: set `OAUTH_RELAY=0` in `.env` and recreate the identity service. The
bounce, OIDC, SIWE and KYC routes are unaffected.
