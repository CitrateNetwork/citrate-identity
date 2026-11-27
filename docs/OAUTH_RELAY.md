---
created: 2026-11-27T00:00:00Z
branch: feat/v60-l6-wp04-oauth-relay
author: Larry Klosowski
status: active
planset: 2026-11-07-v060 (L6-WP04, AR-E8.1 / F-20)
---

# OAuth token relay (`/oauth/relay/v1`)

Citrate Core connects members to GitHub, Notion and other providers whose token
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
  `502 {"error":"provider_rejected","revoked":false,"upstream_status":N}`.
- Relay errors, all with `Cache-Control: no-store`:

| Status | `error` | When |
|---|---|---|
| 400 | `bad_request` | missing field, bad `code_verifier`, unregistered `redirect_uri`, non-JSON body |
| 400 | `unsupported_operation` | refresh or revoke on a provider without that endpoint |
| 401 | `not_signed_in` | no bearer, unknown or expired bearer |
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

Adding a provider is a code change to `providers.ts` with tests. No URL from a
request is ever used outbound.

## Guarantees

- Never logs a request body, response body, code, verifier, token, secret or
  account id. A log line is `[oauth-relay] provider=<id> op=<op> outcome=<x> status=<n>`.
- Only whitelisted fields go upstream. A client-supplied `client_id` or
  `client_secret` is dropped. The member's bearer never goes upstream.
- Upstream redirects are not followed.
- Rate limits: 120 per IP and 40 per account per 15 minutes, shared through
  Redis in production (`src/auth/rate-limit.ts`).

## Environment

| Var | Effect |
|---|---|
| `OAUTH_RELAY` | `0` turns every relay route off. Unset means on. |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | GitHub connections app. Not the `CITRATE_AA_GITHUB_*` login federation app. |
| `NOTION_CLIENT_ID`, `NOTION_CLIENT_SECRET` | Notion public integration. |

The compose file passes these names through; `.env` holds the values. Values
live in 1Password only:

- `op://citrate-infra/identity.oauth-relay/GITHUB_CLIENT_ID`
- `op://citrate-infra/identity.oauth-relay/GITHUB_CLIENT_SECRET`
- `op://citrate-infra/identity.oauth-relay/NOTION_CLIENT_ID`
- `op://citrate-infra/identity.oauth-relay/NOTION_CLIENT_SECRET`

## Deploy checklist (operator)

Secrets never pass through a terminal, a chat, a file on the operator machine or
the shell history. They move from 1Password straight into the droplet `.env`.

1. Register the provider apps (connections runbook, L6-WP21). GitHub callback
   URL: `http://127.0.0.1:8975/oauth/callback`. Notion redirect URI:
   `https://auth.citrate.ai/oauth/callback`. Store the four values in the
   1Password item above.
2. Write a template on the operator machine that holds references only, for
   example `oauth-relay.env.tpl`:

   ```
   GITHUB_CLIENT_ID={{ op://citrate-infra/identity.oauth-relay/GITHUB_CLIENT_ID }}
   GITHUB_CLIENT_SECRET={{ op://citrate-infra/identity.oauth-relay/GITHUB_CLIENT_SECRET }}
   NOTION_CLIENT_ID={{ op://citrate-infra/identity.oauth-relay/NOTION_CLIENT_ID }}
   NOTION_CLIENT_SECRET={{ op://citrate-infra/identity.oauth-relay/NOTION_CLIENT_SECRET }}
   ```

3. Pipe the injected result into the droplet `.env`, replacing any earlier
   relay lines and keeping the file mode 0600 (the `^` anchor leaves the
   `CITRATE_AA_GITHUB_*` lines alone):

   ```
   op inject -i oauth-relay.env.tpl | ssh <deploy-host> \
     'cd <deploy-dir> && umask 077 && \
      grep -Ev "^(GITHUB|NOTION)_CLIENT_(ID|SECRET)=" .env > .env.new && \
      cat >> .env.new && chmod 600 .env.new && mv .env.new .env'
   ```

   Omit the Notion lines from the template until Notion is registered; the relay
   then answers 503 for Notion and never calls it.
4. Deploy the reviewed commit:
   `GIT_SHA="$(git rev-parse HEAD)" docker compose up -d --build identity`.
5. Verify without printing a value:
   - `docker compose exec identity node -e "process.exit(process.env.GITHUB_CLIENT_SECRET ? 0 : 1)"` exits 0.
   - `curl -s -o /dev/null -w '%{http_code}' -X POST https://auth.citrate.ai/oauth/relay/v1/github/token` prints `401`.
   - `GET /health` is still 200 and the OAuth bounce still answers
     `GET /oauth/callback` with 302.
6. Runtime proof is a recorded GitHub connect from a release build of Citrate
   Core (L6-WP05 test plan).

Rollback: set `OAUTH_RELAY=0` in `.env` and recreate the identity service. The
bounce, OIDC, SIWE and KYC routes are unaffected.
