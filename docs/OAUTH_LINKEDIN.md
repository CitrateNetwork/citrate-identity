---
created: 2026-11-27T00:00:00Z
branch: feat/v60-l6-relay-linkedin
author: Larry Klosowski
status: active
planset: 2026-11-07-v060 (L6 relay contract section 3.1, WP21 runbook row 10)
---

# LinkedIn social-identity relay (`/oauth/linkedin/*`)

Implements citrate-core `docs/LINKEDIN_RELAY_SPEC.md` section 2; that spec is
the design source and this page does not restate the reasons. Source
[`src/oauth-relay/linkedin.ts`](../src/oauth-relay/linkedin.ts), tests
[`test/oauth-relay-linkedin.test.ts`](../test/oauth-relay-linkedin.test.ts).

LinkedIn is not a `/oauth/relay/v1` provider ([`OAUTH_RELAY.md`](OAUTH_RELAY.md)):
its token never reaches the desktop, so `/oauth/relay/v1/linkedin/*` answers 404.

## Routes

- `GET /oauth/linkedin/start?state=<16 to 128 unreserved chars>&rd=http://127.0.0.1:8975/oauth/callback[&challenge=<S256>]`
  - `rd` must be that exact loopback.
  - The relay stores `state` (single use, 5 minute TTL, Redis when wired) and
    302s to `https://www.linkedin.com/oauth/v2/authorization` with
    `response_type=code`, `client_id`,
    `redirect_uri=https://auth.citrate.ai/oauth/linkedin/callback`,
    `scope=openid profile`, `state`.
  - 400 on a bad or reused `state` or a bad `rd`; 503 when not configured;
    429 over the per-IP budget.
- `GET /oauth/linkedin/callback?code&state` (exact path only)
  - An unknown, used or expired `state` gets a 400 page, no redirect and no
    outbound call.
  - Otherwise the relay posts the code with the secret to
    `https://www.linkedin.com/oauth/v2/accessToken`, reads
    `https://api.linkedin.com/v2/userinfo`, drops the LinkedIn token and 302s to
    `http://127.0.0.1:8975/oauth/callback?state=<state>&handle=<preferred_username or name>&sub=<sub>`.
  - A LinkedIn error or a failed exchange returns `state` plus a fixed
    `error=access_denied | invalid_request | server_error`.

Every answer carries `Cache-Control: no-store`. Log lines carry only
`provider=linkedin op=<start|callback> outcome=<x> status=<n>`; never a code,
state, token, handle or secret. `OAUTH_RELAY=0` turns both routes off.

Follow-up (L6-WP16): the planset replaces the bare `handle` query value with a
signed assertion (JWS, `aud: citrate-core-social`, `state_hash`, 5 minute
expiry) so the desktop does not take an unsigned handle from a URL. Not in this
change.

## Environment

| Var | Effect |
|---|---|
| `LINKEDIN_CLIENT_ID`, `LINKEDIN_CLIENT_SECRET` | LinkedIn app with "Sign In with LinkedIn using OpenID Connect". Either unset: `/start` answers 503 and LinkedIn is never called. |

Values live in 1Password only, in their own item:

- `op://citrate-infra/identity.linkedin-relay/LINKEDIN_CLIENT_ID`
- `op://citrate-infra/identity.linkedin-relay/LINKEDIN_CLIENT_SECRET`

## Deploy (operator)

1. In the LinkedIn app, set the only Authorized redirect URL to
   `https://auth.citrate.ai/oauth/linkedin/callback`.
2. Inject from 1Password straight into the droplet `.env`, the same way as the
   relay checklist in [`OAUTH_RELAY.md`](OAUTH_RELAY.md), with the tracked
   template [`deploy/oauth-relay.env.tpl`](../deploy/oauth-relay.env.tpl), which
   holds references only and includes these lines:

   ```
   LINKEDIN_CLIENT_ID={{ op://citrate-infra/identity.linkedin-relay/LINKEDIN_CLIENT_ID }}
   LINKEDIN_CLIENT_SECRET={{ op://citrate-infra/identity.linkedin-relay/LINKEDIN_CLIENT_SECRET }}
   ```

   and `grep -Ev "^LINKEDIN_CLIENT_(ID|SECRET)=" .env` to drop earlier lines.
3. Deploy the reviewed commit, then verify without printing a value:
   `curl -s -o /dev/null -w '%{http_code}' 'https://auth.citrate.ai/oauth/linkedin/start?state=probe-0123456789abcdef&rd=https://x.example/'`
   prints `400` (rejected `rd`; `503` means not configured).
4. Runtime proof is a recorded LinkedIn link from a release build of Citrate
   Core (citrate-core client wiring, LINKEDIN_RELAY_SPEC.md section 3).
