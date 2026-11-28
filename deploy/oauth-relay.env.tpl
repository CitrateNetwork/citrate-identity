# 1Password template for the OAuth relay lines of /opt/citrate-identity/.env.
# References only. `op inject` resolves them on the operator machine and the
# result is piped straight into the droplet .env (docs/OAUTH_RELAY.md, Deploy
# checklist). Never write the injected output to a file.
#
#   op inject -i deploy/oauth-relay.env.tpl | ssh <deploy-host> \
#     'cd /opt/citrate-identity && umask 077 && \
#      grep -Ev "^(GITHUB|NOTION|SLACK|LINKEDIN)_CLIENT_(ID|SECRET)=" .env > .env.new && \
#      cat >> .env.new && chmod 600 .env.new && mv .env.new .env'
#
# The ^ anchor leaves the CITRATE_AA_GITHUB_* login federation lines alone.
# Field labels match the 1Password items as of 2026-11-28.

# GitHub connections OAuth App (not the CITRATE_AA_GITHUB_* login app).
GITHUB_CLIENT_ID={{ op://citrate-infra/identity.oauth-relay/GITHUB_CLIENT_ID }}
GITHUB_CLIENT_SECRET={{ op://citrate-infra/identity.oauth-relay/GITHUB_CLIENT_SECRET }}

# Core Slack MCP user app. SLACK_APP_ID in the same item is informational and not read.
SLACK_CLIENT_ID={{ op://citrate-infra/identity.oauth-relay/SLACK_CLIENT_ID }}
SLACK_CLIENT_SECRET={{ op://citrate-infra/identity.oauth-relay/SLACK_CLIENT_SECRET }}

# LinkedIn "Sign In with LinkedIn using OpenID Connect" app (docs/OAUTH_LINKEDIN.md).
LINKEDIN_CLIENT_ID={{ op://citrate-infra/identity.linkedin-relay/LINKEDIN_CLIENT_ID }}
LINKEDIN_CLIENT_SECRET={{ op://citrate-infra/identity.linkedin-relay/LINKEDIN_CLIENT_SECRET }}

# Notion public integration. Left commented until the owner confirms which Notion
# integration Core uses and its redirect URI is registered; while unset the relay
# answers 503 not_configured for Notion and never calls it. To enable, add these two
# lines without the leading "# " and wrap each reference in {{ }} (op inject also
# resolves references inside comments, so they are kept bare here):
# NOTION_CLIENT_ID=op://citrate-infra/identity.oauth-relay/NOTION_CLIENT_ID
# NOTION_CLIENT_SECRET=op://citrate-infra/identity.oauth-relay/NOTION_CLIENT_SECRET
