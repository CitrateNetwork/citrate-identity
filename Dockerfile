# syntax=docker/dockerfile:1
#
# Citrate Identity (auth.citrate.ai) — production image.
#
# Multi-stage:
#   1. builder  — install ALL deps (incl. dev) and compile TS → dist/ via
#                 `npm run build` (tsconfig.build.json emits dist/server.js).
#   2. deps     — install ONLY production deps for a lean runtime node_modules.
#   3. runtime  — copy dist + prod node_modules, drop to a non-root user, expose
#                 3000, healthcheck /health, and run `node dist/server.js`.
#
# The runtime carries no source, no test files, and no dev toolchain.

# ---- 1. builder ----
FROM node:24-alpine AS builder
WORKDIR /app
# Install against the lockfile for a reproducible build (needs dev deps for tsc).
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

# ---- 2. production deps ----
FROM node:24-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
# Only runtime dependencies — no dev toolchain in the final image.
RUN npm ci --omit=dev && npm cache clean --force

# ---- 3. runtime ----
FROM node:24-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app

# Run as the unprivileged `node` user that the base image ships (uid/gid 1000).
# Create a writable .keys dir owned by that user so a JWKS can be generated/persisted
# when no key is mounted (mount a volume here in prod to keep it stable across deploys).
RUN mkdir -p /app/.keys && chown -R node:node /app

COPY --chown=node:node package.json package-lock.json ./
COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/dist ./dist

USER node

EXPOSE 3000

# Liveness/readiness probe for orchestrators that don't read compose's healthcheck.
# Uses node (no curl/wget in alpine by default) to hit the in-process /health route.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health').then(r=>{if(r.status!==200)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "dist/server.js"]
