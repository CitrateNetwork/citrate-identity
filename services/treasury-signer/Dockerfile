# Treasury signer worker (Phase-D D2.4, @rule8). Isolated container: holds the
# vault/SBT owner key, signs onlyOwner grant/mint, caps daily spend. Runs on the
# operator droplet, bound to 127.0.0.1 behind Caddy; the key is passed via
# --env-file (never baked into the image, never on Vercel).
FROM node:22-alpine
WORKDIR /app
COPY package.json ./
RUN npm i --omit=dev --silent
COPY server.mjs ./
# non-root
RUN addgroup -S sign && adduser -S sign -G sign \
 && mkdir -p /var/lib/citrate-treasury-signer && chown -R sign:sign /var/lib/citrate-treasury-signer /app
USER sign
EXPOSE 8790
CMD ["node", "server.mjs"]
