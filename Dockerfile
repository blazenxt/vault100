# Vault100-web — zero-knowledge static vault service (Railway-ready)
FROM node:20-alpine

ENV NODE_ENV=production
WORKDIR /app

# The entire runtime is the static web/ folder + built-in server.mjs
COPY web/ ./

EXPOSE 8080
USER node

HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT:-8080}/health" || exit 1

CMD ["node", "server.mjs"]
