# syntax=docker/dockerfile:1

FROM node:20-bookworm-slim AS deps
WORKDIR /opt/app

COPY package.json package-lock.json ./
RUN npm ci --include=dev --no-audit --no-fund && npm cache clean --force


FROM node:20-bookworm-slim
WORKDIR /app

ENV NODE_ENV=development \
  DEV_HTTP_PORT=3006 \
  HOST=0.0.0.0 \
  NODE_PATH=/app

COPY --from=deps /opt/app/node_modules /opt/node_modules
COPY docker-entrypoint.sh /usr/local/bin/catpawopen-entrypoint
RUN chmod +x /usr/local/bin/catpawopen-entrypoint

EXPOSE 3006
VOLUME ["/app/node_modules"]

ENTRYPOINT ["/usr/local/bin/catpawopen-entrypoint"]
CMD ["npm", "run", "dev"]
