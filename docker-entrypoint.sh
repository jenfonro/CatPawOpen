#!/bin/sh
set -eu

APP_DIR="/app"
DATA_DIR="${NODE_PATH:-$APP_DIR}"
DB_FILE="${DATA_DIR%/}/db.json"

# Seed node_modules from the image into the mounted volume (avoids running npm install on OpenWrt at container start).
if [ ! -d "$APP_DIR/node_modules" ]; then
  mkdir -p "$APP_DIR/node_modules"
fi
if [ ! -f "$APP_DIR/node_modules/fastify/package.json" ]; then
  if [ -d "/opt/node_modules" ]; then
    cp -a /opt/node_modules/. "$APP_DIR/node_modules/"
  fi
fi

# Ensure db.json is a file in the mapped project root (avoid EISDIR when bind-mounting a non-existent file).
mkdir -p "$DATA_DIR"
if [ -d "$DB_FILE" ]; then
  echo "ERROR: $DB_FILE is a directory (EISDIR). Delete it (should be a file) and restart." >&2
  exit 1
fi
if [ ! -f "$DB_FILE" ]; then
  echo "{}" > "$DB_FILE"
fi

exec "$@"
