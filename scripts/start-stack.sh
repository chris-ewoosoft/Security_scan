#!/usr/bin/env bash
# Starts the stack: uses the existing external Postgres if reachable,
# otherwise falls back to the local "postgres" container defined in docker-compose.yml.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a
source .env
set +a

DB_HOST="${DD_DATABASE_HOST:-postgres}"
DB_PORT="${DD_DATABASE_PORT:-5432}"

if (echo > "/dev/tcp/${DB_HOST}/${DB_PORT}") >/dev/null 2>&1; then
  echo "Postgres tai ${DB_HOST}:${DB_PORT} da san sang -> dung truc tiep, bo qua container postgres."
  services=$(docker compose config --services | grep -v '^postgres$')
  docker compose up -d $services
else
  echo "Khong ket noi duoc ${DB_HOST}:${DB_PORT} -> khoi tao postgres bang container local."
  export DD_DATABASE_HOST=postgres
  export DD_DATABASE_PORT=5432
  docker compose up -d
fi
