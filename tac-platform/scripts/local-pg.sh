#!/usr/bin/env bash
# Start a local PostgreSQL 16 cluster WITHOUT a Docker daemon (used in the
# qualification sandbox). Listens on 127.0.0.1:5433, trust auth, db "tac".
# Prints the DSN to export as TAC_DSN.
set -euo pipefail
PGBIN="${PGBIN:-/usr/lib/postgresql/16/bin}"
PGDATA="${PGDATA:-/tmp/pgdata}"
PGSOCK="${PGSOCK:-/tmp/pgrun}"
PORT="${PORT:-5433}"

if ! command -v "$PGBIN/initdb" >/dev/null; then
  echo "installing postgresql..." >&2
  DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-contrib >/dev/null
fi
rm -rf "$PGDATA" && mkdir -p "$PGDATA" "$PGSOCK"
chown -R postgres:postgres "$PGDATA" "$PGSOCK"
su -s /bin/bash postgres -c "$PGBIN/initdb -D $PGDATA -U postgres --auth=trust" >/tmp/initdb.log 2>&1
su -s /bin/bash postgres -c "$PGBIN/pg_ctl -D $PGDATA -o '-p $PORT -k $PGSOCK -c listen_addresses=127.0.0.1' -l /tmp/pg.log start"
sleep 2
su -s /bin/bash postgres -c "$PGBIN/createdb -p $PORT -h $PGSOCK tac"
echo "export TAC_DSN=\"postgres://postgres@127.0.0.1:$PORT/tac?sslmode=disable\""
