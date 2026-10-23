#!/bin/sh
# Creates the platform's database and its two roles. Runs once, when the data
# directory is empty (the official image's /docker-entrypoint-initdb.d hook).
#
#   app_owner    owns the schema and runs migrations. Not a superuser, so the
#                tables' FORCE ROW LEVEL SECURITY binds it as well.
#   app_runtime  what the API connects as: not the owner, no BYPASSRLS, so every
#                query it runs is filtered by the row-level security policies.
#
# See docs/adr/0001-postgres-row-level-security.md.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v db="${APP_DB_NAME:-app}" \
  -v owner="${APP_DB_OWNER:-app_owner}" -v owner_password="$APP_DB_OWNER_PASSWORD" \
  -v runtime="${APP_DB_RUNTIME:-app_runtime}" -v runtime_password="$APP_DB_RUNTIME_PASSWORD" <<'SQL'
CREATE ROLE :"owner" LOGIN PASSWORD :'owner_password' NOSUPERUSER NOCREATEROLE NOBYPASSRLS;
CREATE ROLE :"runtime" LOGIN PASSWORD :'runtime_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE DATABASE :"db" OWNER :"owner";
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO :"runtime";
SQL
