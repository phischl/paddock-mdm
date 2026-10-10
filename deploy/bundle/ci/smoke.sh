#!/usr/bin/env bash
# Smoke test of an operator bundle (plan M7b decision 25, §6.2): follows the installation guide on one machine with two
# bundle directories and two Compose projects, paddock-cp and paddock-audit. The running control plane adds the CI
# overlay compose.ci.yaml (internal TLS instead of ACME, backups to the audit project's RustFS); `./paddock check`
# renders the production files without it.
#   smoke.sh <tarball> [--agent-artifacts <dir>] [--work <dir>]
# Exit 0: every step passed; 1: a step failed (named on stderr); 2: usage. Needs docker, docker compose >= 2.24, go
# (throwaway minisign keys), curl and sha256sum; binds 80 and 443 and, on the primary address, 5432, 5671 and 8200.
# Environment: WAIT_TIMEOUT (default 900 s per wait). The Compose logs of both projects end up in <work>/logs/.
set -euo pipefail

usage() {
  echo "usage: smoke.sh <tarball> [--agent-artifacts <dir>] [--work <dir>]" >&2
  exit 2
}

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
tarball="${1:-}"
[[ -f "$tarball" ]] || usage
shift
agent_artifacts= work=
while (($#)); do
  case "$1" in
    --agent-artifacts) agent_artifacts="${2:-}"; shift 2 || usage ;;
    --work) work="${2:-}"; shift 2 || usage ;;
    *) usage ;;
  esac
done
[[ -z "$agent_artifacts" || -d "$agent_artifacts" ]] || usage
tarball="$(cd "$(dirname "$tarball")" && pwd)/$(basename "$tarball")"
W="${work:-$(mktemp -d)}"
mkdir -p "$W"
W="$(cd "$W" && pwd)"
export PADDOCK_CI_DIR="$here" WAIT_TIMEOUT="${WAIT_TIMEOUT:-900}"
ci_overlay="$here/compose.ci.yaml"
started=$SECONDS
current="setup"

step() {
  current="$1"
  printf '\n== [%s] %s\n' "$(date -u +%H:%M:%S)" "$1"
}
fail() {
  echo "smoke: $*" >&2
  exit 1
}
cp_paddock() { (cd "$W/cp" && PADDOCK_COMPOSE_EXTRA="$ci_overlay" ./paddock "$@"); }
audit_paddock() { (cd "$W/audit" && ./paddock "$@"); }

# Logs of both projects, then both projects down with their volumes; also after a failure.
finish() {
  local rc=$?
  set +e
  if ((rc != 0)); then echo "smoke: step '$current' failed" >&2; fi
  mkdir -p "$W/logs"
  [[ -f "$W/cp/.env" ]] && cp_paddock logs >"$W/logs/paddock-cp.log" 2>&1
  [[ -f "$W/audit/.env" ]] && audit_paddock logs >"$W/logs/paddock-audit.log" 2>&1
  [[ -f "$W/cp/.env" ]] && cp_paddock down --volumes >/dev/null 2>&1
  [[ -f "$W/audit/.env" ]] && audit_paddock down --volumes >/dev/null 2>&1
  echo "smoke: $( ((rc == 0)) && echo passed || echo failed) after $((SECONDS - started)) s (logs: $W/logs/)"
  exit "$rc"
}
trap finish EXIT

# setenv <file> <name> <value>: sets name in an env file, uncommenting a commented default.
setenv() {
  local file="$1" name="$2" value="$3"
  if grep -qE "^(# )?$name=" "$file"; then
    awk -v n="$name" -v v="$value" '$0 ~ "^(# )?" n "=" && !done { print n "=" v; done = 1; next } { print }' \
      "$file" >"$file.tmp" && mv "$file.tmp" "$file"
  else
    printf '%s=%s\n' "$name" "$value" >>"$file"
  fi
}
rand() { head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

step "1 extract and verify"
for host in cp audit; do
  mkdir -p "$W/$host"
  tar -xzf "$tarball" -C "$W/$host" --strip-components=1
  (cd "$W/$host" && ./paddock verify)
done
version="$(sed -n 's/^version=//p' "$W/cp/VERSION")"
echo "bundle version $version"

step "2 settings"
addr="$(hostname -I | awk '{print $1}')"
[[ -n "$addr" ]] || fail "no primary address"
for host in cp audit; do
  env_file="$W/$host/.env"
  cp "$W/$host/.env.example" "$env_file"
  if [[ "$host" == cp ]]; then setenv "$env_file" PADDOCK_HOST controlplane; else setenv "$env_file" PADDOCK_HOST audit; fi
  setenv "$env_file" PADDOCK_PROJECT "paddock-$host"
  setenv "$env_file" PADDOCK_DOMAIN paddock.localhost
  setenv "$env_file" PADDOCK_ACME_EMAIL ci@paddock.localhost
  setenv "$env_file" PADDOCK_PUBLIC_ADMIN_URL https://admin.paddock.localhost
  setenv "$env_file" PADDOCK_PUBLIC_DEVICE_URL https://device.paddock.localhost
  setenv "$env_file" PADDOCK_INTERCONNECT_ADDR "$addr"
  setenv "$env_file" PADDOCK_CONTROLPLANE_ADDR "$addr"
  setenv "$env_file" PADDOCK_AUDIT_ADDR "$addr"
  setenv "$env_file" PADDOCK_BACKUP_S3_ENDPOINT https://backup-s3-tls:9443
done

step "3 secrets"
cp_paddock secrets
audit_paddock secrets
cp "$W/audit/.secrets/db_paddock_audit_reader_password" "$W/cp/.secrets/"
cp "$W/cp/.secrets/rabbitmq_audit_writer_password" "$W/audit/.secrets/"
cp "$W/audit/.secrets/internal-ca/ca.crt" "$W/cp/.secrets/internal-ca/peer-ca.crt"
cp "$W/cp/.secrets/internal-ca/ca.crt" "$W/audit/.secrets/internal-ca/peer-ca.crt"
cp_paddock secrets
audit_paddock secrets
mkdir -p "$W/keys" "$W/cp/.secrets/release-production"
for key in minisign revoke-minisign; do
  (cd "$repo/agent" && GOTOOLCHAIN=auto go run aead.dev/minisign/cmd/minisign -G -W -p "$W/keys/$key.pub" \
    -s "$W/keys/$key.key" </dev/null >/dev/null)
  cp "$W/keys/$key.pub" "$W/cp/.secrets/release-production/$key.pub"
done
for role in pgbackrest worker fleet; do
  printf '%s' "ci$(rand | head -c 16)" >"$W/cp/.secrets/backup_${role}_access_key"
  printf '%s' "$(rand)" >"$W/cp/.secrets/backup_${role}_secret_key"
done
: >"$W/cp/.secrets/caddy-root.crt"
chmod 666 "$W/cp/.secrets/caddy-root.crt"

step "4 audit host: infrastructure, audit bucket, backup bucket"
audit_paddock up --infra
audit_paddock bootstrap audit-bucket
cp "$W/cp/.secrets"/backup_* "$W/audit/.secrets/"
PADDOCK_ENV=development SECRETS_DIR="$W/audit/.secrets" NETWORK=paddock-audit_audit-store \
  "$repo/deploy/compose/scripts/rustfs-backup-bootstrap.sh"

step "5 control plane: infrastructure, OpenBao, buckets, Fleet"
cp_paddock up --infra
cp_paddock bao operator init -key-shares=5 -key-threshold=3 -format=json >"$W/init.json"
root_token="$(sed -n 's/.*"root_token": *"\([^"]*\)".*/\1/p' "$W/init.json")"
[[ -n "$root_token" ]] || fail "no root token in the OpenBao init output"
mapfile -t shares < <(awk '/"unseal_keys_b64"/ { f = 1; next } f && /\]/ { f = 0 } f { gsub(/[ ",]/, ""); print }' \
  "$W/init.json" | head -3)
((${#shares[@]} == 3)) || fail "no unseal shares in the OpenBao init output"
# Shares on stdin, never on a command line.
for share in "${shares[@]}"; do printf '%s' "$share" | cp_paddock bao write sys/unseal key=- >/dev/null; done
cp_paddock bao status </dev/null | grep -Eq '^Sealed +false' || fail "OpenBao is still sealed"
export BAO_TOKEN="$root_token"
cp_paddock bootstrap openbao
unset BAO_TOKEN
mkdir -p "$W/audit/.secrets/approle"
rm -rf "$W/audit/.secrets/approle/paddock-audit-writer"
cp -a "$W/cp/.secrets/approle/paddock-audit-writer" "$W/audit/.secrets/approle/"
cp_paddock bootstrap buckets
cp_paddock bootstrap fleet
# A second run keeps the stored token: Fleet answers 200 for it.
cp_paddock bootstrap fleet | tee "$W/fleet-bootstrap-2.txt"
grep -q 'API token of the API-only user paddock is valid' "$W/fleet-bootstrap-2.txt" ||
  fail "a second ./paddock bootstrap fleet did not keep the token"

step "6 production checks"
cp_paddock check
audit_paddock check --online
# Caddyfile.prod with every variable of .env.example (commented defaults included) and the CI values.
sed -n -E 's/^(# )?([A-Z][A-Z0-9_]*)=(.*)$/\2=\3/p' "$W/cp/.env.example" >"$W/caddy.env"
{
  echo "PADDOCK_DOMAIN=paddock.localhost"
  echo "PADDOCK_ACME_EMAIL=ci@paddock.localhost"
  echo "PADDOCK_ADMIN_ALLOWED_CIDRS=0.0.0.0/0 ::/0"
} >>"$W/caddy.env"
caddy_image="$(sed -n 's/^CADDY_IMAGE=//p' "$W/cp/versions.env")"
# The entrypoint validates the edge settings, renders the servers block and runs `caddy validate`; the stub skips
# `caddy run`.
docker run --rm --env-file "$W/caddy.env" -v "$W/cp/caddy/Caddyfile.prod:/etc/caddy/Caddyfile:ro" \
  -v "$W/cp/caddy/guards.caddy:/etc/caddy/guards.caddy:ro" -v "$W/cp/caddy/entrypoint.sh:/paddock/entrypoint.sh:ro" \
  --entrypoint sh "$caddy_image" -c 'mkdir -p /tmp/bin &&
    printf "#!/bin/sh\n[ \"\$1\" = run ] && exit 0\nexec /usr/bin/caddy \"\$@\"\n" >/tmp/bin/caddy && chmod +x /tmp/bin/caddy &&
    PATH=/tmp/bin:$PATH sh /paddock/entrypoint.sh'

step "7 start both hosts"
# The control plane first: its paddock-migrate provisions the RabbitMQ queue the audit writer consumes.
cp_paddock up
audit_paddock up

step "8 probes"
# probe <name> <method> <path>: the HTTP status through Caddy on 127.0.0.1:443, with the internal root certificate.
probe() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 --cacert "$W/cp/.secrets/caddy-root.crt" \
    --resolve "$1:443:127.0.0.1" -X "$2" "https://$1$3" || true
}
# expect_status <pattern> <name> <method> <path>: retries for 120 s while the roles warm up.
expect_status() {
  local pattern="$1" code=
  shift
  for _ in $(seq 1 40); do
    code="$(probe "$@")"
    if [[ "$code" =~ ^($pattern)$ ]]; then
      echo "$1 $2$3 -> $code"
      return 0
    fi
    sleep 3
  done
  fail "$1 $2$3 answered '$code', want $pattern"
}
expect_status 200 admin.paddock.localhost GET /
expect_status 200 auth.paddock.localhost GET /-/health/ready/
expect_status '4[0-9][0-9]' device.paddock.localhost POST /v1/checkin
cp_paddock compose run --rm --no-deps -T pgbackrest backup --start-fast
cp_paddock compose run --rm --no-deps -T pgbackrest info | tee "$W/pgbackrest-info.txt"
grep -q 'full backup' "$W/pgbackrest-info.txt" || fail "pgbackrest info shows no full backup"
if [[ -n "$agent_artifacts" ]]; then
  mkdir -p "$W/agent/amd64"
  minisign_sign() { (cd "$repo/agent" && GOTOOLCHAIN=auto go run aead.dev/minisign/cmd/minisign -S "$@" </dev/null >/dev/null); }
  cp "$agent_artifacts/paddockd_${version}_linux_amd64-unsigned" "$W/agent/amd64/paddockd"
  minisign_sign -s "$W/keys/minisign.key" -m "$W/agent/amd64/paddockd" -t "paddock-agent version=$version arch=amd64"
  for deb in "$agent_artifacts"/*_amd64-unsigned.deb; do
    name="$(basename "$deb" -unsigned.deb).deb"
    cp "$deb" "$W/agent/$name"
    key=minisign
    [[ "$name" == paddock-revoke_* ]] && key=revoke-minisign
    minisign_sign -s "$W/keys/$key.key" -m "$W/agent/$name"
  done
  cp_paddock agent-release "$version" "$W/agent" | tee "$W/agent-release.json"
  grep -q '"status": "published"' "$W/agent-release.json" || fail "agent-release did not publish $version"
fi

step "9 idempotence"
ids() { docker ps -aq --no-trunc --filter "label=com.docker.compose.project=$1" | sort; }
before="$(ids paddock-cp; ids paddock-audit)"
cp_paddock up
audit_paddock up
after="$(ids paddock-cp; ids paddock-audit)"
[[ "$before" == "$after" ]] || fail "a second ./paddock up recreated containers"

step "10 done"
