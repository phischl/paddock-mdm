#!/usr/bin/env bash
# The steps of the bundle smoke test (plan M7b decision 25), shared by smoke.sh and upgrade.sh (plan M16 decision 10):
# step logging, the probes through Caddy and the installation of a bundle on one machine with two bundle directories
# and two Compose projects, paddock-cp and paddock-audit, following the installation guide.
#
# The caller sets, before it calls a step function:
#   W           the work directory (absolute)
#   CP_DIR      the control plane's bundle directory, AUDIT_DIR the audit host's
#   CP_OVERLAY  PADDOCK_COMPOSE_EXTRA of the control plane (space-separated absolute paths)
#   SMOKE_NAME  the prefix of the failure messages (smoke, upgrade)
#   started     $SECONDS at the start (the duration smoke_finish prints)
# and exports PADDOCK_CI_DIR and WAIT_TIMEOUT as smoke.sh does.
# shellcheck shell=bash

SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMOKE_REPO="$(cd "$SMOKE_LIB_DIR/../../.." && pwd)"
SMOKE_NAME="${SMOKE_NAME:-smoke}"
current="setup"

step() {
  current="$1"
  printf '\n== [%s] %s\n' "$(date -u +%H:%M:%S)" "$1"
}
fail() {
  echo "$SMOKE_NAME: $*" >&2
  exit 1
}
cp_paddock() { (cd "$CP_DIR" && PADDOCK_COMPOSE_EXTRA="$CP_OVERLAY" ./paddock "$@"); }
audit_paddock() { (cd "$AUDIT_DIR" && ./paddock "$@"); }

# wait_unsealed polls for up to 60 s: OpenBao reports sealed for a moment after the last share while it becomes active.
# The output is captured before grep searches it: under pipefail, a `grep -q` on a live pipe exits at the first match
# and the writer's SIGPIPE turns that match into a failure (PDK-544).
wait_unsealed() {
  local status
  for _ in $(seq 1 30); do
    status="$(cp_paddock bao status </dev/null 2>/dev/null || true)"
    grep -Eq '^Sealed +false' <<<"$status" && return 0
    sleep 2
  done
  return 1
}

# smoke_logs <suffix>: the Compose logs of both projects into <W>/logs/paddock-{cp,audit}<suffix>.log.
smoke_logs() {
  mkdir -p "$W/logs"
  [[ -f "$CP_DIR/.env" ]] && cp_paddock logs >"$W/logs/paddock-cp$1.log" 2>&1
  [[ -f "$AUDIT_DIR/.env" ]] && audit_paddock logs >"$W/logs/paddock-audit$1.log" 2>&1
  return 0
}

# smoke_down: both projects down with their volumes.
smoke_down() {
  [[ -f "$CP_DIR/.env" ]] && cp_paddock down --volumes >/dev/null 2>&1
  [[ -f "$AUDIT_DIR/.env" ]] && audit_paddock down --volumes >/dev/null 2>&1
  return 0
}

# smoke_finish is the EXIT trap of smoke.sh: logs of both projects, then both projects down with their volumes; also
# after a failure.
smoke_finish() {
  local rc=$?
  set +e
  if ((rc != 0)); then echo "$SMOKE_NAME: step '$current' failed" >&2; fi
  smoke_logs ""
  smoke_down
  # shellcheck disable=SC2154 # started is the caller's (see the header)
  echo "$SMOKE_NAME: $( ((rc == 0)) && echo passed || echo failed) after $((SECONDS - started)) s (logs: $W/logs/)"
  exit "$rc"
}

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

# probe <name> <method> <path>: the HTTP status through Caddy on 127.0.0.1:443, with the internal root certificate.
probe() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 --cacert "$CP_DIR/.secrets/caddy-root.crt" \
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

# smoke_extract <tarball>: both bundle directories, each verified; sets version.
smoke_extract() {
  local dir
  for dir in "$CP_DIR" "$AUDIT_DIR"; do
    mkdir -p "$dir"
    tar -xzf "$1" -C "$dir" --strip-components=1
    (cd "$dir" && ./paddock verify)
  done
  version="$(sed -n 's/^version=//p' "$CP_DIR/VERSION")"
  echo "bundle version $version"
}

# smoke_settings: .env of both hosts; sets addr, the primary address.
smoke_settings() {
  local host env_file
  addr="$(hostname -I | awk '{print $1}')"
  [[ -n "$addr" ]] || fail "no primary address"
  for host in cp audit; do
    if [[ "$host" == cp ]]; then env_file="$CP_DIR/.env"; else env_file="$AUDIT_DIR/.env"; fi
    cp "${env_file%.env}.env.example" "$env_file"
    if [[ "$host" == cp ]]; then setenv "$env_file" PADDOCK_HOST controlplane; else setenv "$env_file" PADDOCK_HOST audit; fi
    setenv "$env_file" PADDOCK_PROJECT "paddock-$host"
    setenv "$env_file" PADDOCK_DOMAIN paddock.localhost
    setenv "$env_file" PADDOCK_ACME_EMAIL ci@paddock.localhost
    setenv "$env_file" PADDOCK_PUBLIC_ADMIN_URL https://admin.paddock.localhost
    setenv "$env_file" PADDOCK_PUBLIC_DEVICE_URL https://device.paddock.localhost
    setenv "$env_file" PADDOCK_INTERCONNECT_ADDR "$addr"
    setenv "$env_file" PADDOCK_CONTROLPLANE_ADDR "$addr"
    setenv "$env_file" PADDOCK_AUDIT_ADDR "$addr"
  done
}

# smoke_secrets: the secrets of both hosts, exchanged between them, and throwaway release keys in <W>/keys.
smoke_secrets() {
  local key
  cp_paddock secrets
  audit_paddock secrets
  cp "$AUDIT_DIR/.secrets/db_paddock_audit_reader_password" "$CP_DIR/.secrets/"
  cp "$CP_DIR/.secrets/rabbitmq_audit_writer_password" "$AUDIT_DIR/.secrets/"
  cp "$AUDIT_DIR/.secrets/internal-ca/ca.crt" "$CP_DIR/.secrets/internal-ca/peer-ca.crt"
  cp "$CP_DIR/.secrets/internal-ca/ca.crt" "$AUDIT_DIR/.secrets/internal-ca/peer-ca.crt"
  cp_paddock secrets
  audit_paddock secrets
  mkdir -p "$W/keys" "$CP_DIR/.secrets/release-production"
  for key in minisign revoke-minisign; do
    [[ -f "$W/keys/$key.key" ]] || (cd "$SMOKE_REPO/agent" && GOTOOLCHAIN=auto go run aead.dev/minisign/cmd/minisign -G -W \
      -p "$W/keys/$key.pub" -s "$W/keys/$key.key" </dev/null >/dev/null)
    cp "$W/keys/$key.pub" "$CP_DIR/.secrets/release-production/$key.pub"
  done
  : >"$CP_DIR/.secrets/caddy-root.crt"
  chmod 666 "$CP_DIR/.secrets/caddy-root.crt"
}

# smoke_audit_infra: the audit host's infrastructure and its audit bucket.
smoke_audit_infra() {
  audit_paddock up --infra
  audit_paddock bootstrap audit-bucket
}

# smoke_cp_infra: the control plane's infrastructure, OpenBao initialised into <W>/init.json and unsealed, the buckets
# and Fleet.
smoke_cp_infra() {
  local root_token share shares
  cp_paddock up --infra
  cp_paddock bao operator init -key-shares=5 -key-threshold=3 -format=json >"$W/init.json"
  root_token="$(sed -n 's/.*"root_token": *"\([^"]*\)".*/\1/p' "$W/init.json")"
  [[ -n "$root_token" ]] || fail "no root token in the OpenBao init output"
  smoke_unseal_shares shares
  ((${#shares[@]} == 3)) || fail "no unseal shares in the OpenBao init output"
  # Shares on stdin, never on a command line.
  for share in "${shares[@]}"; do printf '%s' "$share" | cp_paddock bao write sys/unseal key=- >/dev/null; done
  wait_unsealed || fail "OpenBao is still sealed 60 s after the last unseal share"
  export BAO_TOKEN="$root_token"
  cp_paddock bootstrap openbao
  unset BAO_TOKEN
  mkdir -p "$AUDIT_DIR/.secrets/approle"
  rm -rf "$AUDIT_DIR/.secrets/approle/paddock-audit-writer"
  cp -a "$CP_DIR/.secrets/approle/paddock-audit-writer" "$AUDIT_DIR/.secrets/approle/"
  cp_paddock bootstrap buckets
  cp_paddock bootstrap fleet
  # A second run keeps the stored token: Fleet answers 200 for it.
  cp_paddock bootstrap fleet | tee "$W/fleet-bootstrap-2.txt"
  grep -q 'API token of the API-only user paddock is valid' "$W/fleet-bootstrap-2.txt" ||
    fail "a second ./paddock bootstrap fleet did not keep the token"
}

# smoke_unseal_shares <array name>: the first three unseal shares of <W>/init.json.
smoke_unseal_shares() {
  mapfile -t "$1" < <(awk '/"unseal_keys_b64"/ { f = 1; next } f && /\]/ { f = 0 } f { gsub(/[ ",]/, ""); print }' \
    "$W/init.json" | head -3)
}

# smoke_checks: the production checks of both hosts and the production Caddyfile.
smoke_checks() {
  local caddy_image
  cp_paddock check
  audit_paddock check --online
  # Caddyfile.prod with every variable of .env.example (commented defaults included) and the CI values.
  sed -n -E 's/^(# )?([A-Z][A-Z0-9_]*)=(.*)$/\2=\3/p' "$CP_DIR/.env.example" >"$W/caddy.env"
  {
    echo "PADDOCK_DOMAIN=paddock.localhost"
    echo "PADDOCK_ACME_EMAIL=ci@paddock.localhost"
    echo "PADDOCK_ADMIN_ALLOWED_CIDRS=0.0.0.0/0 ::/0"
  } >>"$W/caddy.env"
  caddy_image="$(sed -n 's/^CADDY_IMAGE=//p' "$CP_DIR/versions.env")"
  # The entrypoint validates the edge settings, renders the servers block and runs `caddy validate`; the stub skips
  # `caddy run`.
  docker run --rm --env-file "$W/caddy.env" -v "$CP_DIR/caddy/Caddyfile.prod:/etc/caddy/Caddyfile:ro" \
    -v "$CP_DIR/caddy/guards.caddy:/etc/caddy/guards.caddy:ro" -v "$CP_DIR/caddy/entrypoint.sh:/paddock/entrypoint.sh:ro" \
    --entrypoint sh "$caddy_image" -c 'mkdir -p /tmp/bin &&
      printf "#!/bin/sh\n[ \"\$1\" = run ] && exit 0\nexec /usr/bin/caddy \"\$@\"\n" >/tmp/bin/caddy && chmod +x /tmp/bin/caddy &&
      PATH=/tmp/bin:$PATH sh /paddock/entrypoint.sh'
}

# smoke_start: both hosts up; the notifier healthy.
smoke_start() {
  # The control plane first: its paddock-migrate provisions the RabbitMQ queue the audit writer consumes.
  cp_paddock up
  audit_paddock up
  # The notifier (plan M9 decision 41) is one of the roles `./paddock up` waited for; `./paddock ps` lists it healthy.
  grep -qx 'paddock-notifier healthy' <<<"$(cp_paddock ps --format '{{.Service}} {{.Health}}' </dev/null)" ||
    fail "./paddock ps does not list paddock-notifier as healthy"
}

# smoke_probes: the portal, Authentik and the device API through Caddy.
smoke_probes() {
  expect_status 200 admin.paddock.localhost GET /
  expect_status 200 auth.paddock.localhost GET /-/health/ready/
  expect_status '4[0-9][0-9]' device.paddock.localhost POST /v1/checkin
  # The probes above prove Caddy's bind to 443 with NET_BIND_SERVICE as its only capability. Port 80 is not probed: the
  # CI overlay runs the development Caddyfile, which has no HTTP listener (auto_https disable_redirects).
}

# smoke_hardening: every container of both projects matches this tree's hardening matrix (plan M12h decision 11). Only
# for the candidate's stack: the matrix of hardening-exceptions.yaml does not describe an earlier release.
smoke_hardening() {
  "$SMOKE_LIB_DIR/assert-hardening.sh" paddock-cp paddock-audit
}

# smoke_backup_waits: a fresh installation has no confirmed backup key (plan M15 decision 16): paddock-backup is
# healthy and pgBackRest waits for the key instead of backing up.
smoke_backup_waits() {
  local waited=false
  for _ in $(seq 1 30); do
    if cp_paddock compose logs --no-color pgbackrest 2>&1 | grep -q 'waiting for the backup key'; then waited=true; break; fi
    sleep 2
  done
  $waited || fail "pgbackrest does not wait for the backup key"
}

minisign_sign() { (cd "$SMOKE_REPO/agent" && GOTOOLCHAIN=auto go run aead.dev/minisign/cmd/minisign -S "$@" </dev/null >/dev/null); }

# smoke_agent_release <artifacts dir>: the release's unsigned agent artifacts signed with the throwaway keys and
# published as release <version>.
smoke_agent_release() {
  local artifacts="$1" deb name key
  rm -rf "$W/agent"
  mkdir -p "$W/agent/amd64"
  cp "$artifacts/paddockd_${version}_linux_amd64-unsigned" "$W/agent/amd64/paddockd"
  minisign_sign -s "$W/keys/minisign.key" -m "$W/agent/amd64/paddockd" -t "paddock-agent version=$version arch=amd64"
  for deb in "$artifacts"/*_amd64-unsigned.deb; do
    name="$(basename "$deb" -unsigned.deb).deb"
    cp "$deb" "$W/agent/$name"
    if [[ "$name" == paddock-revoke_* ]]; then
      minisign_sign -s "$W/keys/revoke-minisign.key" -m "$W/agent/$name" -t "paddock-agent version=$version arch=amd64"
    else
      minisign_sign -s "$W/keys/minisign.key" -m "$W/agent/$name" -t "paddock-agent version=$version arch=amd64"
    fi
  done
  cp_paddock agent-release "$version" "$W/agent" | tee "$W/agent-release.json"
  grep -q '"status": "published"' "$W/agent-release.json" || fail "agent-release did not publish $version"
}

# smoke_ids <project>: the IDs of the project's containers.
smoke_ids() { docker ps -aq --no-trunc --filter "label=com.docker.compose.project=$1" | sort; }

# smoke_idempotence: a second ./paddock up on both hosts recreates no container.
smoke_idempotence() {
  local before after
  before="$(smoke_ids paddock-cp; smoke_ids paddock-audit)"
  cp_paddock up
  audit_paddock up
  after="$(smoke_ids paddock-cp; smoke_ids paddock-audit)"
  [[ "$before" == "$after" ]] || fail "a second ./paddock up recreated containers"
}
