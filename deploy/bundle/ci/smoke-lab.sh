#!/usr/bin/env bash
# Smoke test of the lab profile of an operator bundle (plan M8a decision 18, ADR 0029): one bundle directory, one
# Compose project paddock-lab with PADDOCK_HOST=lab, and the shipped Nginx reference configuration on the runner in
# front of Caddy's plain-HTTP port (the same-host variant of decision 14) with a throwaway CA. The running stack adds
# the CI overlay compose.ci-lab.yaml (pinned subnet of network cp, trust in the throwaway CA); `./paddock check`
# renders the shipped files without it.
#   smoke-lab.sh <tarball> [--work <dir>]
# Exit 0: every step passed; 1: a step failed (named on stderr); 2: usage. Needs docker, docker compose >= 2.24, go
# (throwaway minisign keys), openssl, curl and sha256sum; binds 80 and 443 on every address (Nginx) and 127.0.0.1:8080
# (Caddy); network cp takes 172.30.0.0/24. Environment: WAIT_TIMEOUT (default 900 s per wait). The Compose logs and
# Nginx's log end up in <work>/logs/.
set -euo pipefail

usage() {
  echo "usage: smoke-lab.sh <tarball> [--work <dir>]" >&2
  exit 2
}

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
tarball="${1:-}"
[[ -f "$tarball" ]] || usage
shift
work=
while (($#)); do
  case "$1" in
    --work) work="${2:-}"; shift 2 || usage ;;
    *) usage ;;
  esac
done
tarball="$(cd "$(dirname "$tarball")" && pwd)/$(basename "$tarball")"
W="${work:-$(mktemp -d)}"
mkdir -p "$W"
W="$(cd "$W" && pwd)"
export PADDOCK_CI_LAB_TLS="$W/tls" WAIT_TIMEOUT="${WAIT_TIMEOUT:-900}"
ci_overlay="$here/compose.ci-lab.yaml"
nginx_name=paddock-lab-nginx
domain=paddock.localhost
warning="lab profile (PADDOCK_HOST=lab): not for production — see docs/operations/lab-install.md"
started=$SECONDS
current="setup"

step() {
  current="$1"
  printf '\n== [%s] %s\n' "$(date -u +%H:%M:%S)" "$1"
}
fail() {
  echo "smoke-lab: $*" >&2
  exit 1
}
# The project is pinned here, not only in .env: an exported PADDOCK_PROJECT, or a call before .env names it, must never
# reach (and in the trap tear down) the default project, which may be a development stack on the same host.
lab_paddock() { (cd "$W/lab" && PADDOCK_PROJECT=paddock-lab PADDOCK_COMPOSE_EXTRA="$ci_overlay" ./paddock "$@"); }

# Logs of the project and of Nginx, then Nginx and the project with its volumes removed; also after a failure.
finish() {
  local rc=$?
  set +e
  if ((rc != 0)); then echo "smoke-lab: step '$current' failed" >&2; fi
  mkdir -p "$W/logs"
  [[ -f "$W/lab/.env" ]] && lab_paddock logs >"$W/logs/paddock-lab.log" 2>&1
  docker logs "$nginx_name" >"$W/logs/nginx.log" 2>&1
  docker rm -f "$nginx_name" >/dev/null 2>&1
  [[ -f "$W/lab/.env" ]] && lab_paddock down --volumes >/dev/null 2>&1
  echo "smoke-lab: $( ((rc == 0)) && echo passed || echo failed) after $((SECONDS - started)) s (logs: $W/logs/)"
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

# Steps 1–8 run the commands of docs/operations/lab-install.md section 5 in its order; deviations for CI are named
# where they occur.
step "1 extract and verify"
mkdir -p "$W/lab"
tar -xzf "$tarball" -C "$W/lab" --strip-components=1
(cd "$W/lab" && ./paddock verify)
echo "bundle version $(sed -n 's/^version=//p' "$W/lab/VERSION")"

step "2 settings"
addr="$(hostname -I | awk '{print $1}')"
[[ -n "$addr" ]] || fail "no primary address"
env_file="$W/lab/.env"
cp "$W/lab/.env.lab.example" "$env_file"
setenv "$env_file" PADDOCK_PROJECT paddock-lab
setenv "$env_file" PADDOCK_DOMAIN "$domain"
setenv "$env_file" PADDOCK_PUBLIC_ADMIN_URL "https://admin.$domain"
setenv "$env_file" PADDOCK_PUBLIC_DEVICE_URL "https://device.$domain"
setenv "$env_file" PADDOCK_INTERCONNECT_ADDR 127.0.0.1
setenv "$env_file" PADDOCK_LAB_HTTP_PORT 8080
setenv "$env_file" PADDOCK_LAB_PROXY_ADDR "$addr"
# The guide sets the two same-host values after `up --infra`, from the gateways Docker chose; the overlay pins the
# subnets, so they are known now. Nginx on this host reaches Caddy's loopback port through Docker, which presents it
# as the gateway of network cp. The api's default route is network audit-index, so its calls to Authentik's API
# through Nginx come from that subnet.
setenv "$env_file" PADDOCK_EDGE_TRUSTED_PROXIES 172.30.0.1
setenv "$env_file" PADDOCK_ADMIN_ALLOWED_CIDRS "172.30.0.0/24 127.0.0.0/8 $addr/32"
setenv "$env_file" PADDOCK_INTERNAL_CIDRS "172.30.0.0/24 172.30.1.0/24 $addr/32"
setenv "$env_file" PADDOCK_LAB_BACKUP no
# CI only: the throwaway CA and the certificate of the five names, before anything starts.
mkdir -p "$W/tls"
names=(admin auth device bundles fleet)
san="$(printf "DNS:%s.$domain," "${names[@]}")"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Paddock lab smoke CA" \
  -keyout "$W/tls/ca.key" -out "$W/tls/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=admin.$domain" \
  -keyout "$W/tls/privkey.pem" -out "$W/tls/leaf.csr" 2>/dev/null
openssl x509 -req -in "$W/tls/leaf.csr" -CA "$W/tls/ca.crt" -CAkey "$W/tls/ca.key" -CAcreateserial -days 2 \
  -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "${san%,}") -out "$W/tls/fullchain.pem" \
  2>/dev/null
chmod 644 "$W/tls/ca.crt"

step "3 secrets"
lab_paddock secrets

step "4 images and infrastructure"
# `./paddock pull` is skipped: a local bundle names local images that no registry has; `up` pulls what is missing.
lab_paddock up --infra

step "5 OpenBao"
lab_paddock bao operator init -key-shares=5 -key-threshold=3 -format=json >"$W/init.json"
root_token="$(sed -n 's/.*"root_token": *"\([^"]*\)".*/\1/p' "$W/init.json")"
[[ -n "$root_token" ]] || fail "no root token in the OpenBao init output"
mapfile -t shares < <(awk '/"unseal_keys_b64"/ { f = 1; next } f && /\]/ { f = 0 } f { gsub(/[ ",]/, ""); print }' \
  "$W/init.json" | head -3)
((${#shares[@]} == 3)) || fail "no unseal shares in the OpenBao init output"
# Non-interactive form of `./paddock bao operator unseal`: the shares on stdin, never on a command line.
for share in "${shares[@]}"; do printf '%s' "$share" | lab_paddock bao write sys/unseal key=- >/dev/null; done
lab_paddock bao status </dev/null | grep -Eq '^Sealed +false' || fail "OpenBao is still sealed"
export BAO_TOKEN="$root_token"
lab_paddock bootstrap openbao
lab_paddock bao token revoke -self </dev/null
unset BAO_TOKEN

step "6 buckets and Fleet"
lab_paddock bootstrap buckets
lab_paddock bootstrap audit-bucket
lab_paddock bootstrap fleet

step "7 release keys"
# Throwaway key pairs in place of the installation's offline ones; only the public keys go to the host.
mkdir -p "$W/keys" "$W/lab/.secrets/release-production"
for key in minisign revoke-minisign; do
  (cd "$repo/agent" && GOTOOLCHAIN=auto go run aead.dev/minisign/cmd/minisign -G -W -p "$W/keys/$key.pub" \
    -s "$W/keys/$key.key" </dev/null >/dev/null)
  cp "$W/keys/$key.pub" "$W/lab/.secrets/release-production/$key.pub"
done

step "8 proxy, check and start"
# The proxy: the shipped reference configuration with the CI values (the operator edits the same three places).
sed -e "s/paddock\.example\.org/$domain/g" -e 's/192\.0\.2\.10:8080/127.0.0.1:8080/' \
  -e "s|/etc/letsencrypt/live/$domain/fullchain.pem|/tls/fullchain.pem|" \
  -e "s|/etc/letsencrypt/live/$domain/privkey.pem|/tls/privkey.pem|" \
  "$W/lab/nginx/paddock.conf.example" >"$W/nginx.conf"
grep -q 'ssl_certificate     /tls/fullchain.pem;' "$W/nginx.conf" ||
  fail "the certificate path of the Nginx example changed"
grep -q 'ssl_certificate_key /tls/privkey.pem;' "$W/nginx.conf" || fail "the key path of the Nginx example changed"
grep -q 'server 127.0.0.1:8080;' "$W/nginx.conf" || fail "the upstream of the Nginx example changed"
nginx_image="$(sed -n 's/^NGINX_IMAGE=//p' "$repo/deploy/compose/versions.env")"
[[ -n "$nginx_image" ]] || fail "NGINX_IMAGE is not set in deploy/compose/versions.env"
docker pull -q "$nginx_image" >/dev/null
docker run -d --name "$nginx_name" --network host -v "$W/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$W/tls:/tls:ro" "$nginx_image" >/dev/null
# check_with_warning <file> [--online]: ./paddock check passes and its first output line is the lab warning.
check_with_warning() {
  local out="$1"
  shift
  lab_paddock check "$@" 2>&1 | tee "$out"
  [[ "$(head -1 "$out")" == "$warning" ]] || fail "./paddock check $* does not begin with the lab warning line"
}
check_with_warning "$W/check.txt"
check_with_warning "$W/check-online.txt" --online
lab_paddock up
lab_paddock ps
"$here/assert-hardening.sh" paddock-lab

step "9 probes"
# probe <name> <method> <path> [curl arguments]: the HTTP status through Nginx on 127.0.0.1:443, with the throwaway CA.
probe() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 30 --cacert "$W/tls/ca.crt" \
    --resolve "$1:443:127.0.0.1" -X "$2" "${@:4}" "https://$1$3" || true
}
# direct <path> [curl arguments]: the HTTP status of Caddy's plain-HTTP port for admin.<domain>, bypassing Nginx.
direct() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "Host: admin.$domain" "${@:2}" "http://127.0.0.1:8080$1" ||
    true
}
# peer <path> [wget arguments]: the HTTP status of Caddy for admin.<domain> from a container on network cp, a peer
# that the edge allow list admits but that is not the trusted proxy.
peer() {
  { docker run --rm --network paddock-lab_cp --entrypoint wget "$caddy_image" -S -O /dev/null -T 10 \
    --header "Host: admin.$domain" "${@:2}" "http://caddy:80$1" 2>&1 || true; } |
    sed -n 's/^ *HTTP\/[0-9.]* \([0-9]*\).*/\1/p' | tail -1
}
# expect <pattern> <description> <command...>: retries the command for 120 s while the roles warm up.
expect() {
  local pattern="$1" what="$2" code=
  shift 2
  for _ in $(seq 1 40); do
    code="$("$@")"
    if [[ "$code" =~ ^($pattern)$ ]]; then
      echo "$what -> $code"
      return 0
    fi
    sleep 3
  done
  fail "$what answered '$code', want $pattern"
}
forged=(-H "X-Forwarded-For: 203.0.113.9")
expect 200 "GET https://admin.$domain/" probe "admin.$domain" GET /
discovery="/application/o/paddock-portal/.well-known/openid-configuration"
expect 200 "GET https://auth.$domain$discovery" probe "auth.$domain" GET "$discovery"
issuer="$(curl -s --max-time 30 --cacert "$W/tls/ca.crt" --resolve "auth.$domain:443:127.0.0.1" \
  "https://auth.$domain$discovery" | sed -n 's/.*"issuer": *"\([^"]*\)".*/\1/p')"
[[ "$issuer" == "https://auth.$domain/"* ]] || fail "the OIDC issuer is '$issuer', want https://auth.$domain/…"
echo "issuer $issuer"
expect '4[0-9][0-9]' "POST https://device.$domain/v1/checkin" probe "device.$domain" POST /v1/checkin
expect 403 "GET https://bundles.$domain/" probe "bundles.$domain" GET /
expect 404 "GET https://fleet.$domain/" probe "fleet.$domain" GET /
# Nginx replaces a client's X-Forwarded-For with the peer address: honoured, 203.0.113.9 would be refused by the edge
# allow list (403) on the portal.
expect 200 "GET https://admin.$domain/ with a forged X-Forwarded-For" probe "admin.$domain" GET / "${forged[@]}"
expect '401|403' "GET https://admin.$domain/api/v1/me with a forged X-Forwarded-For" \
  probe "admin.$domain" GET /api/v1/me "${forged[@]}"
head -c $((20 * 1024 * 1024)) /dev/zero >"$W/20MiB.bin"
expect 403 "PUT https://bundles.$domain/paddock-escrow/org/x (20 MiB)" \
  probe "bundles.$domain" PUT /paddock-escrow/org/x -T "$W/20MiB.bin"
rm -f "$W/20MiB.bin"
expect 200 "GET http://127.0.0.1:8080/ (Host admin.$domain)" direct /
# Deviation from plan M8a decision 18, which sends the forged header to 127.0.0.1:8080: in the same-host topology a
# loopback client is indistinguishable from the proxy, because Docker presents every loopback client of the published
# port as the gateway of network cp, the trusted proxy. A peer on the network is not trusted: honoured, its
# 203.0.113.9 would be refused by the edge allow list (403).
caddy_image="$(sed -n 's/^CADDY_IMAGE=//p' "$W/lab/versions.env")"
expect 200 "GET http://caddy/ (Host admin.$domain) from a peer on network cp with a forged X-Forwarded-For" \
  peer / --header "X-Forwarded-For: 203.0.113.9"
# api_authentik: the status of Authentik's API for the api's service token, sent from the api container's network
# namespace through Nginx, the path of the api's own calls. The token stays inside the container, off every
# command line.
api_authentik() {
  docker run --rm --network "container:$api_id" -v "$W/tls/ca.crt:/ca.crt:ro" \
    -v "$W/lab/.secrets/authentik_service_token:/token:ro" --entrypoint sh "$nginx_image" -c \
    'printf "Authorization: Bearer %s\n" "$(cat /token)" >/tmp/auth && curl -s -o /dev/null -w "%{http_code}" \
      --max-time 30 --cacert /ca.crt --resolve "$1:443:$2" -H @/tmp/auth \
      "https://$1/api/v3/core/brands/?default=true"' \
    sh "auth.$domain" "$addr" || true
}
api_id="$(lab_paddock compose ps -q paddock-api)"
[[ -n "$api_id" ]] || fail "no paddock-api container"
# A 403 here is the edge refusing the api's source address: PADDOCK_INTERNAL_CIDRS misses the subnet of its route.
expect 200 "GET https://auth.$domain/api/v3/core/brands/ as the api, through Nginx" api_authentik

step "10 certificate probe of the worker"
sleep 90
# The full log, not ./paddock logs' last 300 lines, so an early probe failure cannot scroll out of view.
if lab_paddock compose logs --no-color paddock-worker | grep -q 'TLS probe failed'; then
  lab_paddock compose logs --no-color paddock-worker | grep 'TLS probe failed' | tail -5 >&2
  fail "the worker's certificate probe failed"
fi
echo "no TLS probe failure in the worker's log"

step "11 idempotence"
ids() { docker ps -aq --no-trunc --filter "label=com.docker.compose.project=paddock-lab" | sort; }
before="$(ids)"
lab_paddock up
after="$(ids)"
[[ "$before" == "$after" ]] || fail "a second ./paddock up recreated containers"

step "12 automatic unseal"
# Plan M8u gate U6 (ADR 0035), after the idempotence step so that the restarts below do not count as recreated
# containers there. CI stand-in for the portal: the acknowledgement row is set directly; the shares of step 5 reach
# ./paddock auto-unseal enable on stdin, never on a command line. Every output of this step is kept in au_log and
# searched for the shares at the end.
au_log="$W/auto-unseal.log"
: >"$au_log"
lab_paddock compose exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d paddock -c \
  "UPDATE openbao_auto_unseal SET state='enabled', disclaimer_version='2026-10-17', acknowledgement='I understand and accept the risk', acknowledged_by='smoke test', acknowledged_at=now() WHERE id=1" \
  </dev/null 2>&1 | tee -a "$au_log"
printf '%s\n' "${shares[@]}" | lab_paddock auto-unseal enable 2>&1 | tee -a "$au_log"
check_with_warning "$W/check-auto-unseal-on.txt"
cat "$W/check-auto-unseal-on.txt" >>"$au_log"
grep -q '^PASS  openbao auto-unseal$' "$W/check-auto-unseal-on.txt" ||
  fail "./paddock check does not pass openbao auto-unseal with automatic unseal on"
grep -q 'RR-43' "$W/check-auto-unseal-on.txt" || fail "./paddock check does not name RR-43 on the lab host"
lab_paddock compose restart openbao </dev/null 2>&1 | tee -a "$au_log"
unsealed=""
for _ in $(seq 1 30); do
  if lab_paddock bao status </dev/null 2>/dev/null | grep -Eq '^Sealed +false'; then
    unsealed=1
    break
  fi
  sleep 2
done
[[ -n "$unsealed" ]] || fail "OpenBao is not unsealed automatically within 60 s of a restart"
lab_paddock auto-unseal status </dev/null 2>&1 | tee -a "$au_log" | grep -q '^shares file: present$' ||
  fail "./paddock auto-unseal status does not report the shares file"
# The disable below removes the unsealer's container and with it its log, so the log is captured here.
lab_paddock logs paddock-unsealer >"$W/auto-unseal-unsealer.log" 2>&1 </dev/null
grep -q 'OpenBao unsealed automatically' "$W/auto-unseal-unsealer.log" ||
  fail "the log of paddock-unsealer was not captured (no automatic unseal in it)"
lab_paddock auto-unseal disable </dev/null 2>&1 | tee -a "$au_log"
[[ ! -e "$W/lab/.secrets/openbao/auto-unseal-shares" ]] || fail "the shares file is still on the host after disable"
grep -q '^PADDOCK_AUTO_UNSEAL=no$' "$W/lab/.env" || fail ".env does not set PADDOCK_AUTO_UNSEAL=no after disable"
if lab_paddock ps --format '{{.Service}}' </dev/null | grep -qx paddock-unsealer; then
  fail "paddock-unsealer still runs after disable"
fi
check_with_warning "$W/check-auto-unseal-off.txt"
cat "$W/check-auto-unseal-off.txt" >>"$au_log"
grep -A1 '^PASS  openbao auto-unseal$' "$W/check-auto-unseal-off.txt" | grep -q 'automatic unseal is off' ||
  fail "./paddock check does not report automatic unseal as off"
lab_paddock logs >"$W/auto-unseal-compose.log" 2>&1 </dev/null
for share in "${shares[@]}"; do
  if grep -qF -- "$share" "$au_log" "$W/auto-unseal-unsealer.log" "$W/auto-unseal-compose.log" "$W"/check*.txt; then
    fail "an unseal share appears in the output or the logs"
  fi
done
echo "automatic unseal: enabled, unsealed after a restart, disabled; no share in any output or log"

step "13 done"
