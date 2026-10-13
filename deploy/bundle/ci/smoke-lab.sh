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
lab_paddock() { (cd "$W/lab" && PADDOCK_COMPOSE_EXTRA="$ci_overlay" ./paddock "$@"); }

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
# Nginx on this host reaches Caddy's loopback port through Docker, which presents it as the gateway of network cp.
setenv "$env_file" PADDOCK_EDGE_TRUSTED_PROXIES 172.30.0.1
setenv "$env_file" PADDOCK_ADMIN_ALLOWED_CIDRS "172.30.0.0/24 127.0.0.0/8 $addr/32"
setenv "$env_file" PADDOCK_INTERNAL_CIDRS "172.30.0.0/24 $addr/32"
setenv "$env_file" PADDOCK_LAB_BACKUP no

step "3 throwaway CA and certificate of the five names"
mkdir -p "$W/tls"
names=(admin auth device bundles fleet)
san="$(printf "DNS:%s.$domain," "${names[@]}")"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Paddock lab smoke CA" \
  -keyout "$W/tls/ca.key" -out "$W/tls/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=admin.$domain" \
  -keyout "$W/tls/privkey.pem" -out "$W/tls/leaf.csr" 2>/dev/null
openssl x509 -req -in "$W/tls/leaf.csr" -CA "$W/tls/ca.crt" -CAkey "$W/tls/ca.key" -CAcreateserial -days 2 \
  -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "${san%,}") -out "$W/tls/fullchain.pem" 2>/dev/null
chmod 644 "$W/tls/ca.crt"

step "4 secrets"
lab_paddock secrets
mkdir -p "$W/keys" "$W/lab/.secrets/release-production"
for key in minisign revoke-minisign; do
  (cd "$repo/agent" && GOTOOLCHAIN=auto go run aead.dev/minisign/cmd/minisign -G -W -p "$W/keys/$key.pub" \
    -s "$W/keys/$key.key" </dev/null >/dev/null)
  cp "$W/keys/$key.pub" "$W/lab/.secrets/release-production/$key.pub"
done
: >"$W/lab/.secrets/caddy-root.crt"
chmod 666 "$W/lab/.secrets/caddy-root.crt"

step "5 infrastructure, OpenBao, buckets, audit bucket, Fleet"
lab_paddock up --infra
lab_paddock bao operator init -key-shares=5 -key-threshold=3 -format=json >"$W/init.json"
root_token="$(sed -n 's/.*"root_token": *"\([^"]*\)".*/\1/p' "$W/init.json")"
[[ -n "$root_token" ]] || fail "no root token in the OpenBao init output"
mapfile -t shares < <(awk '/"unseal_keys_b64"/ { f = 1; next } f && /\]/ { f = 0 } f { gsub(/[ ",]/, ""); print }' \
  "$W/init.json" | head -3)
((${#shares[@]} == 3)) || fail "no unseal shares in the OpenBao init output"
# Shares on stdin, never on a command line.
for share in "${shares[@]}"; do printf '%s' "$share" | lab_paddock bao write sys/unseal key=- >/dev/null; done
lab_paddock bao status </dev/null | grep -Eq '^Sealed +false' || fail "OpenBao is still sealed"
export BAO_TOKEN="$root_token"
lab_paddock bootstrap openbao
unset BAO_TOKEN
lab_paddock bootstrap buckets
lab_paddock bootstrap audit-bucket
lab_paddock bootstrap fleet

step "6 production checks"
# check_with_warning <file> [--online]: ./paddock check passes and its first output line is the lab warning.
check_with_warning() {
  local out="$1"
  shift
  lab_paddock check "$@" 2>&1 | tee "$out"
  [[ "$(head -1 "$out")" == "$warning" ]] || fail "./paddock check $* does not begin with the lab warning line"
}
check_with_warning "$W/check.txt"
check_with_warning "$W/check-online.txt" --online

step "7 Nginx with the shipped reference configuration"
# Before ./paddock up: the roles' readiness needs Authentik's discovery document through Nginx.
sed -e "s/paddock\.example\.org/$domain/g" -e 's/192\.0\.2\.10:8080/127.0.0.1:8080/' \
  -e "s|/etc/letsencrypt/live/$domain/fullchain.pem|/tls/fullchain.pem|" \
  -e "s|/etc/letsencrypt/live/$domain/privkey.pem|/tls/privkey.pem|" \
  "$W/lab/nginx/paddock.conf.example" >"$W/nginx.conf"
grep -q 'ssl_certificate     /tls/fullchain.pem;' "$W/nginx.conf" || fail "the certificate path of the Nginx example changed"
grep -q 'ssl_certificate_key /tls/privkey.pem;' "$W/nginx.conf" || fail "the key path of the Nginx example changed"
grep -q 'server 127.0.0.1:8080;' "$W/nginx.conf" || fail "the upstream of the Nginx example changed"
nginx_image="$(sed -n 's/^NGINX_IMAGE=//p' "$repo/deploy/compose/versions.env")"
[[ -n "$nginx_image" ]] || fail "NGINX_IMAGE is not set in deploy/compose/versions.env"
docker pull -q "$nginx_image" >/dev/null
docker run -d --name "$nginx_name" --network host -v "$W/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$W/tls:/tls:ro" "$nginx_image" >/dev/null

step "8 start the lab host"
lab_paddock up

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
# Docker presents every loopback client of the published port as the gateway of network cp, the trusted proxy; a peer
# on the network is not: honoured, its 203.0.113.9 would be refused by the edge allow list (403).
caddy_image="$(sed -n 's/^CADDY_IMAGE=//p' "$W/lab/versions.env")"
expect 200 "GET http://caddy/ (Host admin.$domain) from a peer on network cp with a forged X-Forwarded-For" \
  peer / --header "X-Forwarded-For: 203.0.113.9"

step "10 certificate probe of the worker"
sleep 90
if lab_paddock logs paddock-worker | grep -q 'TLS probe failed'; then
  lab_paddock logs paddock-worker | grep 'TLS probe failed' | tail -5 >&2
  fail "the worker's certificate probe failed"
fi
echo "no TLS probe failure in the worker's log"

step "11 idempotence"
ids() { docker ps -aq --no-trunc --filter "label=com.docker.compose.project=paddock-lab" | sort; }
before="$(ids)"
lab_paddock up
after="$(ids)"
[[ "$before" == "$after" ]] || fail "a second ./paddock up recreated containers"

step "12 done"
