#!/usr/bin/env bash
# Tests of assert-segmentation.sh (ADR 0051 decision 1, `make test`): a segmented project passes; Caddy reaching a
# datastore by name or by address, a probe that reaches nothing, Caddy reaching an ops port or the escrow-reader's API
# (decisions-alpha10 A10-1), RabbitMQ's management port answering on data and a failing rabbitmqctl each fail naming the
# finding.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
check() {
  if [[ "$2" == "$3" ]]; then echo "ok   $1"; else
    echo "FAIL $1: got '$2', want '$3'"
    failures=$((failures + 1))
  fi
}

# A docker stub: every container runs, its ID is its service name, its address on data is 10.9.0.<n> and on edge
# 10.8.0.<n>. A connection
# succeeds when "<source> <host> <port>" is a line of $OPEN (source caddy for docker exec, data for docker run);
# rabbitmqctl succeeds unless $CTL_FAILS is set.
mkdir -p "$work/bin"
cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  ps) sed -n 's/.*com.docker.compose.service=\([a-z-]*\).*/\1/p' <<<"$*" ;;
  inspect)
    case "$*" in
      *Config.Image*) echo caddy:test ;;
      *p_edge*) case "${*: -1}" in paddock-worker) echo 10.8.0.5 ;; paddock-escrow-reader) echo 10.8.0.6 ;;
        paddock-revocation-issuer) echo 10.8.0.7 ;; esac ;;
      *NetworkSettings*) case "${*: -1}" in postgres) echo 10.9.0.1 ;; openbao) echo 10.9.0.2 ;; valkey) echo 10.9.0.3 ;;
        rabbitmq) echo 10.9.0.4 ;; esac ;;
    esac ;;
  exec)
    if [[ "$3" == rabbitmqctl ]]; then [[ -z "${CTL_FAILS:-}" ]]; exit; fi
    grep -qxF "caddy ${*: -2:1} ${*: -1}" <<<"$OPEN" ;;
  run) grep -qxF "data ${*: -2:1} ${*: -1}" <<<"$OPEN" ;;
esac
EOF
chmod +x "$work/bin/docker"
data_open=$'data postgres 5432\ndata openbao 8200\ndata valkey 6379\ndata rabbitmq 5672\ndata paddock-worker 9090'
data_open+=$'\ndata paddock-escrow-reader 9090\ndata paddock-revocation-issuer 9090'
assert() {
  local rc=0
  OPEN="$1" CTL_FAILS="${2:-}" PATH="$work/bin:$PATH" "$here/assert-segmentation.sh" p >/dev/null 2>"$work/err" || rc=$?
  echo "$rc $(head -1 "$work/err")"
}

check "segmented project" "$(assert "$data_open")" "0 "
check "caddy reaches postgres by name" "$(assert "$data_open"$'\ncaddy postgres 5432')" \
  "1 assert-segmentation: caddy reaches postgres:5432"
check "caddy reaches openbao by address" "$(assert "$data_open"$'\ncaddy 10.9.0.2 8200')" \
  "1 assert-segmentation: caddy reaches openbao at 10.9.0.2:8200"
check "probe reaches nothing" "$(assert "")" \
  "1 assert-segmentation: postgres:5432 does not answer on p_data (the probe proves nothing)"
check "caddy reaches the worker's ops port by name" "$(assert "$data_open"$'\ncaddy paddock-worker 9090')" \
  "1 assert-segmentation: caddy reaches paddock-worker:9090"
check "caddy reaches the revocation-issuer's ops port by address" \
  "$(assert "$data_open"$'\ncaddy 10.8.0.7 9090')" "1 assert-segmentation: caddy reaches paddock-revocation-issuer at 10.8.0.7:9090"
check "caddy reaches the escrow-reader's API by address" "$(assert "$data_open"$'\ncaddy 10.8.0.6 8080')" \
  "1 assert-segmentation: caddy reaches paddock-escrow-reader at 10.8.0.6:8080"
check "ops port silent on data" "$(assert "${data_open/$'\ndata paddock-worker 9090'/}")" \
  "1 assert-segmentation: paddock-worker:9090 does not answer on p_data (the probe proves nothing)"
check "management port answers" "$(assert "$data_open"$'\ndata rabbitmq 15672')" \
  "1 assert-segmentation: rabbitmq's management port 15672 answers on p_data"
check "rabbitmqctl fails" "$(assert "$data_open" yes)" "1 assert-segmentation: rabbitmqctl fails inside rabbitmq"
check "usage" "$(PATH="$work/bin:$PATH" "$here/assert-segmentation.sh" >/dev/null 2>&1; echo $?)" 2

((failures == 0)) || exit 1
