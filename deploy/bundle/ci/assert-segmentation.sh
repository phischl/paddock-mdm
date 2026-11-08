#!/usr/bin/env bash
# Asserts the network segmentation of a running control plane (ADR 0051 decision 1): from inside Caddy no datastore
# answers, neither by name nor by its address on network data, while a probe container on data reaches each of them
# (so a broken probe cannot pass); the ops port 9090 of the worker, the escrow-reader and the revocation-issuer and the
# escrow-reader's API answer no container on edge, by name or by edge address, while 9090 answers on data
# (decisions-alpha10 A10-1); RabbitMQ's management port answers no other container and rabbitmqctl still works inside
# the broker.
#   assert-segmentation.sh <project>
# Exit 0: every assertion holds; 1: a finding (named on stderr); 2: usage.
set -euo pipefail

project="${1:-}"
[[ -n "$project" && $# -eq 1 ]] || {
  echo "usage: assert-segmentation.sh <project>" >&2
  exit 2
}

failed=0
finding() {
  echo "assert-segmentation: $*" >&2
  failed=1
}
# container <service>: the ID of the service's running container.
container() {
  docker ps -q --filter "label=com.docker.compose.project=$project" --filter "label=com.docker.compose.service=$1" |
    head -1
}
# reachable <docker arguments...>: whether nc connects within 3 s.
reachable() { "$@" >/dev/null 2>&1; }

caddy="$(container caddy)"
rabbitmq="$(container rabbitmq)"
[[ -n "$caddy" && -n "$rabbitmq" ]] || {
  echo "assert-segmentation: no running caddy or rabbitmq in project $project" >&2
  exit 1
}
image="$(docker inspect --format '{{.Config.Image}}' "$caddy")"
data="${project}_data"
for target in postgres:5432 openbao:8200 valkey:6379 rabbitmq:5672; do
  service="${target%%:*}" port="${target#*:}"
  id="$(container "$service")"
  if [[ -z "$id" ]]; then
    finding "no running $service"
    continue
  fi
  ip="$(docker inspect --format "{{(index .NetworkSettings.Networks \"$data\").IPAddress}}" "$id" 2>/dev/null || true)"
  [[ -n "$ip" ]] || finding "$service has no address on $data"
  if ! reachable docker run --rm --network "$data" --entrypoint nc "$image" -z -w 3 "$service" "$port"; then
    finding "$service:$port does not answer on $data (the probe proves nothing)"
  fi
  if reachable docker exec "$caddy" nc -z -w 3 "$service" "$port"; then finding "caddy reaches $service:$port"; fi
  if [[ -n "$ip" ]] && reachable docker exec "$caddy" nc -z -w 3 "$ip" "$port"; then
    finding "caddy reaches $service at $ip:$port"
  fi
done
edge="${project}_edge"
for target in paddock-worker:9090 paddock-escrow-reader:9090 paddock-revocation-issuer:9090 paddock-escrow-reader:8080; do
  service="${target%%:*}" port="${target#*:}"
  id="$(container "$service")"
  if [[ -z "$id" ]]; then
    finding "no running $service"
    continue
  fi
  if [[ "$port" == 9090 ]] &&
    ! reachable docker run --rm --network "$data" --entrypoint nc "$image" -z -w 3 "$service" "$port"; then
    finding "$service:$port does not answer on $data (the probe proves nothing)"
  fi
  ip="$(docker inspect --format "{{(index .NetworkSettings.Networks \"$edge\").IPAddress}}" "$id" 2>/dev/null || true)"
  [[ -n "$ip" ]] || finding "$service has no address on $edge"
  if reachable docker exec "$caddy" nc -z -w 3 "$service" "$port"; then finding "caddy reaches $service:$port"; fi
  if [[ -n "$ip" ]] && reachable docker exec "$caddy" nc -z -w 3 "$ip" "$port"; then
    finding "caddy reaches $service at $ip:$port"
  fi
done
if reachable docker run --rm --network "$data" --entrypoint nc "$image" -z -w 3 rabbitmq 15672; then
  finding "rabbitmq's management port 15672 answers on $data"
fi
docker exec "$rabbitmq" rabbitmqctl -q list_vhosts >/dev/null 2>&1 || finding "rabbitmqctl fails inside rabbitmq"
((failed == 0)) && echo "assert-segmentation: $project segmented"
exit "$failed"
