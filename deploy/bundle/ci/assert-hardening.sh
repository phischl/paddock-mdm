#!/usr/bin/env bash
# Asserts the container hardening of running Compose projects (plan M8s decision 37): every Paddock role and Caddy
# drops every capability and may not gain privileges, and every container bounds its number of processes.
#   assert-hardening.sh <project>...
# Exit 0: every container passes; 1: a finding (named on stderr) or no container at all; 2: usage.
set -euo pipefail

(($#)) || {
  echo "usage: assert-hardening.sh <project>..." >&2
  exit 2
}

failed=0
seen=0
for project in "$@"; do
  mapfile -t containers < <(docker ps -aq --filter "label=com.docker.compose.project=$project")
  ((${#containers[@]})) || continue
  while read -r name service capdrop secopt pids; do
    seen=$((seen + 1))
    echo "$name $capdrop $secopt $pids"
    if [[ "$service" == paddock-* || "$service" == caddy ]]; then
      [[ "$capdrop" == *'"ALL"'* ]] || { echo "assert-hardening: $name does not drop ALL capabilities" >&2; failed=1; }
      [[ "$secopt" == *'"no-new-privileges:true"'* ]] ||
        { echo "assert-hardening: $name lacks no-new-privileges:true" >&2; failed=1; }
    fi
    [[ "$pids" =~ ^[0-9]+$ ]] && ((pids > 0)) || { echo "assert-hardening: $name has no pids limit ($pids)" >&2; failed=1; }
  done < <(docker inspect --format '{{.Name}} {{index .Config.Labels "com.docker.compose.service"}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}} {{.HostConfig.PidsLimit}}' "${containers[@]}")
done
((seen)) || { echo "assert-hardening: no container in project(s) $*" >&2; exit 1; }
exit "$failed"
