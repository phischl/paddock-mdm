#!/usr/bin/env bash
# Asserts the container hardening of running Compose projects against the matrix (plan M8s decision 37, plan M12h
# decisions 10 and 11): every container drops all capabilities, may not gain privileges, has a pids and a memory limit
# and adds no capability, unless deploy/compose/hardening-exceptions.yaml lists its service with that setting (a listed
# cap_add must match exactly). The check is the one `./paddock check --online` prints (`paddock-server
# check-containers`), run from the projects' own server image, so the smoke stacks prove the shipped check.
#   assert-hardening.sh <project>...
# Environment: HARDENING_EXCEPTIONS (default: this tree's deploy/compose/hardening-exceptions.yaml), PADDOCK_IMAGE
# (default: the image of the projects' paddock-api or paddock-audit-writer container).
# Exit 0: every container passes; 1: a finding (the FAIL lines name each container) or no container at all; 2: usage.
set -euo pipefail

(($#)) || {
  echo "usage: assert-hardening.sh <project>..." >&2
  exit 2
}
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exceptions="${HARDENING_EXCEPTIONS:-$(cd "$here/../../compose" && pwd)/hardening-exceptions.yaml}"
[[ -f "$exceptions" ]] || {
  echo "assert-hardening: no exceptions file $exceptions" >&2
  exit 2
}

containers=()
for project in "$@"; do
  mapfile -t ids < <(docker ps -aq --filter "label=com.docker.compose.project=$project")
  containers+=("${ids[@]}")
done
((${#containers[@]})) || { echo "assert-hardening: no container in project(s) $*" >&2; exit 1; }

image="${PADDOCK_IMAGE:-}"
while read -r name service img capadd capdrop secopt pids mem; do
  echo "$name $capadd $capdrop $secopt $pids $mem"
  if [[ -z "$image" && ("$service" == paddock-api || "$service" == paddock-audit-writer) ]]; then image="$img"; fi
done < <(docker inspect --format '{{.Name}} {{index .Config.Labels "com.docker.compose.service"}} {{.Config.Image}} {{json .HostConfig.CapAdd}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}} {{.HostConfig.PidsLimit}} {{.HostConfig.Memory}}' "${containers[@]}")
[[ -n "$image" ]] || { echo "assert-hardening: no paddock-api or paddock-audit-writer container in $*; set PADDOCK_IMAGE" >&2; exit 1; }

docker inspect "${containers[@]}" |
  docker run --rm -i --network none --cap-drop ALL --security-opt no-new-privileges:true --read-only \
    -v "$exceptions:/paddock/hardening-exceptions.yaml:ro" "$image" \
    check-containers --exceptions /paddock/hardening-exceptions.yaml
