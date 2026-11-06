#!/usr/bin/env bash
# Smoke test of an operator bundle (plan M7b decision 25, §6.2): follows the installation guide on one machine with two
# bundle directories and two Compose projects, paddock-cp and paddock-audit. The running control plane adds the CI
# overlay compose.ci.yaml (internal TLS instead of ACME); `./paddock check`
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
SMOKE_NAME=smoke CP_DIR="$W/cp" AUDIT_DIR="$W/audit" CP_OVERLAY="$ci_overlay"
# shellcheck source=lib-smoke.sh
. "$here/lib-smoke.sh"
trap smoke_finish EXIT

step "1 extract and verify"
smoke_extract "$tarball"

step "2 settings"
smoke_settings

step "3 secrets"
smoke_secrets

step "4 audit host: infrastructure, audit bucket"
smoke_audit_infra

step "5 control plane: infrastructure, OpenBao, buckets, Fleet"
smoke_cp_infra

step "6 production checks"
smoke_checks

step "7 start both hosts"
smoke_start

step "8 probes"
smoke_probes
smoke_backup_waits
if [[ -n "$agent_artifacts" ]]; then smoke_agent_release "$agent_artifacts"; fi

step "9 idempotence"
smoke_idempotence

step "10 done"
