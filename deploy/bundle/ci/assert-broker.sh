#!/usr/bin/env bash
# Asserts that a control plane's RabbitMQ has exactly the permissions of this tree's definitions on vhost paddock after
# an upgrade (PDK-1017, decisions main §44): above all the audit writer may publish to paddock.offboarding and the
# worker may read worker.offboarding, which the upgrade's step broker applied without a restart. Every user of the
# definitions must have its patterns and no other user may have permissions on the vhost.
#   assert-broker.sh <project>
# Only user names and permission patterns are read and printed; the definitions' passwords are never read.
# Exit 0: the permissions match; 1: a finding (named on stderr); 2: usage.
set -euo pipefail

project="${1:-}"
if (($# != 1)) || [[ ! "$project" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
  echo "usage: assert-broker.sh <project>" >&2
  exit 2
fi
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
template="$here/../../compose/rabbitmq/definitions.json.tmpl"

container="$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter label=com.docker.compose.service=rabbitmq)"
if [[ -z "$container" || "$container" == *$'\n'* ]]; then
  echo "assert-broker: no single running rabbitmq container of $project" >&2
  exit 1
fi
listing="$(docker exec -e 'RABBITMQ_CTL_ERL_ARGS=+S 1:1 +SDcpu 1:1 +SDio 1 +A 1' "$container" \
  rabbitmqctl -q list_permissions -p paddock --formatter json)"
LISTING="$listing" python3 -I - "$template" <<'PY'
import json, os, sys
want = {p["user"]: (p["configure"], p["write"], p["read"])
        for p in json.load(open(sys.argv[1]))["permissions"] if p["vhost"] == "paddock"}
got = {p["user"]: (p["configure"], p["write"], p["read"]) for p in json.loads(os.environ["LISTING"])}
problems = []
for user, perms in sorted(want.items()):
    if got.get(user) != perms:
        problems.append("%s: has %s, want %s" % (user, got.get(user), perms))
for user in sorted(set(got) - set(want)):
    problems.append("%s: has permissions on vhost paddock that the definitions do not grant" % user)
# The two the organization deletion needs, named explicitly so that a template change cannot drop them unnoticed.
if want.get("audit_writer", (None, None, None))[1] != r"^paddock\.offboarding$":
    problems.append("the definitions do not let audit_writer publish to paddock.offboarding")
if r"worker\.offboarding" not in want.get("worker", (None, None, ""))[2]:
    problems.append("the definitions do not let worker read worker.offboarding")
for p in problems:
    print("assert-broker: " + p, file=sys.stderr)
sys.exit(1 if problems else 0)
PY
echo "assert-broker: the broker of $project has exactly the permissions of the definitions"
