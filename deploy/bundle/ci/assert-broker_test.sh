#!/usr/bin/env bash
# Tests of assert-broker.sh with a stand-in docker: the shipped definitions' permissions pass; a broker of the previous
# release (audit_writer without paddock.offboarding, worker without worker.offboarding) and an extra user fail.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failed=0
pass() { echo "ok   $1"; }
fail() {
  echo "FAIL $1"
  failed=1
}

mkdir -p "$work/bin"
cat >"$work/bin/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  ps) echo c1 ;;
  exec) cat "$FIXTURE_LISTING" ;;
esac
STUB
chmod +x "$work/bin/docker"
export PATH="$work/bin:$PATH" FIXTURE_LISTING="$work/listing.json"

python3 -I - "$here/../../compose/rabbitmq/definitions.json.tmpl" "$work" <<'PY'
import json, sys
perms = [{"user": p["user"], "configure": p["configure"], "write": p["write"], "read": p["read"]}
         for p in json.load(open(sys.argv[1]))["permissions"] if p["vhost"] == "paddock"]
json.dump(perms, open(sys.argv[2] + "/shipped.json", "w"))
old = []
for p in perms:
    p = dict(p)
    if p["user"] == "audit_writer":
        p["write"] = "^$"
    if p["user"] == "worker":
        p["read"] = r"^(ingest\.(enroll|heartbeat|event|command_result|escrow)|command\.issued)$"
    old.append(p)
json.dump(old, open(sys.argv[2] + "/old.json", "w"))
json.dump(perms + [{"user": "guest", "configure": ".*", "write": ".*", "read": ".*"}], open(sys.argv[2] + "/extra.json", "w"))
PY

cp "$work/shipped.json" "$work/listing.json"
if out="$("$here/assert-broker.sh" paddock-cp 2>&1)"; then pass "the shipped permissions pass"; else fail "shipped: $out"; fi
cp "$work/old.json" "$work/listing.json"
if out="$("$here/assert-broker.sh" paddock-cp 2>&1)"; then fail "the previous release's permissions passed"; elif
  [[ "$out" == *"audit_writer: has"* && "$out" == *"worker: has"* ]]; then pass "the previous release's permissions fail"; else
  fail "previous release: $out"
fi
cp "$work/extra.json" "$work/listing.json"
if out="$("$here/assert-broker.sh" paddock-cp 2>&1)"; then fail "an extra user passed"; elif [[ "$out" == *"guest: has permissions"* ]]; then
  pass "an extra user fails"
else fail "extra user: $out"; fi
if "$here/assert-broker.sh" >/dev/null 2>&1; then fail "no project passed"; else pass "usage without a project"; fi

if ((failed)); then
  echo "assert-broker: checks failed"
  exit 1
fi
echo "assert-broker: all checks passed"
