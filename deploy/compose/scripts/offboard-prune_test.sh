#!/usr/bin/env bash
# Tests of the pruning and of the check item for the organization deletion's object-store users (`make test`,
# PDK-1054d), against a fake rc that keeps its users in a file and prints them as rc does; rustfs-offboard_test.sh runs
# the same against a real RustFS. The rc commands name keys as $VARIABLES that only rc expands (SC2016).
# shellcheck disable=SC2016,SC2015
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
ok() { echo "ok   $*"; }
fail() {
  echo "FAIL $*"
  failures=$((failures + 1))
}

BP=paddock-bundles-offboard EP=paddock-escrow-offboard
users="$work/users" removed="$work/removed"

# The fake rc: `rc admin user list t --json` in the pretty format of rc v0.1.37, `rc admin user rm`. FAKE_LIST_FAILS
# makes the listing fail, FAKE_LIST_GARBAGE prints something else, FAKE_RM_FAILS makes a removal fail.
rc() {
  # The real rc runs in `docker run -i` and reads the caller's stdin; a caller that loops over a here-string loses it.
  cat >/dev/null
  case "$*" in
    "admin user list t --json")
      [[ -z "${FAKE_LIST_FAILS:-}" ]] || return 1
      [[ -z "${FAKE_LIST_GARBAGE:-}" ]] || {
        echo '{"unexpected": true}'
        return 0
      }
      echo '{'
      echo '  "users": ['
      local first=1 key pol p sep
      while read -r key pol; do
        [[ -n "$key" ]] || continue
        [[ -n "$first" ]] || echo '    },'
        first=""
        echo '    {'
        echo "      \"accessKey\": \"$key\","
        echo '      "status": "enabled",'
        echo '      "policies": ['
        sep=""
        for p in ${pol//,/ }; do
          [[ -z "$sep" ]] || echo ","
          printf '        "%s"' "$p"
          sep=1
        done
        [[ -z "$sep" ]] || echo
        echo '      ],'
        echo '      "memberOf": []'
      done <"$users"
      [[ -n "$first" ]] || echo '    }'
      echo '  ]'
      echo '}'
      ;;
    "admin user rm -- t "*)
      [[ -z "${FAKE_RM_FAILS:-}" ]] || return 1
      echo "${!#}" >>"$removed"
      awk -v k="${!#}" '$1 != k' "$users" >"$users.new"
      mv "$users.new" "$users"
      ;;
    *) return 99 ;;
  esac
}
fake_rcf() { eval "$1"; }
setup() {
  : >"$removed"
  printf '%s\n' "$@" >"$users"
}
holders_of() { rc_policy_holders fake_rcf t "$1" | paste -sd, -; }

# 1. The listing: policies on several lines, none, several per user; only the exact policy name matches.
setup "cur-b $BP" "stale-b $BP,extra" "none-held " "$BP-lookalike $BP-x" "cur-e $EP" "both $BP,$EP"
[[ "$(holders_of "$BP")" == "cur-b,stale-b,both" ]] && ok "the holders of a policy, by its exact name" ||
  fail "holders of $BP: $(holders_of "$BP")"
[[ "$(holders_of "$EP")" == "cur-e,both" ]] && ok "a user with two policies is listed for each" || fail "holders of $EP: $(holders_of "$EP")"
[[ -z "$(holders_of nothing)" ]] && ok "no holders of an unknown policy" || fail "holders of an unknown policy: $(holders_of nothing)"

# 2. Pruning.
setup "cur-b $BP" "stale-b1 $BP" "stale-b2 $BP" "cur-e $EP" "stale-e $EP" "other-user paddock-bundles-gateway" \
  "paddock-offboard-lookalike paddock-escrow-api"
out="$(rc_prune_policy_holders fake_rcf t "$BP" cur-b cur-e 2>&1)" && ok "pruning the bundles policy" || fail "pruning failed: $out"
[[ "$(sort "$removed" | paste -sd, -)" == "stale-b1,stale-b2" ]] && ok "the stale bundles users are removed" ||
  fail "removed: $(paste -sd, "$removed")"
[[ "$(holders_of "$BP")" == cur-b ]] && ok "the current bundles user is kept" || fail "holders: $(holders_of "$BP")"
[[ "$out" == *"stale-b1"* && "$out" == *"stale-b2"* && "$out" != *"stale-e"* ]] && ok "the output names the removed access keys only" ||
  fail "output: $out"
rc_prune_policy_holders fake_rcf t "$EP" cur-e cur-b >/dev/null 2>&1 || fail "pruning the escrow policy failed"
grep -q '^other-user ' "$users" && grep -q '^paddock-offboard-lookalike ' "$users" && grep -q '^cur-e ' "$users" &&
  ok "users of other policies are untouched, whatever their name" || fail "a user of another policy was removed: $(cat "$users")"
: >"$removed"
out="$(rc_prune_policy_holders fake_rcf t "$BP" cur-b cur-e 2>&1)"
[[ ! -s "$removed" && -z "$out" ]] && ok "a second run removes and prints nothing" || fail "a second run: $out / $(cat "$removed")"

# 3. A protected key (the other policy's current user) is never removed, even when it holds this policy too.
setup "cur-b $BP" "cur-e $BP,$EP"
rc_prune_policy_holders fake_rcf t "$BP" cur-b cur-e >/dev/null 2>&1
[[ ! -s "$removed" ]] && ok "the other policy's current user is protected" || fail "removed: $(cat "$removed")"

# 4. What it cannot read, it does not act on: nothing is removed and the run fails.
setup "cur-b $BP" "stale-b $BP"
if (FAKE_LIST_FAILS=1 rc_prune_policy_holders fake_rcf t "$BP" cur-b) >/dev/null 2>&1; then fail "a failed listing passed"; else
  ok "a failed listing fails"; fi
if (FAKE_LIST_GARBAGE=1 rc_prune_policy_holders fake_rcf t "$BP" cur-b) 2>"$work/err" >/dev/null; then fail "an unreadable listing passed"; else
  grep -q "cannot confirm the current holder" "$work/err" && ok "an unreadable listing fails loudly" || fail "wrong message: $(cat "$work/err")"; fi
if (rc_prune_policy_holders fake_rcf t "$BP" not-listed) 2>/dev/null >&2; then fail "a current key that holds nothing passed"; else
  ok "a current key that is no holder fails"; fi
[[ ! -s "$removed" && "$(wc -l <"$users")" == 2 ]] && ok "none of these removed a user" || fail "removed: $(cat "$removed")"
if (FAKE_RM_FAILS=1 rc_prune_policy_holders fake_rcf t "$BP" cur-b) >/dev/null 2>&1; then fail "a failed removal passed"; else
  ok "a failed removal fails"; fi

# 5. The check item.
check() { offboard_users_check fake_rcf t cur-b cur-e 2>&1; }
setup "cur-b $BP" "cur-e $EP" "other paddock-bundles-gateway"
out="$(check)" && [[ "$out" == "PASS  object store"* ]] && ok "the check passes with one user per policy" || fail "check: $out"
setup "cur-b $BP" "cur-e $EP" "stale-b $BP"
if out="$(check)"; then fail "the check passed with a stale user"; else
  [[ "$out" == "FAIL  object store"* && "$out" == *"2 users hold $BP"* && "$out" == *"stale-b"* ]] &&
    ok "the check fails on a policy held by two users" || fail "check: $out"; fi
setup "other-b $BP" "cur-e $EP"
if out="$(check)"; then fail "the check passed with a mismatched key"; else
  [[ "$out" == *"held by the access key other-b, which is not the key file's"* ]] &&
    ok "the check fails on a key that does not match the file" || fail "check: $out"; fi
setup "cur-b $BP"
if out="$(check)"; then fail "the check passed without an escrow user"; else
  [[ "$out" == *"no user holds $EP"* ]] && ok "the check fails on a policy nobody holds" || fail "check: $out"; fi
setup "cur-b $BP" "cur-e $EP"
out="$(FAKE_LIST_FAILS=1 check)" && [[ "$out" == "WARN  object store"*"not checked"* ]] &&
  ok "an unreadable store is a WARN, not a pass" || fail "check: $out"

# 6. The wiring: the bootstrap prunes after the probes, ./paddock check runs the item, the bundle ships the script.
boot="$here/rustfs-bundles-bootstrap.sh"
probe_line="$(grep -n '^offboard_probe ESCROW_OFFBOARD' "$boot" | cut -d: -f1)"
prune_b="$(grep -n "^rc_prune_policy_holders rc bundles $BP " "$boot" | cut -d: -f1)"
prune_e="$(grep -n "^rc_prune_policy_holders rc bundles $EP " "$boot" | cut -d: -f1)"
if [[ -n "$probe_line" && -n "$prune_b" && -n "$prune_e" ]] && ((probe_line < prune_b && probe_line < prune_e)); then
  ok "the bootstrap prunes both policies only after both probes"
else
  fail "the bootstrap's pruning does not follow the probes (probe $probe_line, prune $prune_b/$prune_e)"
fi
grep -q 'scripts/offboard-users-check.sh' "$here/../../bundle/paddock" && ok "./paddock check runs the item" || fail "./paddock check does not run the item"
grep -q 'scripts/offboard-users-check.sh' "$here/../../bundle/build.sh" && ok "the bundle ships the check script" || fail "the bundle does not ship the check script"

if ((failures > 0)); then
  echo "$failures failure(s)"
  exit 1
fi
echo "all offboard prune tests passed"
