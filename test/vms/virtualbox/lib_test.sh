#!/usr/bin/env bash
# Tests of lib.sh (`make test`, PDK-541): a linked worktree reuses the main checkout's VM secrets and never creates its
# own, the passphrase is typed paced after clearing the prompt, secrets that are not the VM's stop the start at once,
# and a failed unlock leaves console screenshots. VBoxManage and ssh are fakes.
set -euo pipefail

src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

check() {
  if [[ "$2" == "$3" ]]; then
    echo "ok   $1"
  else
    echo "FAIL $1: got '$2', want '$3'"
    failures=$((failures + 1))
  fi
}

# A repository with lib.sh and a linked worktree of it.
repo="$work/repo"
mkdir -p "$repo/test/vms/virtualbox"
cp "$src" "$repo/test/vms/virtualbox/lib.sh"
git -C "$repo" init -q
git -C "$repo" -c user.email=t@t -c user.name=t add . >/dev/null
git -C "$repo" -c user.email=t@t -c user.name=t commit -qm init
git -C "$repo" worktree add -q "$work/wt" >/dev/null 2>&1
main="$repo/test/vms/virtualbox"
wt="$work/wt/test/vms/virtualbox"

# The fakes log every call to $work/calls; extradata lives in $work/extradata.
mkdir -p "$work/bin"
cat >"$work/bin/VBoxManage" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_DIR/calls"
[[ "$1" == getextradata && -e "$FAKE_DIR/getextradata-fails" ]] && exit 1
case "$1 $3" in
  "getextradata "*) [[ -s "$FAKE_DIR/extradata" ]] && echo "Value: $(cat "$FAKE_DIR/extradata")" || echo "No value set!" ;;
  "setextradata "*) printf '%s' "$4" >"$FAKE_DIR/extradata" ;;
esac
[[ "$1 $3" == "controlvm screenshotpng" ]] && : >"$4"
exit 0
EOF
cat >"$work/bin/ssh" <<'EOF'
#!/usr/bin/env bash
[[ -e "$FAKE_DIR/ssh-up" ]]
EOF
chmod +x "$work/bin/VBoxManage" "$work/bin/ssh"
export PATH="$work/bin:$PATH" FAKE_DIR="$work" PADDOCK_VM_KEY_DELAY=0 UNLOCK_SETTLE=0 UNLOCK_POLLS=1 UNLOCK_POLL=0

# lib <dir> <script>: runs script with lib.sh of dir sourced; prints stdout+stderr, then "rc=<exit>".
lib() { local rc=0 out; out=$(bash -c "set -euo pipefail; source '$1/lib.sh'; $2" 2>&1) || rc=$?; printf '%s\nrc=%s' "$out" "$rc"; }

out=$(lib "$wt" ensure_secrets)
check "worktree, owner without secrets: refused" "${out##*rc=}" 1
check "worktree, owner without secrets: nothing created" "$(find "$wt/.secrets" -mindepth 1 ! -name .lock 2>/dev/null | wc -l)" 0

lib "$main" ensure_secrets >/dev/null
check "main checkout creates its secrets" "$(test -s "$main/.secrets/credentials.env" && echo yes)" yes

rm -rf "$wt/.secrets"; mkdir -p "$wt/.secrets"; : >"$wt/.secrets/.lock"
# shellcheck disable=SC2016 # the inner shell expands it
out=$(lib "$wt" 'ensure_secrets; echo "pass=$PADDOCK_LUKS_PASSPHRASE"')
check "worktree: linked to the owner" "$(readlink "$wt/.secrets")" "$main/.secrets"
check "worktree: owner's passphrase" "$(grep -o 'pass=.*' <<<"$out")" "pass=$(sed -n 's/^PADDOCK_LUKS_PASSPHRASE=//p' "$main/.secrets/credentials.env")"

rm "$wt/.secrets"; mkdir -p "$wt/.secrets"
printf 'PADDOCK_LUKS_PASSPHRASE=other\n' >"$wt/.secrets/credentials.env"
out=$(lib "$wt" ensure_secrets)
check "worktree with its own secrets: refused" "${out##*rc=}" 1
check "worktree with its own secrets: message names the owner" "$(grep -c "linked to $main/.secrets" <<<"$out")" 1
check "worktree with its own secrets: kept" "$(cat "$wt/.secrets/credentials.env")" "PADDOCK_LUKS_PASSPHRASE=other"
rm -rf "$wt/.secrets"

cp -r "$main/.secrets" "$wt/.secrets"
printf 'other key\n' >"$wt/.secrets/id_ed25519"
out=$(lib "$wt" ensure_secrets)
check "worktree with the same credentials but its own key: refused" "${out##*rc=}" 1
check "worktree with its own key: kept" "$(cat "$wt/.secrets/id_ed25519")" "other key"
rm -rf "$wt/.secrets"

cp -r "$main/.secrets" "$wt/.secrets"
lib "$wt" ensure_secrets >/dev/null
check "worktree with an exact copy: replaced by the link" "$(readlink "$wt/.secrets")" "$main/.secrets"
rm "$wt/.secrets"

lib "$wt" ensure_secrets >/dev/null & lib "$wt" ensure_secrets >/dev/null & wait
check "parallel first use: one link" "$(readlink "$wt/.secrets")" "$main/.secrets"
check "parallel first use: nothing inside the owner's directory" "$(find "$main/.secrets" -type l | wc -l)" 0
rm "$wt/.secrets"

: >"$work/calls"
lib "$main" 'PADDOCK_LUKS_PASSPHRASE=Ab3; type_luks_passphrase vm1' >/dev/null
check "typing: clear, one key per call, Enter" "$(sed 's/keyboardputscancode \(0e 8e \)*0e 8e$/keyboardputscancode <40 backspaces>/' "$work/calls")" \
  "controlvm vm1 keyboardputscancode <40 backspaces>
controlvm vm1 keyboardputstring A
controlvm vm1 keyboardputstring b
controlvm vm1 keyboardputstring 3
controlvm vm1 keyboardputscancode 1c 9c"
check "typing: 40 backspaces" "$(head -1 "$work/calls" | grep -o '0e 8e' | wc -l)" 40

printf 'deadbeefdeadbeef' >"$work/extradata"; : >"$work/calls"
out=$(lib "$main" 'ensure_secrets; unlock_and_wait_ssh vm1 2224')
check "other VM's passphrase: refused" "${out##*rc=}" 1
check "other VM's passphrase: nothing typed" "$(grep -c keyboard "$work/calls" || true)" 0

rm -f "$work/extradata"; : >"$work/calls"; : >"$work/getextradata-fails"
out=$(lib "$main" 'ensure_secrets; check_passphrase_fingerprint vm1; echo checked')
check "getextradata failing: no silent exit" "$(grep -c '^checked$' <<<"$out")" 1
rm "$work/getextradata-fails"

: >"$work/calls"
out=$(lib "$main" 'ensure_secrets; unlock_and_wait_ssh vm1 2224')
check "failed unlock: exit 1" "${out##*rc=}" 1
check "failed unlock: says the passphrase was rejected" "$(grep -c 'LUKS passphrase rejected' <<<"$out")" 1
check "failed unlock: 5 attempts typed" "$(grep -c 'keyboardputscancode 1c 9c' "$work/calls")" 5
check "failed unlock: screenshots per attempt and at the end" "$(grep -c screenshotpng "$work/calls")" 5
check "failed unlock: screenshot path logged" "$(grep -c "console: $main/work/vm1/console-failed-" <<<"$out")" 1
check "failed unlock: no fingerprint recorded" "$(test -s "$work/extradata" && echo set || echo unset)" unset

: >"$work/ssh-up"
out=$(lib "$main" 'ensure_secrets; unlock_and_wait_ssh vm1 2224')
check "unlock: exit 0" "${out##*rc=}" 0
check "unlock: fingerprint recorded" "$(cat "$work/extradata")" \
  "$(sed -n 's/^PADDOCK_LUKS_PASSPHRASE=//p' "$main/.secrets/credentials.env" | tr -d '\n' | sha256sum | cut -c1-16)"

if ((failures > 0)); then
  echo "vm lib: $failures failure(s)"
  exit 1
fi
echo "vm lib: all cases passed"
