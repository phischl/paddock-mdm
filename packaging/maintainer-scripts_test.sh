#!/usr/bin/env bash
# Guard of the maintainer scripts of paddock-supervisor and paddock-agent (`make test`; plan M5a amendment 2026-11-11 b,
# P1, PDK-985): no script may create, change or look up a user or group, by a command or by a sysusers.d file.
#
# Why: on an enrolled device Himmelblau answers every unknown name with a synthetic directory user (RR-07, RR-133).
# The agent stops himmelblaud around its own package transactions, but the supervisor upgrade
# (`dpkg -i paddock-supervisor`) and the uninstall helper (purges of paddock-agent and paddock-supervisor) run
# WITHOUT that hold, because these scripts need no account. A script that gains a user or group lookup would fail
# or resolve a synthetic user there; it reopens that decision instead of passing this test.
#
# The scripts are read from the `scripts:` blocks of the nfpm configs, so a new script is covered without editing
# this test.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
configs=(packaging/nfpm/paddock-supervisor.yaml packaging/nfpm/paddock-agent.yaml)
failures=0

fail() {
  echo "FAIL $1"
  failures=$((failures + 1))
}

# script_paths <config>: the value of every key in the config's `scripts:` blocks (top level and below `deb:`).
script_paths() {
  awk '
    function indent(s) { match(s, /^ */); return RLENGTH }
    /^[[:space:]]*(#|$)/ { next }
    in_block && indent($0) <= block_indent { in_block = 0 }
    in_block {
      line = $0
      sub(/^[[:space:]]*[A-Za-z_]+:[[:space:]]*/, "", line)
      sub(/[[:space:]]+#.*$/, "", line)
      gsub(/["\047]/, "", line)
      if (line != "") print line
      next
    }
    /^[[:space:]]*scripts:[[:space:]]*$/ { in_block = 1; block_indent = indent($0) }
  ' "$1"
}

# offenders <file>: every line of a shell script that creates, changes or looks up a user or group, with its line
# number. Comments are ignored so that a script may explain why it needs no account.
offenders() {
  local cmd='(^|[;&|(`{]|\$\(|then|do|else|!|exec|xargs|sudo|env|command)[[:space:]]*'
  sed -e 's/^[[:space:]]*#.*$//' -e 's/[[:space:]]#.*$//' "$1" | grep -nE \
    -e '(^|[^A-Za-z0-9_-])(useradd|adduser|groupadd|addgroup|usermod|groupmod|userdel|groupdel|deluser|delgroup|gpasswd|newusers|chpasswd|getent|systemd-sysusers|runuser|setpriv|chown|chgrp)([^A-Za-z0-9_-]|$)' \
    -e 'sysusers\.d' \
    -e "${cmd}id[[:space:]]+[^|;&[:space:]]" \
    -e "${cmd}su[[:space:]]" \
    -e 'sudo[[:space:]]+(-[A-Za-z]+[[:space:]]+)*-[ug]' \
    -e '(^|[^A-Za-z0-9_-])install[[:space:]].*([[:space:]]-[a-zA-Z]*[og]([[:space:]]|$)|--owner|--group)' \
    -e '--uid|--gid|--chuid' ||
    true
}

# The detector itself: every form of account creation or lookup is caught, and the commands the scripts use today
# are not.
forbidden=(
  'useradd --system paddock'
  'adduser --system --group paddock'
  'groupadd -r paddock'
  'addgroup --system paddock'
  'usermod -aG paddock root'
  'deluser paddock'
  'getent passwd paddock >/dev/null'
  'if ! getent group paddock; then :; fi'
  'id paddock'
  'id -u paddock >/dev/null'
  'uid=$(id -u paddock)'
  'systemd-sysusers'
  'systemd-sysusers /usr/lib/sysusers.d/paddock.conf'
  'install -m 0644 x /usr/lib/sysusers.d/paddock.conf'
  'chown paddock:paddock /var/lib/paddock'
  'chown -R paddock /var/lib/paddock'
  'chgrp paddock /etc/paddock'
  'install -d -o paddock -m 0750 /var/lib/paddock'
  'install -d -m 0750 -g paddock /var/lib/paddock'
  'install -d --owner=paddock /var/lib/paddock'
  'runuser -u paddock -- true'
  'su paddock -c true'
  'sudo -u paddock true'
  'setpriv --reuid=paddock true'
  'systemd-run --uid=paddock true'
  'start-stop-daemon --start --chuid paddock --exec /bin/true'
)
allowed=(
  'pam-auth-update --package --enable paddock-deny'
  'systemctl enable paddock-disk-setup.service'
  'install -d -m 0755 "$slots/A"'
  'install -m 0755 /usr/lib/paddock/paddockd "$slots/A/paddockd.new"'
  'mv -f "$slots/A/paddockd.new" "$slots/A/paddockd"'
  'ln -s A "$slots/.current.new"'
  'if [ "$1" = remove ] && [ -d /run/systemd/system ]; then'
  'systemctl disable --now paddock-supervisor.service >/dev/null || true'
  '# no adduser or getent here: the supervisor upgrade runs without the NSS hold'
)
probe="$(mktemp)"
trap 'rm -f "$probe"' EXIT
for line in "${forbidden[@]}"; do
  printf '#!/bin/sh\nset -e\n%s\n' "$line" >"$probe"
  if [[ -n "$(offenders "$probe")" ]]; then echo "ok   detector catches: $line"; else fail "detector misses: $line"; fi
done
for line in "${allowed[@]}"; do
  printf '#!/bin/sh\nset -e\n%s\n' "$line" >"$probe"
  if [[ -z "$(offenders "$probe")" ]]; then echo "ok   detector allows: $line"; else fail "detector flags: $line"; fi
done

# The real scripts.
for config in "${configs[@]}"; do
  [[ -f "$root/$config" ]] || { fail "$config is missing"; continue; }
  mapfile -t scripts < <(script_paths "$root/$config")
  # A config whose scripts are no longer found would pass silently; the guard must see at least one.
  if ((${#scripts[@]} == 0)); then
    fail "$config: no maintainer script found in its scripts: block"
    continue
  fi
  for script in "${scripts[@]}"; do
    if [[ ! -f "$root/$script" ]]; then
      fail "$config: maintainer script $script is missing"
      continue
    fi
    hits="$(offenders "$root/$script")"
    if [[ -z "$hits" ]]; then
      echo "ok   $script ($config) creates and looks up no user or group"
    else
      while IFS= read -r hit; do
        fail "$script:${hit%%:*} creates or looks up a user or group: ${hit#*:}"
      done <<<"$hits"
      echo "     The supervisor upgrade and the uninstall helper run this package's scripts without the NSS hold" \
        "(plan M5a amendment 2026-11-11 b, P1): on an enrolled device Himmelblau answers every unknown name with a" \
        "synthetic user. Remove the account handling, or reopen that decision first."
    fi
  done
  # A sysusers.d file in the package would make systemd create an account on install, outside every script.
  if grep -nE '^[[:space:]]*-?[[:space:]]*dst:.*sysusers\.d' "$root/$config" >/dev/null; then
    fail "$config installs a sysusers.d file"
  else
    echo "ok   $config installs no sysusers.d file"
  fi
done

if ((failures > 0)); then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all maintainer-script checks passed"
