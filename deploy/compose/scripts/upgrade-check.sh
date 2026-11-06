#!/usr/bin/env bash
# The read-only pre-upgrade check of the operator bundle (plan M16 decision 5, ADR 0047 decision 3), sourced by
# `./paddock upgrade-check <old dir> [--json]`: it runs in the directory of the NEW bundle and compares it with the
# directory of the running version. It writes nothing but one temporary Compose override outside both directories, it
# changes no container and it never prints the value of a setting or a secret (key and file names only).
# Exit codes: 0 without FAIL, 1 with a FAIL, 2 on usage.
# shellcheck shell=bash

uc_names=()
uc_status=()
uc_detail=()

# uc_add <name> <PASS|WARN|FAIL|INFO> <detail>
uc_add() {
  uc_names+=("$1")
  uc_status+=("$2")
  uc_detail+=("$3")
}

# uc_oneline squashes whitespace so that a detail stays one table row and one JSON string.
uc_oneline() { tr -s '[:space:]' ' ' | sed -e 's/^ //' -e 's/ $//'; }

# uc_json_escape <text>: the text as the inside of a JSON string.
uc_json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s" | tr -d '\000-\037'
}

# uc_version <dir>: the version= line of a bundle's VERSION file.
uc_version() { sed -n 's/^version=//p' "$1/VERSION" 2>/dev/null | head -n 1; }

# uc_dotenv_value <file> <name>: the value of a setting (for decisions only, never printed).
uc_dotenv_value() { grep "^$2=" "$1" 2>/dev/null | tail -n 1 | cut -d= -f2- || true; }

# uc_lib_value <new dir> <name>: the value of NAME="…" in the bundle's lib.sh, the single source of the file sets.
uc_lib_value() { sed -n "s/^$2=\"\\(.*\\)\"\$/\\1/p" "$1/scripts/lib.sh" | head -n 1; }

# uc_host_files <new dir> <old .env>: the Compose files of the old installation's host, in this bundle.
uc_host_files() {
  local new="$1" env="$2" host files
  host="$(uc_dotenv_value "$env" PADDOCK_HOST)"
  [[ "$host" == controlplane || "$host" == audit || "$host" == lab ]] || return 1
  files="$(uc_lib_value "$new" "PROD_FILES_$host")"
  [[ -n "$files" ]] || return 1
  if [[ "$host" != audit && "$(uc_dotenv_value "$env" PADDOCK_AUTO_UNSEAL)" == yes ]]; then
    files+=" $(uc_lib_value "$new" AUTO_UNSEAL_FILES)"
  fi
  if [[ "$host" == lab && "$(uc_dotenv_value "$env" PADDOCK_LAB_BACKUP)" == yes ]]; then
    files+=" $(uc_lib_value "$new" LAB_BACKUP_FILES)"
  fi
  echo "$files"
}

# uc_item_verified <old dir>
uc_item_verified() {
  local out
  if [[ ! -x "$1/paddock" ]]; then
    uc_add "old bundle verified" FAIL "$1 has no executable ./paddock"
  elif out="$("$1/paddock" verify 2>&1)"; then
    uc_add "old bundle verified" PASS "no shipped file of the old bundle changed"
  else
    uc_add "old bundle verified" FAIL "$(head -n 3 <<<"$out" | uc_oneline)"
  fi
}

# uc_item_adjacent <new dir> <old dir>
uc_item_adjacent() {
  local new="$1" old="$2" newv oldv list="$1/RELEASES" i inew=-1 iold=-1 seq=()
  newv="$(uc_version "$new")"
  oldv="$(uc_version "$old")"
  if [[ -z "$oldv" || ! -f "$list" ]]; then
    uc_add "versions adjacent" FAIL "cannot read ${oldv:+the RELEASES list of }this bundle or the old VERSION ($old/VERSION, $list)"
    return
  fi
  mapfile -t seq <"$list"
  for i in "${!seq[@]}"; do
    [[ "${seq[i]}" != "$newv" ]] || inew="$i"
    [[ "${seq[i]}" != "$oldv" ]] || iold="$i"
  done
  if ((inew < 0)); then
    uc_add "versions adjacent" WARN "this bundle ($newv) is not a release: the step from $oldv cannot be judged"
  elif ((iold < 0)); then
    uc_add "versions adjacent" FAIL "the old version $oldv is not a known release (known: $(paste -sd, - <"$list" | sed 's/,/, /g'))"
  elif ((iold >= inew)); then
    uc_add "versions adjacent" FAIL "the old version $oldv is not older than this bundle ($newv)"
  elif ((inew - iold > 1)); then
    uc_add "versions adjacent" FAIL "$oldv to $newv skips releases: upgrade through $(printf '%s, ' "${seq[@]:iold+1:inew-iold-1}" | sed 's/, $//') first"
  else
    uc_add "versions adjacent" PASS "$oldv is the release directly before $newv"
  fi
}

# uc_item_notes <new dir>
uc_item_notes() {
  local notes="$1/RELEASE-NOTES" upgrade agents
  upgrade="$(grep -m1 '^Upgrade:' "$notes" 2>/dev/null || true)"
  agents="$(grep -m1 '^Agents:' "$notes" 2>/dev/null || true)"
  if [[ -z "$upgrade" ]]; then
    uc_add "release notes" WARN "this bundle carries no Upgrade line: read the release notes of $(uc_version "$1")"
  elif [[ "$upgrade" == *": automatic" ]]; then
    uc_add "release notes" PASS "$upgrade${agents:+; $agents}"
  else
    uc_add "release notes" WARN "$upgrade${agents:+; $agents}"
  fi
}

# uc_comment_of <example file> <key>: the comment block directly above the key's line, as one line.
uc_comment_of() {
  awk -v key="$2" '
    /^#/ { sub(/^# ?/, ""); block = block (block == "" ? "" : " ") $0; next }
    index($0, key "=") == 1 { print block; exit }
    { block = "" }
  ' "$1" | uc_oneline | cut -c1-240
}

# uc_item_env <new dir> <old dir> <files>
uc_item_env() {
  local new="$1" old="$2" files="$3" example env="$2/.env" f key compose_paths missing=() unknown=() retired=() known
  local newv retiredset=""
  if [[ ! -f "$env" ]]; then
    uc_add env FAIL "$old has no .env"
    return
  fi
  example="$new/.env.example"
  [[ "$(uc_dotenv_value "$env" PADDOCK_HOST)" != lab ]] || example="$new/.env.lab.example"
  if [[ ! -f "$example" || -z "$files" ]]; then
    uc_add env FAIL "cannot compare: $(basename "$example") or the host's Compose files are missing in this bundle, or PADDOCK_HOST of the old .env is not controlplane, audit or lab"
    return
  fi
  compose_paths=()
  for f in $files; do compose_paths+=("$new/$f"); done
  while read -r key; do
    [[ -n "$key" ]] || continue
    grep -q "^$key=" "$env" && continue
    # A key with a default (:- or -) in every reference needs no entry; ${KEY:?…}, ${KEY?…} and a bare ${KEY} do.
    # grep reads the files itself: a pipe from cat dies of SIGPIPE once grep -q stops early, and pipefail turns that into a miss.
    if grep -qE "\\\$\\{$key(:\\?|\\?|\\})|\\\$$key([^A-Za-z0-9_{]|\$)" "${compose_paths[@]}"; then
      missing+=("$key ($(uc_comment_of "$example" "$key"))")
    fi
  done < <(sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' "$example")
  known="$(
    {
      sed -n -E 's/^#? ?([A-Za-z_][A-Za-z0-9_]*)=.*/\1/p' "$example"
      cat "$new"/compose*.yaml | grep -ohE '\$\{?[A-Za-z_][A-Za-z0-9_]*' | sed -E 's/^\$\{?//'
      sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' "$new/versions.env" 2>/dev/null
    } | sort -u
  )"
  newv="$(uc_version "$new")"
  if [[ -n "$newv" && -f "$new/RETIRED-SETTINGS" ]]; then
    retiredset="$(awk -v v="$newv" '$1 == v && NF == 2 { print $2 }' "$new/RETIRED-SETTINGS")"
  fi
  while read -r key; do
    [[ -n "$key" ]] || continue
    grep -qx "$key" <<<"$known" && continue
    if grep -qxF "$key" <<<"$retiredset"; then retired+=("$key"); else unknown+=("$key"); fi
  done < <(sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' "$env")
  if ((${#missing[@]} > 0)); then
    uc_add env FAIL "add to .env before the upgrade: $(printf '%s; ' "${missing[@]}" | sed 's/; $//')"
  fi
  if ((${#unknown[@]} > 0)); then
    uc_add env WARN "settings this bundle does not know (remove them or check the release notes): ${unknown[*]}"
  fi
  if ((${#retired[@]} > 0)); then
    uc_add env INFO "retired by this release; kept for the rollback: ${retired[*]}"
  fi
  if ((${#missing[@]} == 0 && ${#unknown[@]} == 0)); then
    uc_add env PASS "every required setting of $(basename "$example") is in the old .env"
  fi
}

# uc_secret_paths <new dir> <files>: the effective .secrets/ path of every top-level secret; a later file overrides an
# earlier one by name, as Compose merges them (compose.prod.yaml replaces the development release keys).
uc_secret_paths() {
  local new="$1" files="$2" f
  for f in $files; do
    awk '
      /^[^ #]/ { in_secrets = ($0 ~ /^secrets:/); next }
      !in_secrets { next }
      /^  [A-Za-z0-9_.-]+:/ { name = $1; sub(/:$/, "", name) }
      match($0, /file: \.\/\.secrets\/[^ ,}]+/) && name != "" {
        print name "\t" substr($0, RSTART + 17, RLENGTH - 17)
      }
    ' "$new/$f"
  done | awk -F'\t' '{ path[$1] = $2 } END { for (n in path) print path[n] }' | sort -u
}

# uc_item_secrets <new dir> <old dir> <files>
uc_item_secrets() {
  local new="$1" old="$2" files="$3" f path missing=() fatal=()
  if [[ -z "$files" ]]; then
    uc_add secrets WARN "skipped: the host's Compose files could not be determined"
    return
  fi
  while read -r path; do
    [[ -n "$path" && ! -e "$old/.secrets/$path" ]] || continue
    case "$path" in
      release-production/* | approle/*) fatal+=("$path") ;;
      *) missing+=("$path") ;;
    esac
  done < <(
    uc_secret_paths "$new" "$files"
  )
  if ((${#fatal[@]} > 0)); then
    uc_add secrets FAIL "files that ./paddock secrets cannot generate are missing in the old .secrets/: ${fatal[*]}"
  fi
  if ((${#missing[@]} > 0)); then
    uc_add secrets INFO "./paddock secrets will generate: ${missing[*]}"
  elif ((${#fatal[@]} == 0)); then
    uc_add secrets PASS "every secret file of this bundle exists in the old .secrets/"
  fi
}

# uc_image_refs <new dir> <files>: the image references of versions.env that the host's files use.
uc_image_refs() {
  local new="$1" files="$2" f var
  while read -r var; do
    for f in $files; do
      if grep -q "\${$var" "$new/$f"; then
        uc_versions_ref "$new" "$var"
        break
      fi
    done
  done < <(sed -n 's/^\([A-Z0-9_]*_IMAGE\)=.*/\1/p' "$new/versions.env")
}
uc_versions_ref() { sed -n "s/^$2=//p" "$1/versions.env" | tail -n 1; }

# uc_image_bytes <ref>: the compressed size of the image for this machine's architecture, empty when unreadable.
uc_image_bytes() {
  local ref="$1" repo out digest arch
  repo="${ref%%@*}"
  repo="${repo%:*}"
  out="$(docker manifest inspect "$ref" 2>/dev/null)" || return 0
  if grep -q '"manifests"' <<<"$out"; then
    case "$(uname -m)" in aarch64 | arm64) arch=arm64 ;; *) arch=amd64 ;; esac
    digest="$(awk -v arch="$arch" '/"digest"/ { gsub(/[",]/, ""); d = $2 } /"architecture"/ && index($0, "\"" arch "\"") { print d; exit }' <<<"$out")"
    [[ -n "$digest" ]] || return 0
    out="$(docker manifest inspect "$repo@$digest" 2>/dev/null)" || return 0
  fi
  awk '/"size"/ { gsub(/[^0-9]/, ""); s += $0 } END { print s + 0 }' <<<"$out"
}

# uc_item_images <refs…>: the disk and the pullable items, from one manifest read per image.
uc_item_images() {
  local ref bytes total=0 unreadable=() unpullable=() root avail need
  for ref in "$@"; do
    if ! docker manifest inspect "$ref" >/dev/null 2>&1; then
      unpullable+=("${ref%%@*}")
      unreadable+=("${ref%%@*}")
      continue
    fi
    bytes="$(uc_image_bytes "$ref")"
    if [[ "$bytes" =~ ^[0-9]+$ && "$bytes" -gt 0 ]]; then total=$((total + bytes)); else unreadable+=("${ref%%@*}"); fi
  done
  if ((${#unreadable[@]} > 0)); then
    uc_add disk WARN "the size of ${#unreadable[@]} image(s) could not be read (offline?): free the space for the new images by hand"
  else
    root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
    avail="$(df -PB1 "${root:-/}" 2>/dev/null | awk 'NR == 2 { print $4 }')"
    need=$((total * 2 + 2 * 1024 * 1024 * 1024))
    if [[ ! "$avail" =~ ^[0-9]+$ ]]; then
      uc_add disk WARN "the free space of ${root:-/} could not be read"
    elif ((avail < need)); then
      uc_add disk FAIL "$((avail / 1048576)) MiB free on ${root:-/}, $((need / 1048576)) MiB needed (new images x 2 + 2 GiB)"
    else
      uc_add disk PASS "$((avail / 1048576)) MiB free on ${root:-/}, $((need / 1048576)) MiB needed"
    fi
  fi
  if ((${#unpullable[@]} > 0)); then
    uc_add "images pullable" WARN "no manifest for: ${unpullable[*]} (offline, or the registry is unreachable)"
  else
    uc_add "images pullable" PASS "$# image(s) have a manifest"
  fi
}

# uc_item_server <new dir> <old dir> <stack running 0|1>
uc_item_server() {
  local new="$1" old="$2" running="$3" newv oldv out status=0 override="" lines rc
  newv="$(uc_version "$new")"
  oldv="$(uc_version "$old")"
  if [[ "$(uc_dotenv_value "$old/.env" PADDOCK_HOST)" == audit ]]; then
    uc_add "server report" INFO "n/a on the audit host: it runs no paddock-worker"
    return
  fi
  if [[ ! -x "$old/paddock" ]]; then
    uc_add "server report" WARN "the old stack cannot be asked: $old has no executable ./paddock"
    return
  fi
  # compose run creates networks and volumes of a stopped project before it fails, which a read-only check must not do.
  if ((!running)); then
    uc_add "server report" WARN "skipped: the old stack is not running"
    return
  fi
  # alpha.8 predates the command, so the new image runs it against the old stack's database; the old ./paddock exports
  # its own versions.env after the process environment, hence the override file instead of PADDOCK_IMAGE.
  # The entrypoint is absolute: the binary lies in / of a distroless image, which is not on its PATH.
  if [[ "$oldv" == 0.1.0-alpha.8 ]]; then
    override="$(mktemp)"
    printf 'services:\n  paddock-worker:\n    image: %s\n' "$(uc_versions_ref "$new" PADDOCK_IMAGE)" >"$override"
    out="$("$old/paddock" compose -f "$override" run --rm --no-deps -T --entrypoint /paddock-server paddock-worker \
      admin upgrade-check --target-version "$newv" 2>&1 </dev/null)" || status=$?
    rm -f "$override"
  else
    out="$("$old/paddock" compose run --rm --no-deps -T paddock-worker admin upgrade-check --target-version "$newv" \
      2>&1 </dev/null)" || status=$?
  fi
  lines="$(grep -E '^(PASS|WARN|FAIL|INFO)[[:space:]]' <<<"$out" || true)"
  uc_server_lines="$lines"
  if [[ -z "$lines" ]]; then
    uc_add "server report" WARN "the report could not be produced (exit $status): $(tail -n 2 <<<"$out" | uc_oneline | cut -c1-200)"
    return
  fi
  rc="$(grep -E '^(FAIL|WARN)[[:space:]]' <<<"$lines" | uc_oneline | sed 's/ \(FAIL\|WARN\) /; \1 /g')"
  if ((status == 0)) && [[ -z "$rc" ]]; then
    uc_add "server report" PASS "no WARN or FAIL in the report"
  elif ((status == 0)); then
    uc_add "server report" WARN "$rc"
  else
    uc_add "server report" FAIL "${rc:-the report failed}"
  fi
}

# uc_item_unseal <old dir>
uc_item_unseal() {
  local env="$1/.env"
  if [[ "$(uc_dotenv_value "$env" PADDOCK_HOST)" == audit ]]; then
    uc_add "openbao unseal path" INFO "n/a on the audit host: it runs no OpenBao"
  elif [[ "$(uc_dotenv_value "$env" PADDOCK_AUTO_UNSEAL)" == yes && -e "$1/.secrets/openbao/auto-unseal-shares" ]]; then
    uc_add "openbao unseal path" PASS "automatic unseal is set up: OpenBao unseals itself during ./paddock up"
  elif [[ "$(uc_dotenv_value "$env" PADDOCK_AUTO_UNSEAL)" == yes ]]; then
    uc_add "openbao unseal path" WARN "PADDOCK_AUTO_UNSEAL=yes, but the shares file is missing: three custodians must be available during ./paddock up"
  else
    uc_add "openbao unseal path" WARN "three custodians must be available during ./paddock up to unseal OpenBao"
  fi
}

# uc_item_running <old dir>: also sets uc_postgres_running, which the server report needs before it may ask the stack.
uc_item_running() {
  local out service state health exit_code bad=() seen=0
  uc_postgres_running=0
  if ! out="$("$1/paddock" ps -a --format '{{.Service}}|{{.State}}|{{.Health}}|{{.ExitCode}}' 2>/dev/null)"; then
    uc_add "running stack healthy" WARN "the old stack's services could not be listed (docker, or the old .env)"
    return
  fi
  while IFS='|' read -r service state health exit_code; do
    [[ -n "$service" ]] || continue
    seen=$((seen + 1))
    if [[ "$service" == postgres && "$state" == running ]]; then uc_postgres_running=1; fi
    case "$state" in
      exited) [[ "$exit_code" == 0 ]] || bad+=("$service (exit $exit_code)") ;;
      running) [[ -z "$health" || "$health" == healthy ]] || bad+=("$service ($health)") ;;
      *) bad+=("$service ($state)") ;;
    esac
  done <<<"$out"
  if ((seen == 0)); then
    uc_add "running stack healthy" WARN "no services found: the old stack is not running"
  elif ((${#bad[@]} > 0)); then
    uc_add "running stack healthy" WARN "not healthy: ${bad[*]}"
  else
    uc_add "running stack healthy" PASS "$seen service(s), all healthy or finished"
  fi
}

# uc_print <json 0|1>: the table or the JSON document; returns the exit code.
uc_print() {
  local json="$1" i exit_code=0 sep=""
  for i in "${!uc_names[@]}"; do [[ "${uc_status[i]}" != FAIL ]] || exit_code=1; done
  if ((json)); then
    printf '{"items":['
    for i in "${!uc_names[@]}"; do
      printf '%s{"name":"%s","status":"%s","detail":"%s"}' "$sep" "$(uc_json_escape "${uc_names[i]}")" \
        "${uc_status[i]}" "$(uc_json_escape "${uc_detail[i]}")"
      sep=","
    done
    printf '],"exit":%d}\n' "$exit_code"
  else
    printf '%-5s  %-24s  %s\n' STATUS ITEM DETAIL
    for i in "${!uc_names[@]}"; do
      printf '%-5s  %-24s  %s\n' "${uc_status[i]}" "${uc_names[i]}" "${uc_detail[i]}"
    done
    if [[ -n "${uc_server_lines:-}" ]]; then
      printf '\nserver report (old stack):\n%s\n' "$uc_server_lines"
    fi
    if ((exit_code == 0)); then echo "upgrade check: no FAIL"; else echo "upgrade check: FAIL, fix the items above first"; fi
  fi
  return "$exit_code"
}

# upgrade_check <new dir> <arguments…>: the arguments of ./paddock upgrade-check.
upgrade_check() {
  local new="$1" old="" json=0 arg files refs=() ref
  shift
  uc_names=() uc_status=() uc_detail=()
  uc_server_lines=""
  uc_postgres_running=0
  for arg in "$@"; do
    case "$arg" in
      --json) json=1 ;;
      -*) echo "usage: ./paddock upgrade-check <old bundle directory> [--json]" >&2; return 2 ;;
      *)
        [[ -z "$old" ]] || { echo "usage: ./paddock upgrade-check <old bundle directory> [--json]" >&2; return 2; }
        old="$arg"
        ;;
    esac
  done
  if [[ -z "$old" || ! -d "$old" ]]; then
    echo "usage: ./paddock upgrade-check <old bundle directory> [--json]" >&2
    return 2
  fi
  old="$(cd "$old" && pwd)"
  if [[ "$old" == "$new" ]]; then
    echo "upgrade-check: <old dir> is this directory" >&2
    return 2
  fi
  files="$(uc_host_files "$new" "$old/.env" 2>/dev/null || true)"

  uc_item_verified "$old"
  uc_item_adjacent "$new" "$old"
  uc_item_notes "$new"
  uc_item_env "$new" "$old" "$files"
  uc_item_secrets "$new" "$old" "$files"
  if [[ -n "$files" ]]; then
    while IFS= read -r ref; do [[ -z "$ref" ]] || refs+=("$ref"); done < <(uc_image_refs "$new" "$files")
  fi
  if ((${#refs[@]} > 0)); then
    uc_item_images "${refs[@]}"
  else
    uc_add disk WARN "skipped: no image of this host could be determined"
    uc_add "images pullable" WARN "skipped: no image of this host could be determined"
  fi
  # The stack state is read first (the server report needs it) but printed last, in the plan's order.
  uc_item_running "$old"
  local running_name="${uc_names[-1]}" running_status="${uc_status[-1]}" running_detail="${uc_detail[-1]}"
  unset 'uc_names[-1]' 'uc_status[-1]' 'uc_detail[-1]'
  uc_item_server "$new" "$old" "$uc_postgres_running"
  uc_item_unseal "$old"
  uc_add "$running_name" "$running_status" "$running_detail"
  uc_print "$json"
}
