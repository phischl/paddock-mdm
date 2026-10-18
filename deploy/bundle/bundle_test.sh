#!/usr/bin/env bash
# Drift test of the operator bundle (plan M7b decision 22, `make bundle-test`, part of `make test`): a local bundle
# renders the same production configurations as deploy/compose/, references only files and images it ships, passes
# its own verification and is reproducible; plus the refusals of build.sh and ./paddock.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose_src="$(cd "$here/../compose" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Fixed inputs, so that the test does not depend on the checkout's history; the Paddock images come from the bundle.
export SOURCE_DATE_EPOCH=1760000000 GIT_COMMIT=0123456789abcdef0123456789abcdef01234567
export PADDOCK_BACKUP_S3_ENDPOINT=https://backup-s3.example.org
unset PADDOCK_IMAGE PADDOCK_COMPILER_IMAGE PADDOCK_PGBACKREST_IMAGE PADDOCK_COMPOSE_EXTRA PADDOCK_ENV PADDOCK_HOST \
  PADDOCK_PROJECT SECRETS_DIR LOCAL_SERVER_IMAGE LOCAL_COMPILER_IMAGE LOCAL_PGBACKREST_IMAGE

failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}
pass() { echo "ok: $*"; }

# redact_tokens (RR-63): Authentik's refresh-token warnings print the raw token as token=<value>.
redacted="$( (. "$compose_src/scripts/lib.sh" && printf '%s\n' 'x Refresh token is revoked token=fake.token-value_x=' \
  '{"event": "Refresh token is revoked", "token": "fake.token-value_x=", "refresh_token_id": 7}' 'no secret here' | redact_tokens))"
if [[ "$redacted" == $'x Refresh token is revoked token=<redacted>\n{"event": "Refresh token is revoked", "token": "<redacted>", "refresh_token_id": 7}\nno secret here' ]]; then
  pass "redact_tokens replaces token values and leaves other lines unchanged"
else
  fail "redact_tokens: $redacted"
fi

# build <bundle sources> <out dir>: a local bundle of version 0.0.0-test.
build() { "$1/build.sh" --version 0.0.0-test --channel local --images local --out "$2" >/dev/null; }
lib_files() { sed -n "s/^$2=\"\\(.*\\)\"\$/\\1/p" "$1/scripts/lib.sh"; }

# host_files <dir> <host>: the Compose files of host per the lib.sh of dir; lab-backup is the lab with
# LAB_BACKUP_FILES; the -auto-unseal variants add AUTO_UNSEAL_FILES (on the lab before LAB_BACKUP_FILES, as
# compose_files orders them).
host_files() {
  case "$2" in
    lab-backup) echo "$(lib_files "$1" PROD_FILES_lab) $(lib_files "$1" LAB_BACKUP_FILES)" ;;
    controlplane-auto-unseal) echo "$(lib_files "$1" PROD_FILES_controlplane) $(lib_files "$1" AUTO_UNSEAL_FILES)" ;;
    lab-auto-unseal)
      echo "$(lib_files "$1" PROD_FILES_lab) $(lib_files "$1" AUTO_UNSEAL_FILES) $(lib_files "$1" LAB_BACKUP_FILES)"
      ;;
    *) lib_files "$1" "PROD_FILES_$2" ;;
  esac
}

# render <compose dir> <settings file> <host>: the production configuration of host, normalized: the project
# directory as <dir>, the three Paddock images as <image>.
render() {
  local dir="$1" settings="$2" host="$3" f args=()
  for f in $(host_files "$compose_src" "$host"); do args+=(-f "$dir/$f"); done
  docker compose --project-directory "$dir" -p paddock-bundle-test --env-file "$dir/versions.env" \
    --env-file "$dir/$settings" "${args[@]}" --profile '*' config |
    sed -E -e "s#$dir#<dir>#g" -e 's#(image: ).*paddock-(server|compiler|pgbackrest)[^ ]*$#\1<image>#'
}

# check_mounts <bundle dir>: every bind-mount source of the configurations of the three hosts exists inside the
# bundle; prints the missing paths relative to the bundle.
check_mounts() {
  local dir="$1" host src missing=0 f args settings
  for host in controlplane audit lab-backup controlplane-auto-unseal lab-auto-unseal; do
    args=()
    settings=.env.example
    [[ "$host" != lab* ]] || settings=.env.lab.example
    for f in $(host_files "$dir" "$host"); do args+=(-f "$dir/$f"); done
    while read -r src; do
      [[ "$src" == "$dir"/.secrets/* ]] && continue
      if [[ "$src" != "$dir"/* || ! -e "$src" ]]; then
        echo "missing bind-mount source: ${src#"$dir"/}"
        missing=1
      fi
    done < <(docker compose --project-directory "$dir" -p paddock-bundle-test --env-file "$dir/versions.env" \
      --env-file "$dir/$settings" "${args[@]}" --profile '*' config |
      sed -n -E 's#^[[:space:]]+source: (/.*)$#\1#p')
  done
  return "$missing"
}

build "$here" "$work/a"
bundle="$work/a/paddock-deploy-0.0.0-test"

# (a) Same configuration as the repository.
for host in controlplane audit lab lab-backup controlplane-auto-unseal lab-auto-unseal; do
  if [[ "$host" == lab* ]]; then
    render "$compose_src" lab.env.example "$host" >"$work/repo.yaml"
    render "$bundle" .env.lab.example "$host" >"$work/bundle.yaml"
  else
    render "$compose_src" prod.env.example "$host" >"$work/repo.yaml"
    render "$bundle" .env.example "$host" >"$work/bundle.yaml"
  fi
  if ! grep -q '^services:' "$work/repo.yaml"; then
    fail "(a) the repository's $host configuration does not render"
  elif diff -u "$work/repo.yaml" "$work/bundle.yaml" >"$work/diff"; then
    pass "(a) the $host configuration of the bundle equals deploy/compose/ ($(grep -c 'image: ' "$work/repo.yaml") images)"
  else
    fail "(a) the $host configuration of the bundle differs from deploy/compose/:"
    cat "$work/diff" >&2
  fi
done

# (b) Every mounted file is shipped; a removed one is named.
if out="$(check_mounts "$bundle")"; then pass "(b) every bind-mount source is in the bundle"; else fail "(b) $out"; fi
cp -a "$bundle" "$work/broken"
rm "$work/broken/caddy/guards.caddy"
if out="$(check_mounts "$work/broken")"; then
  fail "(b) a bundle without caddy/guards.caddy passes the mount check"
elif [[ "$out" == *"caddy/guards.caddy"* ]]; then
  pass "(b) a removed file is named: $out"
else
  fail "(b) the mount check does not name caddy/guards.caddy: $out"
fi

# (c) Every image variable of the shipped Compose files and scripts is defined in the shipped versions.env.
missing_images=()
for var in $(grep -rhoE '\$\{?[A-Z][A-Z0-9_]*_IMAGE' "$bundle" --include='*.yaml' --include='*.sh' --include=paddock |
  sed -E 's/^\$\{?//' | sort -u); do
  grep -q "^$var=" "$bundle/versions.env" || missing_images+=("$var")
done
if ((${#missing_images[@]} == 0)); then pass "(c) every referenced image is in versions.env"; else
  fail "(c) not defined in the bundle's versions.env: ${missing_images[*]}"
fi

# (d) The bundle verifies itself.
if (cd "$bundle" && ./paddock verify >/dev/null); then pass "(d) ./paddock verify"; else fail "(d) ./paddock verify"; fi

# (e) Only lib.sh defines require_development; nothing shipped calls it.
offenders="$(grep -rl require_development "$bundle" | grep -v "/scripts/lib.sh$" || true)"
if [[ -z "$offenders" ]]; then pass "(e) no shipped script is development-only"; else
  fail "(e) development-only scripts in the bundle: $offenders"
fi

# (f) Reproducible tarball.
build "$here" "$work/b"
if [[ "$(sha256sum <"$work/a/paddock-deploy-0.0.0-test.tar.gz")" == "$(sha256sum <"$work/b/paddock-deploy-0.0.0-test.tar.gz")" ]]; then
  pass "(f) two builds produce the same tarball"
else
  fail "(f) two builds of the same tree produce different tarballs"
fi

# build.sh refuses a production Compose file with a build section.
mkdir -p "$work/src/deploy"
cp -a "$here" "$work/src/deploy/bundle"
cp -a "$compose_src" "$work/src/deploy/compose"
rm -rf "$work/src/deploy/compose/.secrets" "$work/src/deploy/compose/.env"
sed -i -E '0,/^  [a-z][a-z0-9-]*:$/s//&\n    build: ./' "$work/src/deploy/compose/compose.prod.yaml"
set +e
out="$(build "$work/src/deploy/bundle" "$work/c" 2>&1)"
rc=$?
set -e
if [[ $rc -eq 1 && "$out" == *"compose.prod.yaml"* ]]; then pass "build.sh refuses a build section: $out"; else
  fail "build.sh with a build section in compose.prod.yaml: exit $rc, $out"
fi

# ./paddock refusals: exit code and message.
expect() {
  local want="$1" name="$2" dir="$3" rc
  shift 3
  set +e
  out="$(cd "$dir" && ./paddock "$@" 2>&1)"
  rc=$?
  set -e
  if [[ $rc -eq $want ]]; then pass "./paddock $name: exit $rc"; else fail "./paddock $name: exit $rc, want $want: $out"; fi
}
cp -a "$bundle" "$work/p"
expect 2 "unknown command" "$work/p" frobnicate
expect 2 "ps without .env" "$work/p" ps
sed 's/^PADDOCK_ENV=.*/PADDOCK_ENV=development/' "$work/p/.env.example" >"$work/p/.env"
expect 2 "ps with PADDOCK_ENV=development" "$work/p" ps
sed 's/^PADDOCK_HOST=.*/PADDOCK_HOST=/' "$work/p/.env.example" >"$work/p/.env"
expect 2 "ps without PADDOCK_HOST" "$work/p" ps
cp "$work/p/.env.example" "$work/p/.env"
mkdir -p "$work/p/.secrets"
echo old >"$work/p/.secrets/marker"
cp -a "$bundle" "$work/q"
expect 0 "migrate-from into a fresh directory" "$work/q" migrate-from "$work/p"
[[ "$(cat "$work/q/.secrets/marker" 2>/dev/null)" == old ]] && pass "migrate-from copied .secrets/" ||
  fail "migrate-from did not copy .secrets/"
rm "$work/q/.env"
expect 1 "migrate-from onto an existing .secrets/" "$work/q" migrate-from "$work/p"

# agent-release refuses a release directory the paddock-api service (uid 65532) cannot read (plan M8x decision 50).
mkdir -p "$work/release"
echo x >"$work/release/paddockd"
chmod 700 "$work/release"
expect 1 "agent-release with a 0700 release directory" "$work/p" agent-release 1.0.0 "$work/release"
if [[ "$out" == *"chmod -R a+rX $work/release"* && "$out" == *"$work/release"* ]]; then
  pass "the release directory refusal names chmod -R a+rX"
else
  fail "the release directory refusal: $out"
fi
chmod 755 "$work/release"

# The lab host (plan M8a decision 8): accepted with its own settings; the backup file only with PADDOCK_LAB_BACKUP=yes.
cp -a "$bundle" "$work/l"
sed 's/^PADDOCK_HOST=.*/PADDOCK_HOST=frobnicate/' "$work/l/.env.lab.example" >"$work/l/.env"
expect 2 "ps with PADDOCK_HOST=frobnicate" "$work/l" ps
if [[ "$out" == *"controlplane, audit or lab"* ]]; then pass "the host refusal names lab"; else fail "the host refusal: $out"; fi
cp "$work/l/.env.lab.example" "$work/l/.env"
expect 0 "compose on a lab host" "$work/l" compose --profile '*' config --services
if [[ $'\n'"$out"$'\n' == *$'\n'paddock-audit-writer$'\n'* && $'\n'"$out"$'\n' != *$'\n'pgbackrest$'\n'* ]]; then
  pass "the lab runs the audit domain and, with PADDOCK_LAB_BACKUP=no, no backup"
else
  fail "the lab services with PADDOCK_LAB_BACKUP=no: $out"
fi
sed -i 's/^PADDOCK_LAB_BACKUP=.*/PADDOCK_LAB_BACKUP=yes/' "$work/l/.env"
expect 0 "compose on a lab host with backups" "$work/l" compose --profile '*' config --services
if [[ $'\n'"$out"$'\n' == *$'\n'pgbackrest$'\n'* ]]; then pass "PADDOCK_LAB_BACKUP=yes adds the backup services"; else
  fail "the lab services with PADDOCK_LAB_BACKUP=yes: $out"
fi

# Automatic unseal (plan M8u decisions 14, 16 and 18): the overlay joins the file set of a control-plane or lab host
# only with PADDOCK_AUTO_UNSEAL=yes, before the lab's backup file, never on the audit host; the unsealer is hardened,
# holds its three secrets only and sits on the network cp only; the host commands refuse without their preconditions.
# files_of <dir>: the Compose files ./paddock would use there, as base names on one line.
files_of() { (cd "$1" && bash -c '. scripts/lib.sh; compose_files' | xargs -n1 basename | paste -sd' ' -); }
cp -a "$bundle" "$work/u"
cp "$work/u/.env.example" "$work/u/.env"
want="$(lib_files "$work/u" PROD_FILES_controlplane)"
[[ "$(files_of "$work/u")" == "$want" ]] && pass "controlplane without PADDOCK_AUTO_UNSEAL=yes: no overlay" ||
  fail "controlplane file set with PADDOCK_AUTO_UNSEAL=no: $(files_of "$work/u")"
sed -i 's/^PADDOCK_AUTO_UNSEAL=.*/PADDOCK_AUTO_UNSEAL=yes/' "$work/u/.env"
[[ "$(files_of "$work/u")" == "$want compose.auto-unseal.yaml" ]] && pass "controlplane with PADDOCK_AUTO_UNSEAL=yes: the overlay last" ||
  fail "controlplane file set with PADDOCK_AUTO_UNSEAL=yes: $(files_of "$work/u")"
sed -i 's/^PADDOCK_HOST=.*/PADDOCK_HOST=audit/' "$work/u/.env"
[[ "$(files_of "$work/u")" == "$(lib_files "$work/u" PROD_FILES_audit)" ]] && pass "the audit host never gets the overlay" ||
  fail "audit file set with PADDOCK_AUTO_UNSEAL=yes: $(files_of "$work/u")"
cp "$work/u/.env.lab.example" "$work/u/.env"
sed -i -e 's/^PADDOCK_AUTO_UNSEAL=.*/PADDOCK_AUTO_UNSEAL=yes/' -e 's/^PADDOCK_LAB_BACKUP=.*/PADDOCK_LAB_BACKUP=yes/' "$work/u/.env"
[[ "$(files_of "$work/u")" == "$(lib_files "$work/u" PROD_FILES_lab) compose.auto-unseal.yaml compose.backup.yaml" ]] &&
  pass "lab with backups: the overlay before compose.backup.yaml" || fail "lab file set: $(files_of "$work/u")"
[[ "$(lib_files "$compose_src" DEV_FILES)" == "compose.yaml compose.audit.yaml compose.auto-unseal.yaml compose.dev.yaml" ]] &&
  pass "DEV_FILES includes the overlay before compose.dev.yaml" || fail "DEV_FILES: $(lib_files "$compose_src" DEV_FILES)"

# unsealer_json <host>: the rendered paddock-unsealer service of the variant as JSON.
unsealer_json() {
  local settings=.env.example f args=()
  [[ "$1" != lab* ]] || settings=.env.lab.example
  for f in $(host_files "$bundle" "$1"); do args+=(-f "$bundle/$f"); done
  docker compose --project-directory "$bundle" -p paddock-bundle-test --env-file "$bundle/versions.env" \
    --env-file "$bundle/$settings" "${args[@]}" --profile '*' config --format json |
    python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps({"u": d["services"]["paddock-unsealer"], "p": d["services"]["prometheus"]["volumes"]}))'
}
for host in controlplane-auto-unseal lab-auto-unseal; do
  if unsealer_json "$host" | python3 -I -c '
import json, sys
d = json.load(sys.stdin); u = d["u"]
secrets = sorted(s["source"] for s in u["secrets"])
env = u["environment"]
problems = []
if u.get("cap_drop") != ["ALL"]: problems.append("cap_drop")
if "no-new-privileges:true" not in u.get("security_opt", []): problems.append("no-new-privileges")
if not u.get("read_only"): problems.append("read_only")
if u.get("pids_limit") != 256: problems.append("pids_limit")
if secrets != ["db_paddock_unsealer_url", "internal_ca_bundle", "openbao_auto_unseal_shares"]: problems.append("secrets %s" % secrets)
if sorted(u["networks"]) != ["cp"]: problems.append("networks %s" % sorted(u["networks"]))
if env.get("PADDOCK_OPENBAO_ADDR") != "https://openbao:8200" or env.get("BAO_CACERT") != "/run/secrets/internal_ca_bundle": problems.append("openbao tls")
for v in ("PADDOCK_OPENBAO_ROLE_ID_FILE", "PADDOCK_OPENBAO_SECRET_ID_FILE", "PADDOCK_VALKEY_ADDR", "PADDOCK_AMQP_URL"):
    if v in env: problems.append(v)
if not any(v.get("target") == "/etc/prometheus/scrape/auto-unseal.yml" for v in d["p"]): problems.append("prometheus scrape mount")
print(", ".join(problems)); sys.exit(1 if problems else 0)
' >"$work/unsealer.out"; then
    pass "$host: the unsealer is hardened, holds three secrets, sits on cp and is scraped"
  else
    fail "$host: the unsealer: $(cat "$work/unsealer.out")"
  fi
done

cp "$work/u/.env.example" "$work/u/.env"
sed -i 's/^PADDOCK_HOST=.*/PADDOCK_HOST=audit/' "$work/u/.env"
expect 2 "auto-unseal enable on the audit host" "$work/u" auto-unseal enable
expect 2 "auto-unseal without a subcommand" "$work/u" auto-unseal
cp "$work/u/.env.example" "$work/u/.env"
sed -i 's/^PADDOCK_AUTO_UNSEAL=.*/PADDOCK_AUTO_UNSEAL=yes/' "$work/u/.env"
expect 1 "auto-unseal enable while PADDOCK_AUTO_UNSEAL=yes" "$work/u" auto-unseal enable
[[ "$out" == *"run ./paddock auto-unseal disable first"* ]] && pass "the refusal names auto-unseal disable" ||
  fail "the refusal while enabled: $out"
sed -i 's/^PADDOCK_AUTO_UNSEAL=.*/PADDOCK_AUTO_UNSEAL=no/' "$work/u/.env"
mkdir -p "$work/u/.secrets/openbao"
echo leftover >"$work/u/.secrets/openbao/auto-unseal-shares"
expect 1 "auto-unseal enable while a shares file exists" "$work/u" auto-unseal enable
rm "$work/u/.secrets/openbao/auto-unseal-shares"

# enable and disable against a stand-in for docker that logs every command line: the portal acknowledgement gates
# the shares, the shares are validated, written 0644 in the 0700 directory and never appear in an output or a
# command line.
mkdir -p "$work/fakebin"
cat >"$work/fakebin/docker" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
# Like docker compose run and exec, the stand-in reads its stdin: a command of enable that is not redirected
# swallows the shares.
[[ -t 0 ]] || cat >/dev/null
case "$*" in
  *"auto-unseal verify"*)
    if [[ "$FAKE_VERIFY" == ok ]]; then
      echo '{"level":"INFO","msg":"startup"}'
      echo "automatic unseal acknowledged by Root Admin on 2026-10-17T09:30:00Z (disclaimer 2026-10-17)"
      exit 0
    fi
    echo "automatic unseal is not enabled: a platform administrator enables it in the portal first (Platform → OpenBao)"
    exit 1
    ;;
esac
exit 0
FAKE
chmod +x "$work/fakebin/docker"
export FAKE_DOCKER_LOG="$work/docker.log"
cp "$work/u/.env.lab.example" "$work/u/.env"
shares=(Share1+AbCdEfGhIjKlMnOpQrStUv Share2+AbCdEfGhIjKlMnOpQrStUv Share3+AbCdEfGhIjKlMnOpQrStUv)
# enable_with <verify> <stdin>: ./paddock auto-unseal enable with the stand-in; output in $out, exit code in $rc.
enable_with() {
  set +e
  out="$(cd "$work/u" && env -u SECRETS_DIR PATH="$work/fakebin:$PATH" FAKE_VERIFY="$1" ./paddock auto-unseal enable <<<"$2" 2>&1)"
  rc=$?
  set -e
}
: >"$FAKE_DOCKER_LOG"
enable_with refused "$(printf '%s\n' "${shares[@]}")"
if [[ $rc -ne 0 && "$out" == *"automatic unseal is not enabled: a platform administrator enables it in the portal first"* &&
  ! -e "$work/u/.secrets/openbao/auto-unseal-shares" ]]; then
  pass "enable refuses without the portal acknowledgement and writes no shares"
else
  fail "enable without the acknowledgement: exit $rc, $out"
fi
for bad in "empty|$(printf '%s\n\n%s' "${shares[0]}" "${shares[2]}")" "whitespace|$(printf '%s\n%s\n%s' "${shares[0]}" "a b" "${shares[2]}")" \
  "equal|$(printf '%s\n%s\n%s' "${shares[0]}" "${shares[0]}" "${shares[2]}")"; do
  enable_with ok "${bad#*|}"
  if [[ $rc -ne 0 && ! -e "$work/u/.secrets/openbao/auto-unseal-shares" && "$(grep '^PADDOCK_AUTO_UNSEAL=' "$work/u/.env")" == PADDOCK_AUTO_UNSEAL=no ]]; then
    pass "enable refuses a share that is ${bad%%|*}"
  else
    fail "enable with a share that is ${bad%%|*}: exit $rc, $out"
  fi
done
: >"$FAKE_DOCKER_LOG"
enable_with ok "$(printf '%s\n' "${shares[@]}")"
f="$work/u/.secrets/openbao/auto-unseal-shares"
if [[ $rc -eq 0 && "$(cat "$f" 2>/dev/null)" == "$(printf '%s\n' "${shares[@]}")" && "$(stat -c %a "$f")" == 644 &&
  "$(stat -c %a "$work/u/.secrets/openbao")" == 700 && "$(stat -c %a "$work/u/.secrets")" == 700 &&
  "$(grep -c '^PADDOCK_AUTO_UNSEAL=yes$' "$work/u/.env")" == 1 && ! -e "$work/u/.env".?????? ]]; then
  pass "enable writes the three shares (0644 in the 0700 directory) and sets PADDOCK_AUTO_UNSEAL=yes"
else
  fail "enable: exit $rc, $out; mode $(stat -c %a "$f" 2>/dev/null)"
fi
[[ "$out" == *'automatic unseal is enabled on this host. Verify it now: ./paddock compose restart openbao, then ./paddock bao status shows "Sealed false" within 30 s. Remove every other unseal automation (for example a cron job) and its copies of the shares.'* ]] &&
  pass "enable prints the verification message" || fail "enable message: $out"
grep -q -- "up -d paddock-unsealer" "$FAKE_DOCKER_LOG" && grep -q -- "-f $work/u/compose.auto-unseal.yaml" "$FAKE_DOCKER_LOG" &&
  pass "enable starts paddock-unsealer with the overlay" || fail "enable did not start the unsealer: $(cat "$FAKE_DOCKER_LOG")"
leaked=""
for s in "${shares[@]}"; do
  if [[ "$out" == *"$s"* ]] || grep -qF -- "$s" "$FAKE_DOCKER_LOG"; then leaked=1; fi
done
[[ -z "$leaked" ]] && pass "no share in the output or on a docker command line" || fail "a share leaked into the output or a command line"

set +e
out="$(cd "$work/u" && env -u SECRETS_DIR PATH="$work/fakebin:$PATH" ./paddock auto-unseal disable 2>&1 </dev/null)"
rc=$?
set -e
if [[ $rc -eq 0 && ! -e "$f" && "$(grep -c '^PADDOCK_AUTO_UNSEAL=no$' "$work/u/.env")" == 1 &&
  "$out" == *"the shares are deleted from this host. If the host, its disk or its backups may have been copied while automatic unseal was on, rotate the shares with three custodians (docs/operations/openbao.md section 6). If the portal still shows automatic unseal as enabled, a platform administrator disables it there."* ]]; then
  pass "disable deletes the shares, sets PADDOCK_AUTO_UNSEAL=no and prints the rotation advice"
else
  fail "disable: exit $rc, $out"
fi
set +e
out="$(cd "$work/u" && env -u SECRETS_DIR PATH="$work/fakebin:$PATH" ./paddock auto-unseal disable 2>&1 </dev/null)"
rc=$?
set -e
[[ $rc -eq 0 ]] && pass "auto-unseal disable a second time: exit 0" || fail "disable a second time: exit $rc, $out"
unset FAKE_DOCKER_LOG

if ((failures > 0)); then
  echo "bundle: $failures check(s) failed" >&2
  exit 1
fi
echo "bundle: all checks passed"
