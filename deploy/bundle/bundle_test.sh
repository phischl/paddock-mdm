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

# backup_root_mount (PDK-760): ./paddock check mounts the parent of the local backup root read-only at its own path, so
# prod-check lstats the root itself; a root it cannot mount that way mounts nothing.
mkdir -p "$work/srv/backup"
mount_of() { (. "$compose_src/scripts/lib.sh" && backup_root_mount "$1" | paste -sd' ' -); }
if [[ "$(mount_of "$work/srv/backup")" == "--mount type=bind,src=$work/srv,dst=$work/srv,readonly" ]]; then
  pass "backup_root_mount mounts the parent of the root read-only at its own path"
else
  fail "backup_root_mount: $(mount_of "$work/srv/backup")"
fi
for root in / /srv "$work/srv/backup/" "$work/srv/../srv/backup" relative/x "$work/nope/backup"; do
  [[ -z "$(mount_of "$root")" ]] && pass "backup_root_mount mounts nothing for '$root'" || fail "backup_root_mount mounts for '$root': $(mount_of "$root")"
done
if grep -q 'backup_root_mount "$(dotenv PADDOCK_BACKUP_LOCAL_ROOT)"' "$here/paddock"; then
  pass "./paddock check passes the backup root's parent to prod-check"
else
  fail "./paddock check does not call backup_root_mount"
fi

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
  # Production and lab serve Authentik on 443 and its issuers carry no port: an issuer with an explicit port (the
  # development default 8443, or 443 from PADDOCK_HTTPS_PORT) never matches discovery, and the api never becomes ready
  # (PDK-492).
  if port_issuers="$(grep -E 'PADDOCK_OIDC_[A-Z_]*ISSUER: https://[^/]*:[0-9]+/' "$work/repo.yaml")"; then
    fail "(a) the $host configuration has an OIDC issuer with an explicit port: $port_issuers"
  else
    pass "(a) every OIDC issuer of the $host configuration has no explicit port"
  fi
  # The one-minute MCP access tokens are a development setting (paddock-mcp.yaml, PDK-467).
  if grep -q 'PADDOCK_MCP_ACCESS_TOKEN_VALIDITY' "$work/repo.yaml"; then
    fail "(a) the $host configuration sets PADDOCK_MCP_ACCESS_TOKEN_VALIDITY, a development setting"
  else
    pass "(a) the $host configuration keeps the production MCP access token lifetime"
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
[[ ! -e "$work/q/compose.backup-targets.yaml" ]] && pass "migrate-from without a targets file creates none" ||
  fail "migrate-from created compose.backup-targets.yaml"
rm "$work/q/.env"
expect 1 "migrate-from onto an existing .secrets/" "$work/q" migrate-from "$work/p"
# PDK-733 review 2 (R2-M1): the rendered backup targets move with the upgrade, or paddock-backup loses its volumes.
(umask 077 && echo 'services: {} # old targets' >"$work/p/compose.backup-targets.yaml")
cp -a "$bundle" "$work/q2"
expect 0 "migrate-from with a targets file" "$work/q2" migrate-from "$work/p"
cmp -s "$work/p/compose.backup-targets.yaml" "$work/q2/compose.backup-targets.yaml" &&
  [[ "$(stat -c '%a %u' "$work/q2/compose.backup-targets.yaml")" == "600 $(id -u)" ]] &&
  pass "migrate-from copies compose.backup-targets.yaml with mode 0600 and its owner" ||
  fail "migrate-from targets file: $(stat -c '%a %u' "$work/q2/compose.backup-targets.yaml" 2>&1)"
cp -a "$bundle" "$work/q3"
echo 'services: {} # newer' >"$work/q3/compose.backup-targets.yaml"
expect 1 "migrate-from onto an existing targets file" "$work/q3" migrate-from "$work/p"
[[ "$(cat "$work/q3/compose.backup-targets.yaml")" == *newer* && ! -e "$work/q3/.env" ]] &&
  pass "migrate-from onto an existing targets file changes nothing" || fail "migrate-from overwrote a targets file"
rm "$work/p/compose.backup-targets.yaml"
ln -s /etc/hostname "$work/p/compose.backup-targets.yaml"
cp -a "$bundle" "$work/q4"
expect 1 "migrate-from with a symlinked targets file" "$work/q4" migrate-from "$work/p"
rm "$work/p/compose.backup-targets.yaml"
# PDK-733 review 3 (R3-m1): a targets copy that fails halfway (disk full) leaves nothing, so the next run is not refused.
(umask 077 && echo 'services: {} # old targets' >"$work/p/compose.backup-targets.yaml")
mkdir -p "$work/fakebin-cp"
cat >"$work/fakebin-cp/cp" <<FAKE
#!/usr/bin/env bash
if [[ "\$*" == *"/compose.backup-targets.yaml "* ]]; then echo 'services: {' >"\${*: -1}"; echo "cp: No space left on device" >&2; exit 1; fi
exec $(command -v cp) "\$@"
FAKE
chmod +x "$work/fakebin-cp/cp"
cp -a "$bundle" "$work/q5"
PATH="$work/fakebin-cp:$PATH" expect 1 "migrate-from with a failing targets copy" "$work/q5" migrate-from "$work/p"
[[ "$out" == *"could not copy"*"nothing changed"* ]] &&
  [[ ! -e "$work/q5/.env" && ! -e "$work/q5/.secrets" && ! -e "$work/q5/compose.backup-targets.yaml" ]] &&
  [[ -z "$(find "$work/q5" -maxdepth 1 -name '.compose.backup-targets.yaml.*')" ]] &&
  pass "a failing targets copy leaves neither .env, .secrets/, the targets file nor a temp file" ||
  fail "failing targets copy left: $(ls -A "$work/q5" | grep -e '^\.env$' -e secrets -e backup-targets)"
expect 0 "migrate-from again after a failing targets copy" "$work/q5" migrate-from "$work/p"
cmp -s "$work/p/compose.backup-targets.yaml" "$work/q5/compose.backup-targets.yaml" &&
  [[ -z "$(find "$work/q5" -maxdepth 1 -name '.compose.backup-targets.yaml.*')" ]] &&
  pass "the re-run copies the targets file and leaves no temp file" || fail "re-run after a failing copy"
rm "$work/p/compose.backup-targets.yaml"

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

# agent-rollout, agent-rollout-halt and agent-rollout-resume (ADR 0034 amendment 2026-10-26): usage errors, and only on
# the control plane or a lab host.
expect 2 "agent-rollout without a version" "$work/p" agent-rollout
expect 2 "agent-rollout with an option instead of a version" "$work/p" agent-rollout --waves 100
expect 2 "agent-rollout-halt without a version" "$work/p" agent-rollout-halt
expect 2 "agent-rollout-halt with an option" "$work/p" agent-rollout-halt 1.0.0 --waves 100
expect 2 "agent-rollout-resume without a version" "$work/p" agent-rollout-resume
expect 2 "agent-rollout-resume with an option" "$work/p" agent-rollout-resume 1.0.0 --waves 100
if [[ "$out" == *"usage: ./paddock agent-rollout-resume <version>"* ]]; then pass "the agent-rollout-resume usage names the command"; else
  fail "the agent-rollout-resume usage: $out"
fi
# restore and backup-target export (plan M15 decisions 23–24): usage errors before anything runs, the control plane only.
expect 2 "restore without a source" "$work/p" restore
expect 2 "restore with --from and --from-target-file" "$work/p" restore --from a --from-target-file b
expect 2 "restore --plan with --only" "$work/p" restore --plan 11111111-2222-3333-4444-555555555555 --only fleet
if [[ "$out" == *"usage: ./paddock restore --plan <id>"* ]]; then pass "the restore usage names the forms"; else
  fail "the restore usage: $out"
fi
expect 2 "backup-target without a subcommand" "$work/p" backup-target
expect 2 "backup-target export without a file" "$work/p" backup-target export offsite
sed 's/^PADDOCK_HOST=.*/PADDOCK_HOST=audit/' "$work/p/.env.example" >"$work/p/.env"
expect 2 "agent-rollout on the audit host" "$work/p" agent-rollout 1.0.0
expect 2 "restore on the audit host" "$work/p" restore --from x
expect 2 "backup-target export on the audit host" "$work/p" backup-target export offsite out.json
if [[ "$out" == *"runs on the controlplane host"* ]]; then pass "the agent-rollout host refusal names the control plane"; else
  fail "the agent-rollout host refusal: $out"
fi
expect 2 "agent-rollout-halt on the audit host" "$work/p" agent-rollout-halt 1.0.0
expect 2 "agent-rollout-resume on the audit host" "$work/p" agent-rollout-resume 1.0.0
cp "$work/p/.env.example" "$work/p/.env"

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
# holds its three secrets only and sits on the network data only; the host commands refuse without their preconditions.
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
if sorted(u["networks"]) != ["data"]: problems.append("networks %s" % sorted(u["networks"]))
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

# The audit writer's export temp space (PDK-593): TMPDIR on the named volume, /tmp a noexec, nosuid, nodev tmpfs, the
# root read-only; in the audit-host and lab bundles and in the development stack (which the bundle does not ship).
audit_writer_ok() {
  local dir="$1" settings="$2" f args=()
  shift 2
  for f in "$@"; do args+=(-f "$dir/$f"); done
  docker compose --project-directory "$dir" -p paddock-bundle-test --env-file "$dir/versions.env" \
    --env-file "$dir/$settings" "${args[@]}" --profile '*' config --format json | python3 -I -c '
import json, sys
w = json.load(sys.stdin)["services"]["paddock-audit-writer"]
problems = []
tmp = [t for t in w.get("tmpfs", []) if t.split(":")[0] == "/tmp"]
if len(tmp) != 1 or not {"noexec", "nosuid", "nodev"} <= set(tmp[0].partition(":")[2].split(",")): problems.append("/tmp tmpfs %s" % tmp)
if not w.get("read_only"): problems.append("read_only")
if w["environment"].get("TMPDIR") != "/var/lib/paddock/export-tmp": problems.append("TMPDIR %s" % w["environment"].get("TMPDIR"))
vols = [(v.get("type"), v.get("source"), v.get("target")) for v in w.get("volumes", [])]
if vols != [("volume", "audit-writer-tmp", "/var/lib/paddock/export-tmp")]: problems.append("volumes %s" % vols)
print(", ".join(problems)); sys.exit(1 if problems else 0)
'
}
for host in audit lab; do
  settings=.env.example
  [[ "$host" != lab* ]] || settings=.env.lab.example
  # shellcheck disable=SC2046 # the file list is word-split on purpose
  if out="$(audit_writer_ok "$bundle" "$settings" $(host_files "$bundle" "$host"))"; then
    pass "$host: the audit writer keeps /tmp noexec, nosuid, nodev and TMPDIR on audit-writer-tmp"
  else
    fail "$host: the audit writer's temp space: $out"
  fi
done
# shellcheck disable=SC2046
if out="$(audit_writer_ok "$compose_src" .env.example $(lib_files "$compose_src" DEV_FILES))"; then
  pass "dev: the audit writer keeps /tmp noexec, nosuid, nodev and TMPDIR on audit-writer-tmp"
else
  fail "dev: the audit writer's temp space: $out"
fi

# The notifier (plan M9 decision 41, amendment B13.1): production on cp and audit-index, TLS to OpenBao, exactly its
# secrets, hardened by the anchor, no lab extra_hosts, scraped.
for host in controlplane lab; do
  settings=.env.example
  [[ "$host" != lab ]] || settings=.env.lab.example
  args=()
  for f in $(host_files "$bundle" "$host"); do args+=(-f "$bundle/$f"); done
  if docker compose --project-directory "$bundle" -p paddock-bundle-test --env-file "$bundle/versions.env" \
    --env-file "$bundle/$settings" "${args[@]}" --profile '*' config --format json | python3 -I -c '
import json, sys
d = json.load(sys.stdin); n = d["services"]["paddock-notifier"]; env = n["environment"]
problems = []
if n.get("cap_drop") != ["ALL"] or "no-new-privileges:true" not in n.get("security_opt", []) or not n.get("read_only") or n.get("pids_limit") != 256: problems.append("hardening")
if n.get("command") != ["serve", "notifier"]: problems.append("command %s" % n.get("command"))
secrets = sorted(s["source"] for s in n["secrets"])
if secrets != ["approle_notifier_role_id", "approle_notifier_secret_id", "db_paddock_audit_reader_url", "db_paddock_notifier_url", "db_paddock_platform_url", "internal_ca_bundle", "smtp_password"]: problems.append("secrets %s" % secrets)
if sorted(n["networks"]) != ["audit-index", "data"]: problems.append("networks %s" % sorted(n["networks"]))
if n.get("extra_hosts"): problems.append("extra_hosts")
if env.get("PADDOCK_ENV") != "production": problems.append("PADDOCK_ENV")
if env.get("PADDOCK_OPENBAO_ADDR") != "https://openbao:8200" or env.get("BAO_CACERT") != "/run/secrets/internal_ca_bundle": problems.append("openbao tls")
for v in ("PADDOCK_DB_NOTIFIER_URL_FILE", "PADDOCK_DB_PLATFORM_URL_FILE", "PADDOCK_AUDIT_DB_READER_URL_FILE", "PADDOCK_OPENBAO_ROLE_ID_FILE", "PADDOCK_OPENBAO_SECRET_ID_FILE", "PADDOCK_PUBLIC_ADMIN_URL", "PADDOCK_SMTP_PASSWORD_FILE"):
    if not env.get(v): problems.append(v)
if env.get("PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE") or env.get("PADDOCK_SMTP_TLS") == "none": problems.append("development settings")
if d["services"]["paddock-api"]["environment"].get("PADDOCK_SMTP_ENABLED") != "false": problems.append("api PADDOCK_SMTP_ENABLED")
print(", ".join(problems)); sys.exit(1 if problems else 0)
' >"$work/notifier.out"; then
    pass "$host: the notifier is hardened, holds its seven secrets, sits on cp and audit-index and talks TLS to OpenBao"
  else
    fail "$host: the notifier: $(cat "$work/notifier.out")"
  fi
done
if grep -q '"paddock-notifier:9090"' "$bundle/prometheus/scrape/controlplane.yml"; then pass "Prometheus scrapes paddock-notifier"; else
  fail "prometheus/scrape/controlplane.yml has no target paddock-notifier:9090"
fi

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


# Backup targets on the host (plan M15 decisions 20–22, decisions-alpha9 items 35 and 36): the rendered file joins the
# file set only on a host with backups; ./paddock backup-target apply writes it 0600 from the render, tries it before it
# replaces the old one, removes stale volumes and the rows of deleted targets, and no SMB password reaches an output or
# a command line.
redacted="$( (. "$compose_src/scripts/lib.sh" && printf '%s\n' \
  "mount //127.0.0.1/share:/var/lib/docker/volumes/x/_data, data: vers=3,username=u,password=********,,tail: connection refused" \
  'o: "uid=999,username=svc,password=S3cr3t,,pass$$word"' 'no secret here' | redact_mount_secrets))"
if [[ "$redacted" == $'mount //127.0.0.1/share:/var/lib/docker/volumes/x/_data, data: vers=3,username=u,password=<redacted>\no: "uid=999,username=svc,password=<redacted>\nno secret here' ]]; then
  pass "redact_mount_secrets cuts every line after password="
else
  fail "redact_mount_secrets: $redacted"
fi
# PDK-733 review 2 (R2-m2): behind Docker's mask the errno stays; anything else after password= still goes.
redacted="$( (. "$compose_src/scripts/lib.sh" && printf '%s\n' \
  "data: vers=3,username=u,password=********: permission denied" \
  'o: "uid=999,username=svc,password=********: secret"' \
  "data: vers=3,username=u,password=********: Secret" | redact_mount_secrets))"
if [[ "$redacted" == $'data: vers=3,username=u,password=<redacted>: permission denied\no: "uid=999,username=svc,password=<redacted>\ndata: vers=3,username=u,password=<redacted>' ]]; then
  pass "redact_mount_secrets keeps the errno behind Docker's mask"
else
  fail "redact_mount_secrets errno: $redacted"
fi
rr_rc=0
rr_out="$( (. "$compose_src/scripts/lib.sh" && run_redacted bash -c 'echo out; echo "password=hunter2" >&2; exit 7') 2>&1)" || rr_rc=$?
[[ $rr_rc == 7 && "$rr_out" == *out* && "$rr_out" == *"password=<redacted>"* && "$rr_out" != *hunter2* ]] &&
  pass "run_redacted keeps stdout and the exit code and redacts stderr" || fail "run_redacted: exit $rr_rc, $rr_out"
if tar -tzf "$work/a/paddock-deploy-0.0.0-test.tar.gz" | grep -q 'compose.backup-targets'; then
  fail "the tarball ships compose.backup-targets.yaml"
else
  pass "the tarball does not ship compose.backup-targets.yaml"
fi
grep -qxF 'deploy/compose/compose.backup-targets.yaml' "$here/../../.gitignore" &&
  pass ".gitignore excludes compose.backup-targets.yaml" || fail ".gitignore does not exclude compose.backup-targets.yaml"

cp -a "$bundle" "$work/t"
cp "$work/t/.env.example" "$work/t/.env"
targets_file="$work/t/compose.backup-targets.yaml"
echo 'services: {}' >"$targets_file"
[[ "$(files_of "$work/t")" == "$(lib_files "$work/t" PROD_FILES_controlplane) compose.backup-targets.yaml" ]] &&
  pass "controlplane: the rendered targets file joins the file set last" || fail "controlplane with targets: $(files_of "$work/t")"
[[ "$(cd "$work/t" && BACKUP_TARGETS_OVERLAY='' bash -c '. scripts/lib.sh; compose_files' | grep -c backup-targets)" == 0 ]] &&
  pass "BACKUP_TARGETS_OVERLAY='' leaves the targets file out" || fail "BACKUP_TARGETS_OVERLAY='' keeps the targets file"
cp "$work/t/.env.lab.example" "$work/t/.env"
[[ "$(files_of "$work/t")" != *backup-targets* ]] && pass "lab without backups: no targets file" ||
  fail "lab without backups: $(files_of "$work/t")"
expect 2 "backup-target apply on a lab host without backups" "$work/t" backup-target apply
sed -i 's/^PADDOCK_LAB_BACKUP=.*/PADDOCK_LAB_BACKUP=yes/' "$work/t/.env"
[[ "$(files_of "$work/t")" == *" compose.backup.yaml compose.backup-targets.yaml" ]] &&
  pass "lab with backups: the targets file after compose.backup.yaml" || fail "lab with backups: $(files_of "$work/t")"
cp "$work/t/.env.example" "$work/t/.env"
sed -i 's/^PADDOCK_HOST=.*/PADDOCK_HOST=audit/' "$work/t/.env"
expect 2 "backup-target apply on the audit host" "$work/t" backup-target apply
expect 2 "backup now on the audit host" "$work/t" backup now
cp "$work/t/.env.example" "$work/t/.env"
rm "$targets_file"

# The legacy key import (decisions-alpha9 item 63): a fresh installation has no .secrets/backup_encryption_key and
# leaves the import out; an installation upgraded from 0.1.0-alpha.8 keeps the file (migrate-from) and gets the import,
# on a host with backups only. A present file is mounted whatever it is, so a broken one fails the start.
legacy_key="$work/t/.secrets/backup_encryption_key"
mkdir -p "$work/t/.secrets"
[[ "$(files_of "$work/t")" == "$(lib_files "$work/t" PROD_FILES_controlplane)" ]] &&
  pass "fresh control plane: no legacy key import" || fail "fresh control plane: $(files_of "$work/t")"
expect 0 "compose on a fresh control plane" "$work/t" compose --profile '*' config
[[ "$out" != *PADDOCK_BACKUP_LEGACY_KEY_FILE* && "$out" != *backup_encryption_key* ]] &&
  pass "fresh control plane: the api neither names nor mounts a legacy key" || fail "fresh control plane names the legacy key"
echo placeholder >"$legacy_key"
[[ "$(files_of "$work/t")" == "$(lib_files "$work/t" PROD_FILES_controlplane) compose.backup-legacy-key.yaml" ]] &&
  pass "upgraded control plane: the legacy key import joins the file set" || fail "upgraded control plane: $(files_of "$work/t")"
expect 0 "compose on an upgraded control plane" "$work/t" compose --profile '*' config
[[ "$out" == *"PADDOCK_BACKUP_LEGACY_KEY_FILE: /run/secrets/backup_encryption_key"* ]] &&
  pass "upgraded control plane: the api imports the host file" || fail "upgraded control plane: the api lacks the import"
rm "$legacy_key"
ln -s "$work/t/.secrets/missing" "$legacy_key"
[[ "$(files_of "$work/t")" == *" compose.backup-legacy-key.yaml" ]] &&
  pass "a dangling key file link still joins the import" || fail "a dangling key file link is skipped: $(files_of "$work/t")"
sed -i 's/^PADDOCK_HOST=.*/PADDOCK_HOST=audit/' "$work/t/.env"
[[ "$(files_of "$work/t")" != *legacy-key* ]] && pass "the audit host never imports a legacy key" ||
  fail "audit host: $(files_of "$work/t")"
cp "$work/t/.env.lab.example" "$work/t/.env"
[[ "$(files_of "$work/t")" != *legacy-key* ]] && pass "lab without backups: no legacy key import" ||
  fail "lab without backups: $(files_of "$work/t")"
sed -i 's/^PADDOCK_LAB_BACKUP=.*/PADDOCK_LAB_BACKUP=yes/' "$work/t/.env"
[[ "$(files_of "$work/t")" == *" compose.backup.yaml compose.backup-legacy-key.yaml" ]] &&
  pass "lab with backups: the legacy key import after compose.backup.yaml" || fail "lab with backups: $(files_of "$work/t")"
rm -rf "$work/t/.secrets"
cp "$work/t/.env.example" "$work/t/.env"
expect 2 "backup-target without apply" "$work/t" backup-target
expect 2 "backup without a subcommand" "$work/t" backup

# The render fixture: an SMB target whose password has a comma and a dollar, an NFS and a local target, and a deleted
# target whose old volume is still there.
password='S3cr3t,,pass$$word'
smb=10000000-0000-4000-8000-000000000001 nfs=20000000-0000-4000-8000-000000000002
loc=30000000-0000-4000-8000-000000000003 gone=40000000-0000-4000-8000-000000000004
smbv=backup-target-$smb-r3-0123456789ab nfsv=backup-target-$nfs-r1-0a1b2c3d4e5f locv=backup-target-$loc-r1-ffeeddccbbaa
fixture="# Rendered by ./paddock backup-target apply on 2026-11-06T10:00:00Z from the database; do not edit.
# revisions: $smb=3 $nfs=1 $loc=1
# local: $(printf %s /srv/paddock-backup/paddock-backup | base64 -w0)
services:
  paddock-backup:
    volumes:
      - \"$smbv:/backup-targets/$smb\"
volumes:
  $smbv:
    driver: local
    driver_opts:
      type: \"cifs\"
      device: \"//nas.example.org/backup\$\$\"
      o: \"uid=999,gid=999,file_mode=0640,dir_mode=0750,vers=3,username=svc,password=$password\"
"
b64() { printf %s "$1" | base64 -w0; }
render_out="compose $(b64 "$fixture")
mount $smb 3 $(b64 nas) $smbv
mount $nfs 1 $(b64 nfs) $nfsv
mount $loc 1 $(b64 local) $locv
deleted $gone $(b64 'old share')"
mkdir -p "$work/fakebin-backup"
cat >"$work/fakebin-backup/docker" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
[[ -t 0 ]] || cat >/dev/null
case "$*" in
  *"admin backup-targets render"*)
    [[ "$FAKE_RENDER" != fail ]] || { echo "command failed error=\"a restore plan is running\"" >&2; exit 1; }
    printf '%s\n' "$FAKE_RENDER"
    ;;
  *"admin backup-targets revisions"*) echo "$FAKE_REVISIONS" ;;
  *"admin backup-targets purge"*) shift "$#" ;;
  *"backup resolve-local"*) exit "${FAKE_RESOLVE:-0}" ;;
  *"backup mark-mount"*)
    if [[ "$FAKE_MARK" == fail ]]; then
      echo "Error response from daemon: failed to mount local volume: mount //10.0.0.5/backup:/var/lib/docker/volumes/x/_data, data: vers=3,username=svc,password=********,,pass\$word: permission denied" >&2
      exit 1
    fi
    ;;
  *":/run/paddock-check/containers.json:ro "*)
    for a in "$@"; do [[ "$a" != *:/run/paddock-check/containers.json:ro ]] || cp "${a%%:*}" "$FAKE_DOCKER_LOG.containers"; done
    ;;
  "ps -q --filter label=com.docker.compose.project="*) [[ -z "${FAKE_PS_FAIL:-}" ]] || exit 1; printf '%s\n' $FAKE_CONTAINERS ;;
  "inspect "*) printf '[{"Name":"/%s"}]\n' "${*:2}" ;;
  "network ls"*) [[ -z "${FAKE_NETWORKS_FAIL:-}" ]] || exit 1; printf '%s\n' n1 n2 ;;
  "network inspect"*) printf '%s\n' paddock_edge=172.28.0.0/24 vpn=10.8.0.0/16,fd00::/64 ;;
  "volume ls"*) printf '%s\n' $FAKE_VOLUMES ;;
  "volume rm"*) [[ " $FAKE_IN_USE " != *" ${*: -1} "* ]] || exit 1 ;;
  # Compose folds a long plain scalar at its spaces onto more-indented continuation lines (PDK-733 review 3).
  *" config"*) printf '%s\n' '      o: uid=999,gid=999,file_mode=0640,dir_mode=0750,vers=3,username=svc,password=S3cr3t' \
    '        pass$word battery staple' ;;
esac
exit 0
FAKE
chmod +x "$work/fakebin-backup/docker"
export FAKE_DOCKER_LOG="$work/docker-backup.log"
# paddock_t <args…>: ./paddock in $work/t with the stand-in; output in $out, exit code in $rc.
paddock_t() {
  set +e
  out="$(cd "$work/t" && env -u SECRETS_DIR PATH="$work/fakebin-backup:$PATH" ./paddock "$@" 2>&1 </dev/null)"
  rc=$?
  set -e
}
leaks() { [[ "$out" == *S3cr3t* || "$out" == *'pass$word'* ]] || grep -q -e 'S3cr3t' -e 'pass\$word' "$FAKE_DOCKER_LOG"; }
: >"$FAKE_DOCKER_LOG"
FAKE_RENDER="$render_out" FAKE_VOLUMES="paddock_backup-target-$smb-r2-0123456789ab paddock_backup-target-$smb-r3-aaaaaaaaaaaa paddock_$smbv paddock_$locv paddock_backup-target-$gone-r5-0123456789ab paddock_postgres-data" \
  paddock_t backup-target apply
if [[ $rc == 0 ]] && cmp -s <(printf %s "$fixture") "$targets_file" && [[ "$(stat -c %a "$targets_file")" == 600 ]]; then
  pass "backup-target apply writes the rendered file unchanged with mode 0600"
else
  fail "backup-target apply: exit $rc, mode $(stat -c %a "$targets_file" 2>/dev/null), $out"
fi
grep -q "backup mark-mount $smb 3 $nfs 1 $loc 1" "$FAKE_DOCKER_LOG" && grep -q -- "-f $work/t/.compose.backup-targets.*\.yaml.* run --rm --no-deps -T paddock-backup backup mark-mount" "$FAKE_DOCKER_LOG" &&
  pass "apply writes every marker through the new file before it replaces the old one" || fail "mark-mount: $(cat "$FAKE_DOCKER_LOG")"
grep -q -- "--user 0:0 --network none --cap-drop ALL --read-only .* backup resolve-local --root /srv/paddock-backup -- /srv/paddock-backup/paddock-backup" "$FAKE_DOCKER_LOG" &&
  pass "apply resolves every local target below the root in a container without network and capabilities" ||
  fail "resolve-local: $(grep resolve-local "$FAKE_DOCKER_LOG")"
grep -q "admin backup-targets render --local-root /srv/paddock-backup" "$FAKE_DOCKER_LOG" &&
  ! grep "admin backup-targets render" "$FAKE_DOCKER_LOG" | grep -q -- "compose.backup-targets" &&
  pass "the render runs without the target volumes and with the local root" || fail "render: $(grep render "$FAKE_DOCKER_LOG")"
grep -qx "volume rm paddock_backup-target-$smb-r2-0123456789ab" "$FAKE_DOCKER_LOG" && grep -qx "volume rm paddock_backup-target-$gone-r5-0123456789ab" "$FAKE_DOCKER_LOG" &&
  ! grep -q "volume rm paddock_$smbv\|volume rm paddock_$locv\|volume rm paddock_postgres-data" "$FAKE_DOCKER_LOG" &&
  pass "apply removes the stale and deleted targets' volumes and keeps the current ones" || fail "volumes: $(grep volume "$FAKE_DOCKER_LOG")"
# PDK-733 review 1 (R1-M1): Docker keeps an existing volume's options, so a volume of the same revision whose mount
# changed (another local root, other default options) has another name and must go like an older revision's.
grep -qx "volume rm paddock_backup-target-$smb-r3-aaaaaaaaaaaa" "$FAKE_DOCKER_LOG" &&
  pass "apply removes a volume of the current revision whose mount changed" || fail "same-revision volume kept: $(grep volume "$FAKE_DOCKER_LOG")"
grep -q "admin backup-targets purge $gone" "$FAKE_DOCKER_LOG" && pass "apply removes the deleted target's row after its volume" ||
  fail "purge: $(cat "$FAKE_DOCKER_LOG")"
[[ "$out" == *"target: nas"* && "$out" == *"target: local"* && "$out" == *"next: ./paddock up"* ]] &&
  pass "apply names the targets and the next step" || fail "apply output: $out"
leaks && fail "a password reached the output or a command line" || pass "no SMB password in the output or on a command line"
first="$(cat "$targets_file")"
: >"$FAKE_DOCKER_LOG"
FAKE_RENDER="$render_out" FAKE_VOLUMES="paddock_$smbv paddock_backup-target-$gone-r5-0123456789ab" FAKE_IN_USE="paddock_backup-target-$gone-r5-0123456789ab" \
  paddock_t backup-target apply
[[ $rc == 0 && "$(cat "$targets_file")" == "$first" ]] && ! grep -q "purge" "$FAKE_DOCKER_LOG" &&
  [[ "$out" == *"run ./paddock backup-target apply again"*"paddock_backup-target-$gone-r5-0123456789ab"* ]] &&
  pass "apply again: same file; a volume still in use keeps its target's row and is named" || fail "apply again: exit $rc, $out"
: >"$FAKE_DOCKER_LOG"
FAKE_RENDER="$render_out" FAKE_MARK=fail paddock_t backup-target apply
[[ $rc == 1 && "$(cat "$targets_file")" == "$first" && "$out" == *"password=<redacted>"* && "$out" == *"nothing changed"* ]] &&
  [[ -z "$(find "$work/t" -maxdepth 1 -name '.compose.backup-targets.*')" ]] &&
  pass "a share that does not mount: exit 1, the old file stays, the mount error is redacted" || fail "mount failure: exit $rc, $out"
leaks && fail "a mount error leaked the password" || pass "no password in the mount error"
FAKE_RENDER="$render_out" FAKE_RESOLVE=1 paddock_t backup-target apply
[[ $rc == 1 && "$(cat "$targets_file")" == "$first" && "$out" == *"does not resolve below PADDOCK_BACKUP_LOCAL_ROOT"* ]] &&
  pass "a local target that does not resolve: exit 1, nothing changed" || fail "resolve failure: exit $rc, $out"
FAKE_RENDER=fail paddock_t backup-target apply
[[ $rc == 1 && "$(cat "$targets_file")" == "$first" && "$out" == *"could not be rendered"* ]] &&
  pass "a refused render (a restore plan running): exit 1, nothing changed" || fail "render failure: exit $rc, $out"
for bad in "mount $smb 3 $(b64 nas)" "mount $smb 3 $(b64 nas) backup-target-$nfs-r3-0123456789ab" "mount $smb 3 $(b64 nas) ../$smbv"; do
  FAKE_RENDER="compose $(b64 "$fixture")
$bad" paddock_t backup-target apply
  [[ $rc == 1 && "$(cat "$targets_file")" == "$first" && "$out" == *"unexpected render line"* ]] ||
    fail "a mount record without its own volume name is taken: '$bad': exit $rc, $out"
done
pass "a mount record without the target's own volume name is refused"
cp "$targets_file" "$work/targets.keep"
FAKE_RENDER="" paddock_t backup-target apply
[[ $rc == 0 && ! -e "$targets_file" && "$out" == *"no local, SMB or NFS target"* ]] &&
  pass "apply without a volume target removes the file" || fail "apply without targets: exit $rc, $out"
cp -p "$work/targets.keep" "$targets_file"
: >"$FAKE_DOCKER_LOG"
FAKE_RESOLVE=1 paddock_t up
[[ $rc == 1 && "$out" == *"no longer resolves"* ]] && ! grep -q " up -d" "$FAKE_DOCKER_LOG" &&
  pass "up refuses to start when a local target no longer resolves" || fail "up with a broken local target: exit $rc, $out"
# PDK-733 review 3 (R3-M1): a folded o: line defeats any line-based redaction, so with the targets file in the file
# set the configuration is not printed at all, and Compose is not even asked for it.
for args in "config" "--profile backup config --services" "convert"; do
  : >"$FAKE_DOCKER_LOG"
  # shellcheck disable=SC2086
  paddock_t compose $args
  [[ $rc == 1 && "$out" == *"refusing to print the configuration"* && "$out" != *"o:"* && "$out" != *battery* ]] &&
    ! leaks && ! grep -q " config\| convert" "$FAKE_DOCKER_LOG" ||
    fail "compose $args with the targets file: exit $rc, $out, docker: $(cat "$FAKE_DOCKER_LOG")"
done
pass "./paddock compose config refuses to print while the targets file is in the file set; nothing printed"
mv "$targets_file" "$work/targets.aside"
: >"$FAKE_DOCKER_LOG"
paddock_t compose config
[[ $rc == 0 && "$out" == *"o: uid=999"* ]] && grep -q " config$" "$FAKE_DOCKER_LOG" &&
  pass "./paddock compose config prints without the targets file" || fail "compose config without targets: exit $rc, $out"
mv "$work/targets.aside" "$targets_file"
: >"$FAKE_DOCKER_LOG"
paddock_t backup now --wait
grep -q "run --rm --no-deps -T paddock-backup backup now --wait" "$FAKE_DOCKER_LOG" &&
  ! grep "backup now" "$FAKE_DOCKER_LOG" | grep -q "compose.backup-targets" &&
  pass "backup now runs in a one-off paddock-backup without the target volumes" || fail "backup now: $(cat "$FAKE_DOCKER_LOG")"
: >"$FAKE_DOCKER_LOG"
FAKE_REVISIONS="$smb=4 $nfs=1 $loc=1" paddock_t check --online
grep -q -- "prod-check --host controlplane .* --online --backup-revisions-file $smb=3 $nfs=1 $loc=1 --backup-revisions-db $smb=4 $nfs=1 $loc=1" "$FAKE_DOCKER_LOG" &&
  ! grep "config --format json" "$FAKE_DOCKER_LOG" | grep -q "compose.backup-targets" &&
  ! grep -q -- "--network paddock_audit-store" "$FAKE_DOCKER_LOG" &&
  pass "check --online compares the file's revisions with the database's and leaves the targets file out" ||
  fail "check --online: $(grep -e prod-check -e 'config --format' "$FAKE_DOCKER_LOG")"
# decisions-alpha10 A10-1: the check container has no Docker socket, so ./paddock check hands it the host's networks.
grep -q -- "prod-check .* --docker-networks --docker-network paddock_edge=172.28.0.0/24 --docker-network vpn=10.8.0.0/16,fd00::/64 " \
  "$FAKE_DOCKER_LOG" && pass "check hands prod-check the host's Docker networks and their subnets" ||
  fail "check without the host's networks: $(grep prod-check "$FAKE_DOCKER_LOG")"
# Plan M12h decision 10: online, prod-check gets the project's running containers (docker inspect, as a mounted file)
# and the bundle's exceptions file; the file is removed afterwards.
: >"$FAKE_DOCKER_LOG"
rm -f "$FAKE_DOCKER_LOG.containers"
FAKE_CONTAINERS="c1 c2" FAKE_REVISIONS="$smb=4 $nfs=1 $loc=1" paddock_t check --online
mounted="$(grep -o -- "-v [^ ]*:/run/paddock-check/containers.json:ro" "$FAKE_DOCKER_LOG" | head -1 | sed 's/^-v //; s/:.*//')"
grep -q -- "^ps -q --filter label=com.docker.compose.project=paddock$" "$FAKE_DOCKER_LOG" &&
  grep -q -- "prod-check .* --online .* --containers /run/paddock-check/containers.json --hardening-exceptions $work/t/hardening-exceptions.yaml$" \
    "$FAKE_DOCKER_LOG" && [[ "$(cat "$FAKE_DOCKER_LOG.containers" 2>/dev/null)" == '[{"Name":"/c1 c2"}]' ]] &&
  [[ -n "$mounted" && ! -e "$mounted" ]] &&
  pass "check --online hands prod-check the inspected containers of the project and the exceptions file" ||
  fail "check --online without the containers: exit $rc, $out, docker: $(grep -e prod-check -e '^ps ' -e '^inspect' "$FAKE_DOCKER_LOG")"
: >"$FAKE_DOCKER_LOG"
FAKE_CONTAINERS="c1" FAKE_REVISIONS="$smb=4 $nfs=1 $loc=1" paddock_t check
! grep -q -- "--containers" "$FAKE_DOCKER_LOG" && ! grep -q "^ps -q" "$FAKE_DOCKER_LOG" &&
  pass "check without --online inspects no container" || fail "offline check inspected: $(cat "$FAKE_DOCKER_LOG")"
: >"$FAKE_DOCKER_LOG"
PADDOCK_CHECK_SKIP_CONTAINERS=1 FAKE_CONTAINERS="c1" FAKE_REVISIONS="$smb=4 $nfs=1 $loc=1" paddock_t check --online
[[ "$out" == *"WARN  containers: capabilities and security options match the matrix"*"not checked: the old release still runs"* ]] &&
  grep -q -- "prod-check .* --online " "$FAKE_DOCKER_LOG" && ! grep -q -- "--containers" "$FAKE_DOCKER_LOG" &&
  ! grep -q "^ps -q" "$FAKE_DOCKER_LOG" &&
  pass "check --online with PADDOCK_CHECK_SKIP_CONTAINERS (upgrade before up) inspects no container" ||
  fail "check --online with PADDOCK_CHECK_SKIP_CONTAINERS: exit $rc, $out, docker: $(grep -e prod-check -e '^ps ' "$FAKE_DOCKER_LOG")"
: >"$FAKE_DOCKER_LOG"
FAKE_PS_FAIL=1 FAKE_REVISIONS="$smb=4 $nfs=1 $loc=1" paddock_t check --online
[[ "$out" == *"WARN  containers: capabilities and security options match the matrix"*"not checked: listing the project's containers failed"* ]] &&
  grep -q -- "prod-check " "$FAKE_DOCKER_LOG" && ! grep -q -- "--containers" "$FAKE_DOCKER_LOG" &&
  pass "check --online reports the container matrix as not checked when listing the containers fails" ||
  fail "check --online with a failed container listing: exit $rc, $out, docker: $(grep prod-check "$FAKE_DOCKER_LOG")"
: >"$FAKE_DOCKER_LOG"
FAKE_NETWORKS_FAIL=1 paddock_t check
[[ "$out" == *"WARN  networks: edge subnet free on this host"*"not checked: listing the host's Docker networks failed"* ]] &&
  grep -q -- "prod-check " "$FAKE_DOCKER_LOG" && ! grep -q -- "--docker-networks" "$FAKE_DOCKER_LOG" &&
  pass "check reports the edge subnet as not checked when listing the host's networks fails" ||
  fail "check with a failed network listing: exit $rc, $out, docker: $(grep prod-check "$FAKE_DOCKER_LOG")"
# PDK-733 review 2 (R2-m1): bash writes a here-string above 64 KiB to a temp file (sh-thd.*), so a large render with the
# passwords must reach the loop and base64 through pipes. Without strace the backup-target branch is read instead.
big="$fixture# $(head -c 60000 /dev/zero | tr '\0' x)
"
big_render="compose $(b64 "$big")
mount $smb 3 $(b64 nas) $smbv"
if command -v strace >/dev/null && strace -f -qq -o /dev/null true 2>/dev/null; then
  set +e
  out="$(cd "$work/t" && FAKE_RENDER="$big_render" env -u SECRETS_DIR PATH="$work/fakebin-backup:$PATH" \
    strace -f -qq -e trace=openat,open,creat -o "$work/heredoc.trace" ./paddock backup-target apply 2>&1 </dev/null)"
  rc=$?
  set -e
  [[ $rc == 0 ]] && cmp -s <(printf %s "$big") "$targets_file" && ! grep -q 'sh-thd' "$work/heredoc.trace" &&
    pass "a render above 64 KiB never reaches a temp file" ||
    fail "large render: exit $rc, $(grep -c 'sh-thd' "$work/heredoc.trace") temp file(s), $out"
else
  sed -n '/^  backup-target)$/,/^    ;;$/p' "$bundle/paddock" | grep -q '<<<' &&
    fail "backup-target apply feeds the render through a here-string" ||
    pass "backup-target apply feeds the render through pipes (strace not available)"
fi

# ./paddock pull pulls only the images that are not present by their reference (decisions-alpha9 item 54).
mkdir -p "$work/fakebin-pull"
cat >"$work/fakebin-pull/docker" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
case "$*" in
  *" config --images") printf '%s\n' reg/a:1@sha256:aa reg/b:2@sha256:bb reg/a:1@sha256:aa ;;
  "image inspect reg/a:1@sha256:aa") exit 0 ;;
  "image inspect "*) exit 1 ;;
  "pull reg/b:2@sha256:bb") exit "${FAKE_PULL_EXIT:-0}" ;;
esac
exit 0
FAKE
chmod +x "$work/fakebin-pull/docker"
paddock_pull() {
  : >"$FAKE_DOCKER_LOG"
  set +e
  out="$(cd "$work/t" && env -u SECRETS_DIR PATH="$work/fakebin-pull:$PATH" ./paddock pull "$@" 2>&1 </dev/null)"
  rc=$?
  set -e
}
paddock_pull
if [[ $rc == 0 ]] && grep -qx 'pull reg/b:2@sha256:bb' "$FAKE_DOCKER_LOG" && ! grep -q '^pull reg/a' "$FAKE_DOCKER_LOG" &&
  [[ "$(grep -c '^image inspect reg/a' "$FAKE_DOCKER_LOG")" == 1 && "$out" == *"present: reg/a:1@sha256:aa"* ]]; then
  pass "pull skips an image present by its reference and pulls the missing one, each image once"
else
  fail "pull: exit $rc, $out, $(cat "$FAKE_DOCKER_LOG")"
fi
FAKE_PULL_EXIT=1 paddock_pull
[[ $rc != 0 && "$out" == *"pulling reg/b:2@sha256:bb failed"* ]] && pass "pull fails when a missing image cannot be pulled" ||
  fail "failed pull: exit $rc, $out"
paddock_pull paddock-api
grep -q -- "--profile \* pull paddock-api$" "$FAKE_DOCKER_LOG" && ! grep -q '^image inspect' "$FAKE_DOCKER_LOG" &&
  pass "pull <service> pulls the named service through Compose as before" || fail "pull paddock-api: $(cat "$FAKE_DOCKER_LOG")"
unset FAKE_DOCKER_LOG
if ((failures > 0)); then
  echo "bundle: $failures check(s) failed" >&2
  exit 1
fi
echo "bundle: all checks passed"
