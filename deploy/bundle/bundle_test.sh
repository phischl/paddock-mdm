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

# build <bundle sources> <out dir>: a local bundle of version 0.0.0-test.
build() { "$1/build.sh" --version 0.0.0-test --channel local --images local --out "$2" >/dev/null; }
lib_files() { sed -n "s/^$2=\"\\(.*\\)\"\$/\\1/p" "$1/scripts/lib.sh"; }

# render <compose dir> <settings file> <host>: the production configuration of host, normalized: the project
# directory as <dir>, the three Paddock images as <image>.
render() {
  local dir="$1" settings="$2" host="$3" f args=()
  for f in $(lib_files "$compose_src" "PROD_FILES_$host"); do args+=(-f "$dir/$f"); done
  docker compose --project-directory "$dir" -p paddock-bundle-test --env-file "$dir/versions.env" \
    --env-file "$dir/$settings" "${args[@]}" --profile '*' config |
    sed -E -e "s#$dir#<dir>#g" -e 's#(image: ).*paddock-(server|compiler|pgbackrest)[^ ]*$#\1<image>#'
}

# check_mounts <bundle dir>: every bind-mount source of both configurations exists inside the bundle; prints the
# missing paths relative to the bundle.
check_mounts() {
  local dir="$1" host src missing=0 f args
  for host in controlplane audit; do
    args=()
    for f in $(lib_files "$dir" "PROD_FILES_$host"); do args+=(-f "$dir/$f"); done
    while read -r src; do
      [[ "$src" == "$dir"/.secrets/* ]] && continue
      if [[ "$src" != "$dir"/* || ! -e "$src" ]]; then
        echo "missing bind-mount source: ${src#"$dir"/}"
        missing=1
      fi
    done < <(docker compose --project-directory "$dir" -p paddock-bundle-test --env-file "$dir/versions.env" \
      --env-file "$dir/.env.example" "${args[@]}" --profile '*' config |
      sed -n -E 's#^[[:space:]]+source: (/.*)$#\1#p')
  done
  return "$missing"
}

build "$here" "$work/a"
bundle="$work/a/paddock-deploy-0.0.0-test"

# (a) Same configuration as the repository.
for host in controlplane audit; do
  render "$compose_src" prod.env.example "$host" >"$work/repo.yaml"
  render "$bundle" .env.example "$host" >"$work/bundle.yaml"
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

if ((failures > 0)); then
  echo "bundle: $failures check(s) failed" >&2
  exit 1
fi
echo "bundle: all checks passed"
