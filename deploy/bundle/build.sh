#!/usr/bin/env bash
# Builds the operator bundle paddock-deploy-<version> (plan M7b decisions 11–13, 21, ADR 0022): a copy of the production
# subset of deploy/compose/ plus the files of deploy/bundle/, never a transformation of the Compose files.
#   build.sh --version <v> --channel stable|edge|local --images <images.txt | local> --out <dir>
# Writes <dir>/paddock-deploy-<v>/ and the reproducible tarball <dir>/paddock-deploy-<v>.tar.gz, after checking that
# the production and lab configurations render and carry no build section. Exit 1: validation failed; exit 2: usage.
# Environment: SOURCE_DATE_EPOCH (default: the commit's author time), GIT_COMMIT (default: HEAD); for --images local
# LOCAL_SERVER_IMAGE, LOCAL_COMPILER_IMAGE, LOCAL_PGBACKREST_IMAGE (default paddock-{server,compiler,pgbackrest}:dev).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$(cd "$here/../compose" && pwd)"
registry=ghcr.io/phischl
repo_url=https://github.com/phischl/paddock-mdm

usage() {
  echo "usage: build.sh --version <v> --channel stable|edge|local --images <images.txt|local> --out <dir>" >&2
  exit 2
}
fail() {
  echo "build.sh: $*" >&2
  exit 1
}

version= channel= images= out=
while (($#)); do
  case "$1" in
    --version) version="${2:-}"; shift 2 || usage ;;
    --channel) channel="${2:-}"; shift 2 || usage ;;
    --images) images="${2:-}"; shift 2 || usage ;;
    --out) out="${2:-}"; shift 2 || usage ;;
    *) usage ;;
  esac
done
[[ "$version" =~ ^[0-9A-Za-z][0-9A-Za-z.+-]*$ ]] || usage
[[ "$channel" == stable || "$channel" == edge || "$channel" == local ]] || usage
[[ -n "$images" && -n "$out" ]] || usage
[[ "$images" == local || -f "$images" ]] || usage

commit="${GIT_COMMIT:-$(git -C "$here" rev-parse HEAD)}"
epoch="${SOURCE_DATE_EPOCH:-$(git -C "$here" log -1 --format=%at)}"
built="$(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ)"

# image <key> prints the reference of one Paddock image: tag and index digest from images.txt, or the local tag.
image() {
  local key="$1" ref
  if [[ "$images" == local ]]; then
    case "$key" in
      server) printf '%s' "${LOCAL_SERVER_IMAGE:-paddock-server:dev}" ;;
      compiler) printf '%s' "${LOCAL_COMPILER_IMAGE:-paddock-compiler:dev}" ;;
      pgbackrest) printf '%s' "${LOCAL_PGBACKREST_IMAGE:-paddock-pgbackrest:dev}" ;;
    esac
    return
  fi
  ref="$(sed -n "s/^$key=//p" "$images" | tail -1)"
  [[ "$ref" == *@sha256:* ]] || fail "$images: no $key=<image>:<tag>@sha256:<digest> line"
  printf '%s' "$ref"
}

name="paddock-deploy-$version"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
dir="$out/$name"
rm -rf "$dir" "$dir.tar.gz"
mkdir -p "$dir"

# The production subset of deploy/compose/ (decision 11). Development files, image sources, tests and the
# development-only scripts stay out.
shipped=(
  compose.yaml compose.prod.yaml compose.backup.yaml compose.audit.yaml compose.audit.prod.yaml compose.lab.yaml
  caddy/Caddyfile.prod caddy/Caddyfile.lab caddy/guards.caddy caddy/entrypoint.sh
  openbao/config.hcl openbao/prod.hcl
  rabbitmq/rabbitmq.conf rabbitmq/enabled_plugins rabbitmq/tls.conf rabbitmq/definitions.json.tmpl
  valkey/valkey.conf
  postgres/init/10-roles.sh audit-postgres/init/10-roles.sh
  authentik/entrypoint.sh
  fleet/entrypoint.sh fleet/backup.sh fleet/backup-upload.sh
  prometheus/prometheus.yml prometheus/alerts.yml prometheus/scrape/controlplane.yml prometheus/scrape/audit.yml
  scripts/lib.sh scripts/gen-prod-secrets.sh scripts/openbao-configure.sh scripts/rustfs-bundles-bootstrap.sh
  scripts/rustfs-audit-bootstrap.sh scripts/fleet-bootstrap.sh scripts/wait-healthy.sh
)
for f in "$src"/authentik/blueprints/*.yaml; do shipped+=("authentik/blueprints/$(basename "$f")"); done

# copy <source> <target>: the content with a normalized mode (0755 for executables, else 0644), so that the tarball
# does not depend on the umask of the checkout.
copy() {
  mkdir -p "$(dirname "$2")"
  cp "$1" "$2"
  if [[ -x "$1" ]]; then chmod 0755 "$2"; else chmod 0644 "$2"; fi
}
for f in "${shipped[@]}"; do
  [[ -f "$src/$f" ]] || fail "missing deploy/compose/$f"
  copy "$src/$f" "$dir/$f"
done
copy "$here/paddock" "$dir/paddock"
chmod 0755 "$dir/paddock"
copy "$src/prod.env.example" "$dir/.env.example"
copy "$src/lab.env.example" "$dir/.env.lab.example"

# versions.env: the third-party images of the stack (everything above the build and tooling images) and the three
# Paddock images of this version (decision 12).
grep -q '^# Build and tooling images$' "$src/versions.env" || fail "deploy/compose/versions.env: no '# Build and tooling images' line"
{
  sed '/^# Build and tooling images$/,$d' "$src/versions.env"
  printf '# Paddock images of %s (channel %s, commit %s)\n' "$version" "$channel" "$commit"
  printf 'PADDOCK_IMAGE=%s\n' "$(image server)"
  printf 'PADDOCK_COMPILER_IMAGE=%s\n' "$(image compiler)"
  printf 'PADDOCK_PGBACKREST_IMAGE=%s\n' "$(image pgbackrest)"
} >"$dir/versions.env"
chmod 0644 "$dir/versions.env"

printf 'version=%s\nchannel=%s\ncommit=%s\nbuilt=%s\n' "$version" "$channel" "$commit" "$built" >"$dir/VERSION"
chmod 0644 "$dir/VERSION"

# README: the version, the documentation of the same source, the signing identity of the channel and the cosign image
# are filled in.
cosign_image="$(sed -n 's/^COSIGN_IMAGE=//p' "$src/versions.env")"
case "$channel" in
  stable)
    docs_ref="v$version"
    identity="^$repo_url/\\.github/workflows/release\\.yml@refs/tags/v"
    notice=""
    ;;
  *)
    docs_ref="$commit"
    identity="^$repo_url/\\.github/workflows/ci\\.yml@refs/heads/main\$"
    notice="> **Channel $channel: unsupported, never for production.** This bundle was built from commit \`$commit\`. Use a
> stable release (\`paddock-deploy-<x.y.z>.tar.gz\` of a GitHub release) for any installation you depend on."
    ;;
esac
readme="$(<"$here/README.md")"
readme="${readme//@VERSION@/$version}"
readme="${readme//@DOCS_REF@/$docs_ref}"
readme="${readme//@IDENTITY@/$identity}"
readme="${readme//@COSIGN_IMAGE@/$cosign_image}"
readme="${readme//@REGISTRY@/$registry}"
readme="${readme//@CHANNEL_NOTICE@/$notice}"
printf '%s\n' "$readme" >"$dir/README.md"
chmod 0644 "$dir/README.md"

# Validation (decision 21): no shipped Compose file has a build section, and the configurations of the three hosts
# render; the lab's with its own settings and the backup file (plan M8a decision 9).
for f in "$dir"/compose*.yaml; do
  if grep -qE '^[[:space:]]*build:' "$f"; then fail "$(basename "$f") contains a build section"; fi
done
lib_files() { sed -n "s/^$1=\"\\(.*\\)\"\$/\\1/p" "$dir/scripts/lib.sh"; }
for host in controlplane audit lab; do
  files="$(lib_files "PROD_FILES_$host")"
  [[ -n "$files" ]] || fail "scripts/lib.sh: no PROD_FILES_$host"
  settings=.env.example
  if [[ "$host" == lab ]]; then
    settings=.env.lab.example
    files+=" $(lib_files LAB_BACKUP_FILES)"
  fi
  args=()
  for f in $files; do args+=(-f "$dir/$f"); done
  if ! rendered="$(env -u PADDOCK_IMAGE -u PADDOCK_COMPILER_IMAGE -u PADDOCK_PGBACKREST_IMAGE \
    PADDOCK_BACKUP_S3_ENDPOINT=https://backup-s3.example.org \
    docker compose --project-directory "$dir" -p paddock-bundle-check --env-file "$dir/versions.env" \
    --env-file "$dir/$settings" "${args[@]}" --profile '*' config 2>&1)"; then
    printf '%s\n' "$rendered" >&2
    fail "the $host configuration ($files) does not render"
  fi
  if grep -qE '^[[:space:]]*build:' <<<"$rendered"; then fail "the $host configuration ($files) has a build section"; fi
done

(cd "$dir" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs sha256sum >SHA256SUMS)
chmod 0644 "$dir/SHA256SUMS"
find "$dir" -type d -exec chmod 0755 {} +

# gzip -n: no name and no time stamp in the gzip header, so that two builds of one commit are byte-identical.
tar -C "$out" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" -cf - "$name" | gzip -9 -n >"$dir.tar.gz"
echo "$dir.tar.gz"
