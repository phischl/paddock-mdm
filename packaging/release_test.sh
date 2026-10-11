#!/usr/bin/env bash
# Tests of the release version rules in the Makefile (`make test`): which versions release-check accepts, that every
# release image is tagged with exactly the release version (never latest), and how a version maps to the Debian
# version of the packages (a pre-release sorts before its release), and that the release assets are named with the
# release version and only characters GitHub keeps.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failures=0

check() {
  if [[ "$2" == "$3" ]]; then
    echo "ok   $1"
  else
    echo "FAIL $1: got '$2', want '$3'"
    failures=$((failures + 1))
  fi
}

# value <variable> <make arguments>...: the value of a Makefile variable.
value() {
  local var="$1"
  shift
  make -s -C "$root" --no-print-directory --eval "print-value: ; @echo \$($var)" print-value "$@"
}

for v in 0.1.0 1.20.3 0.1.0-alpha.1 0.1.0-alpha.12 0.1.0-beta.1 0.1.0-rc.1 0.1.0-rc.0; do
  if make -s -C "$root" --no-print-directory release-check RELEASE_VERSION="$v" >/dev/null 2>&1; then got=0; else got=1; fi
  check "release-check accepts $v" "$got" 0
done
for v in "" 0.1 v0.1.0 0.1.0-foo 0.1.0-alpha 0.1.0-alpha.01 0.1.0-alpha.1.2 0.1.0-ALPHA.1 0.1.0-dev 0.1.0+build.1 \
  0.1.0-rc.1+build.1 01.0.0 "0.1.0 " 0.1.0-alpha.-1; do
  if make -s -C "$root" --no-print-directory release-check RELEASE_VERSION="$v" >/dev/null 2>&1; then got=0; else got=1; fi
  check "release-check rejects '$v'" "$got" 1
done

for v in 0.1.0 0.1.0-alpha.1; do
  check "images of $v" "$(value RELEASE_IMAGES RELEASE_VERSION="$v")" \
    "server=ghcr.io/phischl/paddock-server:$v compiler=ghcr.io/phischl/paddock-compiler:$v pgbackrest=ghcr.io/phischl/paddock-pgbackrest:$v"
done

# Tags (plan M7b decisions 4-5): a pre-release only its version; a plain x.y.z also <major>.<minor> and latest only as
# the highest plain x.y.z among the v* tags; an edge build its version and edge, never latest.
tags() { value RELEASE_TAGS RELEASE_GIT_TAGS="v0.1.0-alpha.1 v1.1.0 v1.0.0 v1.2.0-rc.1" "$@" | xargs; }
check "tags of a new highest stable 1.1.1" "$(tags RELEASE_VERSION=1.1.1)" "1.1.1 1.1 latest"
check "tags of the tagged highest stable 1.1.0" "$(tags RELEASE_VERSION=1.1.0)" "1.1.0 1.1 latest"
check "tags of the older stable 1.0.1" "$(tags RELEASE_VERSION=1.0.1)" "1.0.1 1.0"
check "tags of the pre-release 1.2.0-rc.1" "$(tags RELEASE_VERSION=1.2.0-rc.1)" "1.2.0-rc.1"
check "tags of the pre-release 9.0.0-alpha.1" "$(tags RELEASE_VERSION=9.0.0-alpha.1)" "9.0.0-alpha.1"
check "tags of an edge build" "$(tags RELEASE_VERSION=edge-20261010-abcdef0 RELEASE_CHANNEL=edge)" \
  "edge-20261010-abcdef0 edge"

if make -s -C "$root" --no-print-directory release-check RELEASE_VERSION=edge-20261010-abcdef0 RELEASE_CHANNEL=edge \
  >/dev/null 2>&1; then got=0; else got=1; fi
check "release-check accepts the edge version edge-20261010-abcdef0" "$got" 0
for v in 0.1.0 edge-2026101-abcdef0 edge-20261010-ABCDEF0 edge-20261010-abcdef01 edge; do
  if make -s -C "$root" --no-print-directory release-check RELEASE_VERSION="$v" RELEASE_CHANNEL=edge >/dev/null 2>&1; then
    got=0
  else got=1; fi
  check "release-check rejects the edge version '$v'" "$got" 1
done
if make -s -C "$root" --no-print-directory release-check RELEASE_VERSION=edge-20261010-abcdef0 >/dev/null 2>&1; then
  got=0
else got=1; fi
check "release-check rejects an edge version on the stable channel" "$got" 1

# The printed buildx commands: three multi-platform images, every label of decision 6, never latest for a pre-release.
dry_dir="$(mktemp -d)"
recipe="$(make -s -C "$root" --no-print-directory release-images RELEASE_VERSION=0.1.0-alpha.1 DRY_RUN=1 \
  RELEASE_DIR="$dry_dir")"
check "release-images builds three images" \
  "$(grep -c 'docker buildx build --platform linux/amd64,linux/arm64 --push' <<<"$recipe")" 3
if grep -q latest <<<"$recipe"; then got=1; else got=0; fi
check "release-images never tags a pre-release latest" "$got" 0
for label in source url documentation title description version revision created licenses vendor; do
  check "label org.opencontainers.image.$label on every image" \
    "$(grep -c "org.opencontainers.image.$label=" <<<"$recipe")" 3
done
check "label io.paddock.channel on every image" "$(grep -c 'io.paddock.channel=stable' <<<"$recipe")" 3

# The printed cosign commands: every index recursively, one attestation per image and platform, both blobs.
echo sums >"$dry_dir/SHA256SUMS"
signing="$(make -s -C "$root" --no-print-directory release-sign RELEASE_VERSION=0.1.0 DRY_RUN=1 RELEASE_DIR="$dry_dir")"
check "release-sign signs three indexes recursively" "$(grep -c 'sign --yes --recursive' <<<"$signing")" 3
check "release-sign attests six platform manifests" "$(grep -c 'attest --yes --type spdxjson' <<<"$signing")" 6
check "release-sign signs SHA256SUMS" \
  "$(grep -c 'sign-blob --yes --bundle /work/SHA256SUMS.sigstore.json /work/SHA256SUMS' <<<"$signing")" 1
check "release-sign signs the bundle" \
  "$(grep -c 'sign-blob --yes --bundle /work/paddock-deploy-0.1.0.tar.gz.sigstore.json' <<<"$signing")" 1
rm -rf "$dry_dir"

sequence=(0.1.0-alpha.1 0.1.0-alpha.2 0.1.0-beta.1 0.1.0-rc.1 0.1.0)
debian=(0.1.0~alpha.1 0.1.0~alpha.2 0.1.0~beta.1 0.1.0~rc.1 0.1.0)
for i in "${!sequence[@]}"; do
  check "Debian version of ${sequence[$i]}" "$(value DEB_VERSION VERSION="${sequence[$i]}")" "${debian[$i]}"
done
check "Debian version of the development build" "$(value DEB_VERSION VERSION=0.0.0-dev)" "0.0.0~dev"
if command -v dpkg >/dev/null; then
  for ((i = 0; i + 1 < ${#debian[@]}; i++)); do
    if dpkg --compare-versions "${debian[$i]}" lt "${debian[$((i + 1))]}"; then got=0; else got=1; fi
    check "dpkg orders ${debian[$i]} before ${debian[$((i + 1))]}" "$got" 0
  done
else
  echo "skip Debian ordering: dpkg is not installed"
fi

# Release assets: GitHub renames names with characters outside [A-Za-z0-9._+-] (such as ~), which would no longer
# match SHA256SUMS, so the packages are published under the release version.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/deb" "$work/out"
for pkg in paddock-agent paddock-supervisor paddock-revoke; do : >"$work/deb/${pkg}_0.1.0~alpha.1_amd64.deb"; done
make -s -C "$root" --no-print-directory release-debs RELEASE_VERSION=0.1.0-alpha.1 RELEASE_DEB_DIR="$work/deb" \
  RELEASE_DIR="$work/out"
check "release package names" "$(ls "$work/out" | LC_ALL=C sort | tr '\n' ' ')" \
  "paddock-agent_0.1.0-alpha.1_amd64-unsigned.deb paddock-revoke_0.1.0-alpha.1_amd64-unsigned.deb paddock-supervisor_0.1.0-alpha.1_amd64-unsigned.deb "
if ls "$work/out" | grep -qv '^[A-Za-z0-9._+-]*$'; then got=1; else got=0; fi
check "release file names keep to [A-Za-z0-9._+-]" "$got" 0
if make -s -C "$root" --no-print-directory release-names-check RELEASE_DIR="$work/out" >/dev/null 2>&1; then got=0; else got=1; fi
check "release-names-check accepts the release files" "$got" 0
: >"$work/out/paddock-agent_0.1.0~alpha.1_amd64-unsigned.deb"
if make -s -C "$root" --no-print-directory release-names-check RELEASE_DIR="$work/out" >/dev/null 2>&1; then got=0; else got=1; fi
check "release-names-check rejects a ~ in a file name" "$got" 1

if ((failures > 0)); then
  echo "$failures failure(s)"
  exit 1
fi
