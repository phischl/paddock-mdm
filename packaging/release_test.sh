#!/usr/bin/env bash
# Tests of the release version rules in the Makefile (`make test`): which versions release-check accepts, that every
# release image is tagged with exactly the release version (never latest), and how a version maps to the Debian
# version of the packages (a pre-release sorts before its release).
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
  check "image tags of $v" "$(value RELEASE_IMAGES RELEASE_VERSION="$v")" \
    "server=ghcr.io/phischl/paddock-server:$v compiler=ghcr.io/phischl/paddock-compiler:$v"
  recipe="$(make -n -C "$root" --no-print-directory release-images RELEASE_VERSION="$v" PUSH=1)"
  if grep -qF "paddock-server:$v" <<<"$recipe" && ! grep -q latest <<<"$recipe"; then got=0; else got=1; fi
  check "release-images of $v builds and pushes $v, never latest" "$got" 0
done

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

if ((failures > 0)); then
  echo "$failures failure(s)"
  exit 1
fi
