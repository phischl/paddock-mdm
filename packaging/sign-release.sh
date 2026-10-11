#!/usr/bin/env bash
# Signs the agent release files with the agent release key (ADR 0006, amendment 2026-10-11; sign job of
# .github/workflows/release.yml): paddockd for amd64 and arm64 and every paddock-agent and paddock-supervisor package
# of <in>, each with the trusted comment "paddock-agent version=<version> arch=<arch>". Writes each file under its
# final name (without -unsigned) and its .minisig to <out>, and verifies every signature and trusted comment against
# the public key. paddock-revoke is never signed here: the revocation release key stays offline (two holders).
#   sign-release.sh --version <version> --in <dir> --out <dir> --key <secret key> --public-key <public key>
#                   [--minisign <path>]
# The passphrase of the secret key comes from the environment variable PADDOCK_RELEASE_KEY_PASSPHRASE and reaches
# minisign on stdin, never on a command line. Exit 0: all signed and verified; 1: signing or verification failed;
# 2: usage or missing input.
set -euo pipefail

usage() {
  echo "usage: sign-release.sh --version <version> --in <dir> --out <dir> --key <secret key> --public-key <public key> [--minisign <path>]" >&2
  exit 2
}

version='' in='' out='' key='' pub='' minisign=minisign
while (($#)); do
  case "$1" in
    --version) version="${2:-}"; shift 2 || usage ;;
    --in) in="${2:-}"; shift 2 || usage ;;
    --out) out="${2:-}"; shift 2 || usage ;;
    --key) key="${2:-}"; shift 2 || usage ;;
    --public-key) pub="${2:-}"; shift 2 || usage ;;
    --minisign) minisign="${2:-}"; shift 2 || usage ;;
    *) usage ;;
  esac
done
[[ -n "$version" && -d "$in" && -n "$out" && -s "$key" && -s "$pub" ]] || usage
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]] || {
  echo "not a release version: $version" >&2
  exit 2
}
[[ -n "${PADDOCK_RELEASE_KEY_PASSPHRASE:-}" ]] || {
  echo "PADDOCK_RELEASE_KEY_PASSPHRASE is not set" >&2
  exit 2
}
command -v "$minisign" >/dev/null || {
  echo "minisign not found: $minisign" >&2
  exit 2
}
mkdir -p "$out"

# sign <unsigned file name> <final file name> <arch>
sign() {
  local src="$in/$1" dst="$out/$2" comment="paddock-agent version=$version arch=$3" got
  [[ -f "$src" ]] || {
    echo "missing $src" >&2
    exit 2
  }
  cp "$src" "$dst"
  # printf is a shell builtin: the passphrase is written to the pipe without appearing in any process's argv.
  if ! printf '%s\n' "$PADDOCK_RELEASE_KEY_PASSPHRASE" |
    "$minisign" -S -s "$key" -m "$dst" -x "$dst.minisig" -t "$comment" >/dev/null; then
    echo "signing $2 failed" >&2
    exit 1
  fi
  got="$("$minisign" -V -p "$pub" -m "$dst" -x "$dst.minisig" -Q </dev/null)" || {
    echo "$2: the signature does not verify with $pub" >&2
    exit 1
  }
  # aead.dev/minisign prints "Trusted comment: <comment>" with -Q, the C minisign only the comment.
  got="${got#Trusted comment: }"
  [[ "$got" == "$comment" ]] || {
    echo "$2: trusted comment '$got', want '$comment'" >&2
    exit 1
  }
  echo "signed $2 ($comment)"
}

for arch in amd64 arm64; do
  sign "paddockd_${version}_linux_${arch}-unsigned" "paddockd_${version}_linux_${arch}" "$arch"
done
for pkg in paddock-agent paddock-supervisor; do
  found=0
  for deb in "$in/${pkg}_${version}_"*-unsigned.deb; do
    [[ -f "$deb" ]] || continue
    name="$(basename "$deb" -unsigned.deb)"
    sign "$name-unsigned.deb" "$name.deb" "${name##*_}"
    found=1
  done
  ((found)) || {
    echo "no $pkg package of $version in $in" >&2
    exit 2
  }
done
