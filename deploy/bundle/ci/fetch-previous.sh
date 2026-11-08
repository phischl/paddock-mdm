#!/usr/bin/env bash
# The previous release of the upgrade job (plan M16 decision 11): the newest v* tag below the candidate, its operator
# bundle verified with cosign as docs/operations/install.md §3 does, and its amd64 agent artifacts.
#   fetch-previous.sh <out dir> [<candidate tag>]
# Without a candidate tag (a pull request, main) the previous release is the newest v* tag. Prints the previous tag on
# the last line of stdout. Needs git with the tags, gh (GH_TOKEN) and docker; the cosign image is COSIGN_IMAGE of
# deploy/compose/versions.env. Exit 0: downloaded and verified; 1: no previous tag, a download or the verification
# failed; 2: usage.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"

# previous_tag <candidate tag|""> < tags newest first: the tag after the candidate, or the first one without it.
previous_tag() {
  local candidate="$1" tag seen=""
  while IFS= read -r tag; do
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]] || continue
    if [[ -z "$candidate" || -n "$seen" ]]; then
      printf '%s\n' "$tag"
      return 0
    fi
    [[ "$tag" != "$candidate" ]] || seen=1
  done
  return 1
}

# The test sources this file for previous_tag only.
[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0

out="${1:-}"
candidate="${2:-}"
[[ -n "$out" && $# -le 2 ]] || {
  echo "usage: fetch-previous.sh <out dir> [<candidate tag>]" >&2
  exit 2
}
# versionsort.suffix=- orders x.y.z-alpha.N before x.y.z, as semantic versions do.
prev="$(git -C "$repo" -c versionsort.suffix=- tag -l 'v*' --sort=-v:refname | previous_tag "$candidate")" ||
  { echo "fetch-previous: no v* tag below ${candidate:-the tree}" >&2; exit 1; }
v="${prev#v}"
mkdir -p "$out"
echo "previous release: $prev"
gh release download "$prev" --repo "${GITHUB_REPOSITORY:-phischl/paddock-mdm}" --dir "$out" --clobber \
  --pattern "paddock-deploy-$v.tar.gz" --pattern "paddock-deploy-$v.tar.gz.sigstore.json" \
  --pattern "paddockd_${v}_linux_amd64" --pattern '*_amd64.deb' --pattern '*_amd64-unsigned.deb'
cosign_image="$(sed -n 's/^COSIGN_IMAGE=//p' "$repo/deploy/compose/versions.env")"
[[ -n "$cosign_image" ]] || { echo "fetch-previous: no COSIGN_IMAGE in versions.env" >&2; exit 1; }
docker run --rm -v "$(cd "$out" && pwd):/w:ro" -w /w "$cosign_image" verify-blob "paddock-deploy-$v.tar.gz" \
  --bundle "paddock-deploy-$v.tar.gz.sigstore.json" \
  --certificate-identity-regexp '^https://github.com/phischl/paddock-mdm/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
echo "$prev"
