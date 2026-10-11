#!/usr/bin/env bash
# Edge retention of the published images (plan M7b decision 9, §6.7; workflow ghcr-prune.yml): deletes the package
# versions on ghcr.io whose tags are all edge-<yyyymmdd>-<sha7> and which are older than --older-than-days. Keeps
# every version with any other tag (edge, latest, a release, a cosign sha256-… tag) and every untagged version.
#   prune-edge.sh [--dry-run] [--older-than-days N] [--now <RFC 3339>] [--versions-json <file>] [--api-base <path>]
#                 <package>...
# One line per version: "<package> <id> <created_at> <tags> delete|keep <reason>". Exit 0: done; 1: an API call failed
# (the first failure stops the run); 2: usage. Needs bash, jq and, without --versions-json, gh with GH_TOKEN.
set -euo pipefail

usage() {
  echo "usage: prune-edge.sh [--dry-run] [--older-than-days N] [--now <RFC 3339>] [--versions-json <file>] [--api-base <path>] <package>..." >&2
  exit 2
}

dry_run= days=30 now= versions_json= api_base=/user
packages=()
while (($#)); do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    --older-than-days) days="${2:-}"; shift 2 || usage ;;
    --now) now="${2:-}"; shift 2 || usage ;;
    --versions-json) versions_json="${2:-}"; shift 2 || usage ;;
    --api-base) api_base="${2:-}"; shift 2 || usage ;;
    -*) usage ;;
    *) packages+=("$1"); shift ;;
  esac
done
((${#packages[@]} > 0)) || usage
[[ "$days" =~ ^[0-9]+$ ]] || usage
[[ -z "$versions_json" || -f "$versions_json" ]] || usage
for p in "${packages[@]}"; do
  case "$p" in paddock-server | paddock-compiler | paddock-pgbackrest) ;; *) usage ;; esac
done
command -v jq >/dev/null || { echo "prune-edge.sh: jq is required" >&2; exit 1; }
if [[ -n "$now" ]]; then
  now_epoch="$(date -u -d "$now" +%s)" || usage
else
  now_epoch="$(date -u +%s)"
fi
cutoff=$((now_epoch - days * 86400))

for package in "${packages[@]}"; do
  if [[ -n "$versions_json" ]]; then
    versions="$(jq -c '.' "$versions_json")"
  elif ! versions="$(gh api --paginate "$api_base/packages/container/$package/versions" | jq -sc 'add')"; then
    echo "prune-edge.sh: listing the versions of $package failed" >&2
    exit 1
  fi
  # Keep rules first: any tag that is not an edge-<date>-<sha7> keeps the version, so a release, edge, latest and the
  # cosign tags are never deleted.
  decisions="$(jq -r --argjson cutoff "$cutoff" '
    .[] | (.metadata.container.tags // []) as $tags
    | (if ($tags | length) == 0 then ["keep", "untagged"]
       elif any($tags[]; test("^edge-[0-9]{8}-[0-9a-f]{7}$") | not) then ["keep", "tagged"]
       elif (.created_at | fromdateiso8601) >= $cutoff then ["keep", "recent"]
       else ["delete", "expired"] end) as $d
    | [(.id | tostring), .created_at, (if ($tags | length) == 0 then "-" else ($tags | join(",")) end), $d[0], $d[1]]
    | join(" ")' <<<"$versions")"
  while read -r id created tags decision reason; do
    [[ -n "$id" ]] || continue
    echo "$package $id $created $tags $decision $reason"
    if [[ "$decision" == delete && -z "$dry_run" ]]; then
      gh api -X DELETE "$api_base/packages/container/$package/versions/$id" >/dev/null ||
        { echo "prune-edge.sh: deleting $package version $id ($tags) failed" >&2; exit 1; }
    fi
  done <<<"$decisions"
done
