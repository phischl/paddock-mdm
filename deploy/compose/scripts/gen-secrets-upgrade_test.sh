#!/usr/bin/env bash
# Regression test (`make test`, plan M17 amendment k point 3, PDK-1054): on an installation that predates the
# organization deletion's credentials, the secret generators (./paddock secrets in ./paddock upgrade, make dev-secrets)
# create the four missing files with the usual mode and leave every existing file byte for byte as it was, the
# escrow's and the root credentials above all; a further run changes nothing. Only file names are printed, never a
# value.
set -euo pipefail

src="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
check() {
  if "${@:2}"; then echo "ok   $1"; else
    echo "FAIL $1"
    failures=$((failures + 1))
  fi
}
offboard=(rustfs_bundles_offboard_access_key rustfs_bundles_offboard_secret_key rustfs_escrow_offboard_access_key
  rustfs_escrow_offboard_secret_key)

# sums <secrets dir>: checksum and mode of every file, by path; values never leave this function's output file.
sums() { (cd "$1" && find . -type f -print0 | sort -z | xargs -0 -r stat -c '%a %n' | while read -r mode f; do
  printf '%s %s %s\n' "$mode" "$(sha256sum <"$f" | cut -d' ' -f1)" "$f"
done); }

# scenario <name> <compose dir> <generator command…>: generator runs on a fresh directory, the four files are removed
# (an installation of an earlier release), and two more runs follow.
scenario() {
  local name="$1" dir="$2" out f leaked=""
  shift 2
  "$@" >/dev/null 2>&1 || {
    echo "FAIL $name: the first run failed"
    failures=$((failures + 1))
    return
  }
  # One more pre-existing value the generator would never write: an operator-set escrow credential.
  printf 'operator-set-%s' "$RANDOM" >"$dir/.secrets/rustfs_escrow_worker_secret_key"
  for f in "${offboard[@]}"; do rm -f "$dir/.secrets/$f"; done
  sums "$dir/.secrets" >"$work/$name.before"
  check "$name: the earlier installation has escrow and root credentials" \
    grep -q 'rustfs_escrow_worker_secret_key$' "$work/$name.before"
  out="$("$@" 2>&1)" || {
    echo "FAIL $name: the upgrade run failed"
    failures=$((failures + 1))
    return
  }
  sums "$dir/.secrets" >"$work/$name.after"
  check "$name: every existing file is byte-identical, with its mode" \
    test -z "$(grep -Fvxf "$work/$name.after" "$work/$name.before")"
  check "$name: only the four offboard files are new" \
    test "$(grep -Fvxf "$work/$name.before" "$work/$name.after" | sed 's/.* \.\///' | LC_ALL=C sort | paste -sd,)" \
    == "$(printf '%s\n' "${offboard[@]}" | LC_ALL=C sort | paste -sd,)"
  for f in "${offboard[@]}"; do
    # shellcheck disable=SC2016 # the inner shell expands $1
    check "$name: $f is non-empty with mode 644" bash -c '[[ -s "$1" && "$(stat -c %a "$1")" == 644 ]]' _ "$dir/.secrets/$f"
    grep -qF -- "$(cat "$dir/.secrets/$f")" <<<"$out" && leaked="$leaked $f"
  done
  check "$name: the run prints no generated value" test -z "$leaked"
  check "$name: the run names the created files" grep -q "created .secrets/rustfs_escrow_offboard_access_key" <<<"$out"
  check "$name: four distinct values" test "$(for f in "${offboard[@]}"; do
    cat "$dir/.secrets/$f"
    echo
  done | sort -u | wc -l)" -eq 4
  "$@" >/dev/null 2>&1
  sums "$dir/.secrets" >"$work/$name.again"
  check "$name: a further run changes nothing" cmp -s "$work/$name.after" "$work/$name.again"
}

# The bundle's generator on a lab host (control plane and audit parts in one run).
lab="$work/lab"
mkdir -p "$lab/scripts" "$lab/rabbitmq"
cp "$src"/scripts/{lib.sh,gen-prod-secrets.sh} "$lab/scripts/"
cp "$src/rabbitmq/definitions.json.tmpl" "$lab/rabbitmq/"
cp "$src/versions.env" "$lab/"
cp "$src/lab.env.example" "$lab/.env"
scenario prod-lab "$lab" env -u SECRETS_DIR -u PADDOCK_HOST -u PADDOCK_ENV -u PADDOCK_INTERCONNECT_ADDR \
  "$lab/scripts/gen-prod-secrets.sh" lab

# make dev-secrets in a copy of deploy/compose.
dev="$work/dev"
mkdir -p "$dev"
tar -C "$src" --exclude=./.env --exclude=./.secrets -cf - . | tar -C "$dev" -xf -
scenario dev "$dev" env -u SECRETS_DIR -u PADDOCK_INSTANCE bash "$dev/scripts/gen-dev-secrets.sh"

if ((failures > 0)); then
  echo "$failures failure(s)"
  exit 1
fi
echo "gen-secrets-upgrade: all checks passed"
