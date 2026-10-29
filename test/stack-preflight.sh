#!/usr/bin/env bash
# Preflight of `make acceptance`, `make system-test` and `make e2e` (PDK-353): they run against the development stack
# and need the checkout's deploy/compose/.env and .secrets, which a fresh worktree lacks. Without the check a run
# failed only minutes in (S3 `make down`, gdmLogin's `docker compose exec`: "couldn't find env file"), which read like
# a gate failure. Both may be symlinks to the checkout the stack runs from; only presence is checked, never contents.
#
# usage: stack-preflight.sh <compose dir> <secrets dir>
set -euo pipefail

compose_dir="${1:?usage: stack-preflight.sh <compose dir> <secrets dir>}"
secrets_dir="${2:?usage: stack-preflight.sh <compose dir> <secrets dir>}"
problems=()

# -f and -d follow symlinks, so a dangling link to a removed worktree counts as missing.
if [[ ! -f "$compose_dir/.env" ]]; then
  problems+=("$compose_dir/.env is missing (or a dangling symlink)")
fi
if [[ ! -d "$secrets_dir" ]]; then
  problems+=("$secrets_dir is missing (or a dangling symlink)")
else
  # dev_alice_password comes from `make dev-secrets`; caddy-root.crt is created empty there and filled by `make up`,
  # so an empty one means the stack never ran with this secrets directory.
  for f in dev_alice_password caddy-root.crt; do
    [[ -s "$secrets_dir/$f" ]] || problems+=("$secrets_dir/$f is missing or empty")
  done
fi

if ((${#problems[@]} > 0)); then
  {
    echo "stack preflight failed: this checkout is not set up for the running development stack"
    printf '  - %s\n' "${problems[@]}"
    echo "In the checkout the stack runs from: make dev-secrets up dev-seed."
    echo "In a further worktree: symlink deploy/compose/.env and deploy/compose/.secrets to that checkout's"
    echo "(test/system/README.md, Worktrees)."
  } >&2
  exit 1
fi
