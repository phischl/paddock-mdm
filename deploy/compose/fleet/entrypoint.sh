#!/bin/sh
# Exports every <NAME>_FROMFILE=<path> environment variable as <NAME>=<file content>, migrates the Fleet database and
# starts Fleet. Fleet reads the Redis password and its private key from the environment only; this keeps the values
# out of `docker inspect`.
set -eu
for var in $(env | sed -n 's/^\([A-Za-z0-9_]*\)_FROMFILE=.*/\1/p'); do
  eval "file=\${${var}_FROMFILE}"
  # shellcheck disable=SC2154
  value="$(cat "$file")"
  export "$var=$value"
  unset "${var}_FROMFILE"
done
fleet prepare db --no-prompt
exec fleet serve
