#!/usr/bin/env bash
# Zero-test guard of `make system-test` and `make acceptance` (PDK-339): a `go test -v` whose -run filter matches no
# test exits 0 with "no tests to run" and looks exactly like a passed gate. Piped behind `go test -v`, this passes the
# output through unchanged and fails when not a single test started (no `=== RUN` line). go test's own exit code
# reaches the caller through `set -o pipefail`.
set -euo pipefail

awk '
  { print; fflush() }
  /^=== RUN / { ran++ }
  END {
    if (!ran) {
      print "no test ran: the -run filter (T) matched nothing; a gate run without tests is not green" > "/dev/stderr"
      exit 1
    }
  }
'
