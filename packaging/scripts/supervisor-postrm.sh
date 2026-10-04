#!/bin/sh
# paddock-supervisor postrm: forget the unit. Agent state in /var/lib/paddock and /etc/paddock stays, also on
# purge: an enrolled identity is never destroyed by a package operation.
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
