#!/bin/sh
# paddock-supervisor prerm: stop the supervisor (and with it the agent) on removal, not on upgrade.
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
  systemctl disable --now paddock-supervisor.service >/dev/null || true
fi
