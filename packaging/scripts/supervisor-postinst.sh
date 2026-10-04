#!/bin/sh
# paddock-supervisor postinst: register the unit; a running supervisor is restarted after an upgrade.
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable paddock-supervisor.service >/dev/null
  if systemctl is-active --quiet paddock-supervisor.service; then
    systemctl restart paddock-supervisor.service
  fi
fi
