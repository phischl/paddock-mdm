#!/bin/sh
# paddock-agent postinst: enable the PAM profile paddock-deny, and on a device without an agent install paddockd
# into slot A and point current at it. An existing current (and every slot) is left alone: updates arrive as signed
# releases (plan M2b decision 25). `dpkg-reconfigure paddock-agent` enables the profile again after it was removed
# locally; the agent itself never edits PAM files (plan M3b decision 9).
set -e
pam-auth-update --package --enable paddock-deny
slots=/opt/paddock/agent
if [ ! -e "$slots/current" ] && [ ! -L "$slots/current" ]; then
  install -d -m 0755 "$slots/A"
  install -m 0755 /usr/lib/paddock/paddockd "$slots/A/paddockd.new"
  mv -f "$slots/A/paddockd.new" "$slots/A/paddockd"
  ln -s A "$slots/.current.new"
  mv -T "$slots/.current.new" "$slots/current"
fi
if [ -d /run/systemd/system ]; then
  systemctl start paddock-supervisor.service
fi
