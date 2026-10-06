#!/bin/sh
# paddock-agent prerm: disable the PAM profile paddock-deny (plan M3b decision 9) and the first-boot disk setup on
# removal, not on upgrade.
set -e
if [ "$1" = remove ]; then
  pam-auth-update --package --remove paddock-deny
  systemctl disable paddock-disk-setup.service >/dev/null 2>&1 || true
fi
