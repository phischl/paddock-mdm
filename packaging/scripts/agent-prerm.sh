#!/bin/sh
# paddock-agent prerm: disable the PAM profile paddock-deny on removal, not on upgrade (plan M3b decision 9).
set -e
if [ "$1" = remove ]; then
  pam-auth-update --package --remove paddock-deny
fi
