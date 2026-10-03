#!/usr/bin/env bash
# M1 step 3: prepares a running test VM (started from base-installed) for the login criteria: Authentik hostname
# and Caddy CA (decision 5), Himmelblau from the official package repository (decision 2) with the dpkg conffile
# options of the upstream installer (confdef/confold), PAM/NSS via the package's documented method
# (aad-tool configure-pam), himmelblau.conf from the template, pamtester for checks.
#
# Usage: vm-prepare.sh <vm>
set -euo pipefail

source "$(dirname "$0")/lib.sh"
ensure_secrets
vm=${1:?usage: $0 <vm>}
out=$(evidence_dir "$vm" prepare)

HIMMELBLAU_VERSION=${HIMMELBLAU_VERSION:-4.0.4}
HIMMELBLAU_KEY_URL=https://packages.himmelblau-idm.org/himmelblau.asc
HIMMELBLAU_KEY_FPR=E87FD8D463A5E4814B9CDBA90CC0D4002C425E03
PACKAGES="himmelblau pam-himmelblau nss-himmelblau himmelblau-qr-greeter himmelblau-sshd-config"
ISSUER="$AUTH_URL/application/o/paddock-device-acme/"

[[ -s "$CADDY_ROOT" ]] || die "missing $CADDY_ROOT (is the dev stack up?)"

log "$vm: hosts entry and CA trust"
gssh "$vm" "sudo tee /usr/local/share/ca-certificates/paddock-dev-caddy-root.crt >/dev/null" <"$CADDY_ROOT"
gssh "$vm" "
    set -euo pipefail
    grep -q ' $AUTH_HOST\$' /etc/hosts || echo '$HOST_FROM_GUEST $AUTH_HOST' | sudo tee -a /etc/hosts >/dev/null
    sudo update-ca-certificates 2>&1 | tail -1
    getent hosts $AUTH_HOST" | tee "$out/network.log"

log "$vm: Himmelblau $HIMMELBLAU_VERSION package repository"
gssh "$vm" "
    set -euo pipefail
    . /etc/os-release
    sudo apt-get install -y -q curl gpg >/dev/null
    curl -fsSL $HIMMELBLAU_KEY_URL -o /tmp/himmelblau.asc
    fpr=\$(gpg --show-keys --with-colons /tmp/himmelblau.asc | awk -F: '/^fpr/ {print \$10; exit}')
    [ \"\$fpr\" = $HIMMELBLAU_KEY_FPR ] || { echo \"unexpected signing key \$fpr\" >&2; exit 1; }
    echo \"signing key \$fpr\"
    sudo install -d -m 0755 /etc/apt/keyrings
    gpg --dearmor </tmp/himmelblau.asc | sudo tee /etc/apt/keyrings/himmelblau.gpg >/dev/null
    echo \"deb [signed-by=/etc/apt/keyrings/himmelblau.gpg] https://packages.himmelblau-idm.org/stable/$HIMMELBLAU_VERSION/deb/ubuntu\$VERSION_ID/ ./\" |
        sudo tee /etc/apt/sources.list.d/himmelblau.list
    sudo apt-get update -q 2>&1 | grep -i himmelblau
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold $PACKAGES pamtester </dev/null 2>&1 | grep -E '^(The following|  |Setting up (himmelblau|pam-|nss-))' || true
    dpkg-query -W -f='\${Package} \${Version}\n' $PACKAGES pamtester" 2>&1 | tee "$out/install.log"

log "$vm: himmelblau.conf"
sed -e "s|@ISSUER@|$ISSUER|" -e "s|@CLIENT_ID@|paddock-device-acme|" -e "s|@DOMAIN@|acme.test|" \
    -e "s|@ALLOW@|paddock.acme|" "$POC_DIR/himmelblau/himmelblau.conf.tmpl" |
    gssh "$vm" 'sudo install -d -m 0755 /etc/himmelblau && sudo tee /etc/himmelblau/himmelblau.conf >/dev/null'

log "$vm: PAM/NSS integration (aad-tool configure-pam) and services"
gssh "$vm" '
    set -euo pipefail
    sudo rm -rf /tmp/pam.d.before && sudo cp -a /etc/pam.d /tmp/pam.d.before
    sudo aad-tool configure-pam --really 2>&1 || true
    echo "--- PAM changes"
    sudo diff -ru /tmp/pam.d.before /etc/pam.d || true
    echo "--- pam_himmelblau lines (set by the package via pam-auth-update)"
    grep -H himmelblau /etc/pam.d/common-* || true
    echo "--- nsswitch"
    grep -E "^(passwd|group|shadow|initgroups):" /etc/nsswitch.conf
    # The package starts the daemon before a configuration exists; that hits the start limit.
    sudo systemctl reset-failed himmelblaud himmelblaud-tasks
    sudo systemctl enable himmelblaud himmelblaud-tasks
    sudo systemctl restart himmelblaud himmelblaud-tasks
    sleep 3
    systemctl is-active himmelblaud himmelblaud-tasks
    echo "--- journal"
    sudo journalctl -b -u himmelblaud -u himmelblaud-tasks --no-pager -o short-iso-precise | tail -25
    echo "--- aad-tool status"
    sudo aad-tool status 2>&1 || true
    echo "--- aad-tool tpm"
    sudo aad-tool tpm 2>&1 || true' 2>&1 | tee "$out/integration.log"
