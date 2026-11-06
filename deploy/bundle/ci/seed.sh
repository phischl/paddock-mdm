#!/usr/bin/env bash
# Seeds a running installation for the upgrade job (plan M16 decision 10): through the admin API a platform
# administrator, the organization ci-upgrade with an administrator, a managed file, an auto-approving enrollment token,
# a notification destination and an API token (upgradeprobe seed); then one device enrolled with the given
# upgradesim, which escrows its local administrator password; then the snapshot "pre" (the device and the audit event
# count). Every later probe compares against it.
#   seed.sh <work dir> <control-plane bundle dir> <upgradesim binary>
# Environment: UPGRADEPROBE (the upgradeprobe binary), CP_OVERLAY (PADDOCK_COMPOSE_EXTRA of the control plane).
# The state lands in <work dir>/seed (0700): seed.json, the passkeys, the API token, the device state and its
# enrollment configuration. Exit 0: seeded; 1: a step failed (named on stderr); 2: usage.
set -euo pipefail

[[ $# -eq 3 && -d "$2" && -x "$3" && -x "${UPGRADEPROBE:-}" ]] || {
  echo "usage: UPGRADEPROBE=<binary> seed.sh <work dir> <control-plane bundle dir> <upgradesim binary>" >&2
  exit 2
}
W="$1" cp_dir="$(cd "$2" && pwd)" sim="$3"
state="$W/seed"
(umask 077 && mkdir -p "$state" "$W/bin")
export PADDOCK_SECRETS_DIR="$cp_dir/.secrets" PADDOCK_TEST_ADMIN_URL=https://admin.paddock.localhost \
  PADDOCK_TEST_AUTH_URL=https://auth.paddock.localhost

# The passkeys are registered through Authentik's own shell, the way the gates install TOTP authenticators; the
# script (public keys only) travels on stdin.
cat >"$W/bin/ak-shell" <<EOF
#!/usr/bin/env bash
cd $(printf '%q' "$cp_dir") && PADDOCK_COMPOSE_EXTRA=$(printf '%q' "${CP_OVERLAY:-}") exec ./paddock compose exec -T authentik-worker ak shell
EOF
chmod 700 "$W/bin/ak-shell"

echo "seed: administrators, organization and objects"
"$UPGRADEPROBE" seed --state "$state" --ak-shell "$W/bin/ak-shell" --enrollment-config "$state/enroll.json"
echo "seed: a device of $(basename "$sim") with an escrowed password"
out="$("$sim" enroll --state "$state/device.json" --hostname ci-upgrade-device <"$state/enroll.json")" ||
  { echo "seed: the device did not enroll" >&2; exit 1; }
device_id="$(sed -n 's/.*"device_id":"\([0-9a-f-]*\)".*/\1/p' <<<"$out")"
[[ -n "$device_id" ]] || { echo "seed: no device ID in '$out'" >&2; exit 1; }
echo "seed: device $device_id"
"$UPGRADEPROBE" snapshot --state "$state" --label pre --device-id "$device_id"
