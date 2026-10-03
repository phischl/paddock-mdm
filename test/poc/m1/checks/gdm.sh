#!/usr/bin/env bash
# Drives the GDM greeter and the GNOME lock screen of a test VM through the VirtualBox keyboard (US layout) and
# takes screenshots. Reading the device code from the QR greeter needs a human or an image viewer: the step
# "shot" prints the screenshot path, "approve" takes the code read from it (plan §10: documented
# manual-equivalent headless method).
#
# Usage: checks/gdm.sh <vm> <criterion> user <name> [tabs]  greeter: Tab x tabs (default 1; one per listed user)
#                                                    to "Not listed?" -> Enter -> type user name -> Enter
#        checks/gdm.sh <vm> <criterion> approve <user> <code>   approve the device code shown on screen
#        checks/gdm.sh <vm> <criterion> type <secret-file> [n]  type .secrets/<secret-file> + Enter n times
#        checks/gdm.sh <vm> <criterion> key <scancodes...>      raw set-1 scancodes (e.g. 1c 9c Enter, 39 b9 Space)
#        checks/gdm.sh <vm> <criterion> shot <name>             screenshot to out/<vm>/<criterion>/gdm/<name>.png
#        checks/gdm.sh <vm> <criterion> sessions                loginctl sessions with LockedHint
set -euo pipefail

source "$(dirname "$0")/../lib.sh"
ensure_secrets
vm=${1:?vm}; crit=${2:?criterion}; step=${3:?step}; shift 3
dir="$(evidence_dir "$vm" "$crit")/gdm"
mkdir -p "$dir"

case "$step" in
    user)
        for _ in $(seq 1 "${2:-1}"); do
            VBoxManage controlvm "$vm" keyboardputscancode 0f 8f   # Tab towards "Not listed?"
            sleep 1
        done
        VBoxManage controlvm "$vm" keyboardputscancode 1c 9c
        sleep 2
        VBoxManage controlvm "$vm" keyboardputstring "${1:?user}"
        VBoxManage controlvm "$vm" keyboardputscancode 1c 9c
        echo "$(ts) typed user $1" | tee -a "$dir/steps.log"
        ;;
    approve)
        echo "$(ts) approving code $2 as $1" | tee -a "$dir/steps.log"
        "$POC_DIR/authentik-setup.sh" approve "$1" "$2" 2>&1 | tee -a "$dir/steps.log"
        ;;
    type)
        for _ in $(seq 1 "${2:-1}"); do
            VBoxManage controlvm "$vm" keyboardputstring "$(poc_secret "$1")"
            VBoxManage controlvm "$vm" keyboardputscancode 1c 9c
            sleep 6   # the next field (e.g. "Confirm PIN") needs a moment on GNOME 46
        done
        echo "$(ts) typed $1 x${2:-1}" | tee -a "$dir/steps.log"
        ;;
    key)
        VBoxManage controlvm "$vm" keyboardputscancode "$@"
        echo "$(ts) scancodes $*" | tee -a "$dir/steps.log"
        ;;
    shot)
        screenshot "$vm" "$dir/${1:?name}.png"
        echo "$dir/$1.png"
        ;;
    sessions)
        gssh "$vm" 'for s in $(loginctl list-sessions --no-legend | awk "{print \$1}"); do
            loginctl show-session "$s" -p Id -p Name -p Class -p Type -p State -p LockedHint -p Active; echo; done' |
            tee -a "$dir/sessions.log"
        ;;
    *) die "unknown step $step" ;;
esac
