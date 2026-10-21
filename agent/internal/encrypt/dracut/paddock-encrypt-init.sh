#!/bin/sh
# Paddock in-place encryption, init step (plan M8e decision 16): runs in the initrd before anything mounts the root
# file system. It shrinks the file system, initialises LUKS2 in place with the conversion key and opens the mapping,
# or opens the header an earlier boot wrote. Every failure before the header exists leaves the device booting as
# before; the outcome goes to /run/paddock/encrypt-boot.env for the agent. The script never exits non-zero: a failed
# unit would hold up the boot.
set -u

# Tests run the script against a fake root; in the initrd the variable is unset.
root=${PADDOCK_ENCRYPT_TEST_ROOT:-}
plan=$root/etc/paddock/encrypt-plan.env
# The conversion key is handed to cryptsetup by path only; the script never reads it.
key=/etc/paddock/encrypt-key
out_dir=$root/run/paddock
out=$out_dir/encrypt-boot.env
err=$out_dir/encrypt-init.err
start=0
dev=
rc=0

log() {
	echo "paddock-encrypt: $*" >&2
}

uptime_s() {
	up=0
	{ read -r up _ <"$root/proc/uptime"; } 2>/dev/null
	echo "${up%%.*}"
}

# safe keeps a reason inside the charset the agent accepts, cut at 200 characters.
safe() {
	s=$1 r='' n=0
	while [ -n "$s" ] && [ "$n" -lt 200 ]; do
		c=${s%"${s#?}"}
		s=${s#?}
		case $c in
		[A-Za-z0-9_.:-]) r=$r$c ;;
		*) r=${r}_ ;;
		esac
		n=$((n + 1))
	done
	printf '%s' "$r"
}

# result STATUS STAGE [REASON] records the outcome for the agent (plan M8e §6.3).
result() {
	now=$(uptime_s)
	{
		echo "PADDOCK_BOOT_STATUS=$1"
		echo "PADDOCK_BOOT_STAGE=$2"
		echo "PADDOCK_BOOT_REASON=$(safe "${3:-}")"
		echo "PADDOCK_BOOT_SECONDS=$((now - start))"
	} >"$out"
	log "result $1 $2 ${3:-}"
}

# run logs and runs a command; its stderr goes to the journal and stays readable for first_err.
run() {
	log "run $*"
	"$@" 2>"$err"
	rc=$?
	while IFS= read -r line || [ -n "$line" ]; do
		echo "$line" >&2
	done <"$err"
	return "$rc"
}

first_err() {
	while IFS= read -r line || [ -n "$line" ]; do
		if [ -n "$line" ]; then
			printf '%s' "$line"
			return 0
		fi
	done <"$err"
	printf 'exit_%s' "$rc"
}

# bytes runs a tool that prints one byte count; lvm's "B" suffix and padding are tolerated.
bytes() {
	v=$(run "$@") || return 1
	v=${v#"${v%%[![:space:]]*}"}
	v=${v%"${v##*[![:space:]]}"}
	v=${v%B}
	case $v in
	'' | *[!0-9]*) return 1 ;;
	esac
	echo "$v"
}

# fs_bytes prints the size of the ext4 file system on $1: block count times block size from its superblock.
fs_bytes() {
	sb=$(run dumpe2fs -h "$1") || return 1
	printf '%s\n' "$sb" | {
		count='' size=''
		while IFS=: read -r k v; do
			case $k in
			'Block count') count=${v#"${v%%[![:space:]]*}"} ;;
			'Block size') size=${v#"${v%%[![:space:]]*}"} ;;
			esac
		done
		number "$count" && number "$size" || exit 1
		echo $((count * size))
	}
}

number() {
	case $1 in
	'' | *[!0-9]*) return 1 ;;
	esac
}

check_plan() {
	[ -r "$plan" ] || return 1
	# shellcheck disable=SC1090 # the plan is written by the agent; every value is in [A-Za-z0-9_.-] (§6.3)
	. "$plan" || return 1
	for v in "${PADDOCK_PART_UUID:-}" "${PADDOCK_LUKS_UUID:-}" "${PADDOCK_MAPPING:-}" "${PADDOCK_FS_UUID:-}"; do
		[ -n "$v" ] || return 1
	done
	number "${PADDOCK_FS_TARGET_BYTES:-}" && number "${PADDOCK_FS_TARGET_SECTORS:-}" &&
		number "${PADDOCK_PV_TARGET_BYTES:-}" || return 1
	case ${PADDOCK_LAYOUT:-} in
	lvm) [ -n "${PADDOCK_VG:-}" ] && [ -n "${PADDOCK_LV:-}" ] ;;
	plain) return 0 ;;
	*) return 1 ;;
	esac
}

lvm_layout() {
	[ "$PADDOCK_LAYOUT" = lvm ]
}

# dracut_arg NAME= prints a kernel command line argument as dracut's getarg sees it (it also reads /etc/cmdline.d);
# it fails when the argument is absent.
dracut_arg() {
	# dracut-lib.sh is not written for set -u; the subshell keeps it away from this script.
	(
		set +u
		# shellcheck source=/dev/null # dracut-lib.sh of the initrd
		. "$root/lib/dracut-lib.sh" >/dev/null 2>&1
		getarg "$1"
	)
}

# splash shows the conversion on the boot splash, where the console lines are hidden.
splash() {
	command -v plymouth >/dev/null 2>&1 || return 0
	plymouth --ping 2>/dev/null || return 0
	plymouth display-message --text="Encrypting the disk - do not switch off"
}

# testdelay STAGE is the dev-only hook of decision 19: paddock.encrypt.testdelay=STAGE:SECONDS on the kernel command
# line, honoured only in an initrd that carries the marker a dev build of the agent installs.
testdelay() {
	[ -e "$root/etc/paddock/encrypt-test" ] || return 0
	arg=$(dracut_arg paddock.encrypt.testdelay=) || return 0
	case $arg in
	"$1":*) s=${arg#*:} ;;
	*) return 0 ;;
	esac
	number "$s" || return 0
	log "test delay $1 ${s}s"
	sleep "$s"
}

# Stage 1: the partition of the plan, waited for at most 60 s.
wait_device() {
	dev=$root/dev/disk/by-partuuid/$PADDOCK_PART_UUID
	run udevadm settle --timeout=30
	i=0
	while [ ! -e "$dev" ]; do
		[ "$i" -lt 30 ] || return 1
		sleep 1
		i=$((i + 1))
	done
}

# Stage 2: on battery without mains the conversion waits for a new request (decision 9). Batteries of peripherals
# (scope Device) do not count.
on_battery() {
	battery=0 mains=0
	for d in "$root"/sys/class/power_supply/*; do
		[ -r "$d/type" ] || continue
		t='' scope='' online=''
		{ read -r t <"$d/type"; } 2>/dev/null
		{ read -r scope <"$d/scope"; } 2>/dev/null
		{ read -r online <"$d/online"; } 2>/dev/null
		case $t in
		Battery) [ "$scope" = Device ] || battery=1 ;;
		Mains) [ "$online" = 1 ] && mains=1 ;;
		esac
	done
	[ "$battery" = 1 ] && [ "$mains" = 0 ]
}

# open_luks opens the header; a mapping that already exists (the crypttab line of decision 20) counts as open.
open_luks() {
	if [ -e "$root/dev/mapper/$PADDOCK_MAPPING" ]; then
		log "mapping $PADDOCK_MAPPING already active"
		return 0
	fi
	run cryptsetup open --key-file "$key" "$dev" "$PADDOCK_MAPPING"
}

# Stage 3: a header written by an earlier boot is opened; cryptsetup recovers an interrupted reencryption.
open_path() {
	log "header found, opening"
	if ! open_luks; then
		result failed open "$(first_err)"
		return
	fi
	if lvm_layout && ! run lvm vgchange -ay "$PADDOCK_VG"; then
		result failed open "vg_activate_$rc"
		return
	fi
	result ok open
}

# fsck DEVICE accepts exit 0 (clean) and 1 (errors corrected). Preen only: whatever needs more than a safe repair is
# left to the administrator, and the conversion fails without changing anything.
fsck() {
	run e2fsck -f -p "$1"
	case $rc in
	0 | 1) return 0 ;;
	esac
	return 1
}

# Stage 4, lvm: shrink the root LV's file system and the LV by decision 17's margin, then the PV by the header.
shrink_lvm() {
	lv=$root/dev/$PADDOCK_VG/$PADDOCK_LV
	if ! run lvm vgchange -ay "$PADDOCK_VG"; then
		result failed init "vg_activate_$rc"
		return 1
	fi
	if ! fsck "$lv"; then
		result failed init "fsck_$rc"
		run lvm vgchange -ay "$PADDOCK_VG"
		return 1
	fi
	if ! size=$(bytes blockdev --getsize64 "$lv"); then
		result failed init size_unknown
		return 1
	fi
	if [ "$size" -gt "$PADDOCK_FS_TARGET_BYTES" ]; then
		if ! run resize2fs "$lv" "${PADDOCK_FS_TARGET_SECTORS}s"; then
			result failed init "resize2fs_$rc"
			return 1
		fi
		# The LV is reduced only after resize2fs succeeded: the file system then ends inside the new size.
		if ! run lvm lvreduce -f -L "${PADDOCK_FS_TARGET_BYTES}b" "$lv"; then
			result failed init "lvreduce_$rc"
			return 1
		fi
	else
		log "file system already at target"
	fi
	if ! pv=$(bytes lvm pvs --noheadings --units b -o pv_size "$dev"); then
		result failed init size_unknown
		return 1
	fi
	if [ "$pv" -gt "$PADDOCK_PV_TARGET_BYTES" ]; then
		if ! run lvm pvresize -y --setphysicalvolumesize "${PADDOCK_PV_TARGET_BYTES}b" "$dev"; then
			result failed init "pvresize_$rc"
			return 1
		fi
	fi
	if ! run lvm vgchange -an "$PADDOCK_VG"; then
		result failed init vg_busy
		run lvm vgchange -ay "$PADDOCK_VG"
		return 1
	fi
	log "shrink done"
}

# Stage 4, plain: shrink the file system on the partition by decision 17's margin.
shrink_plain() {
	if ! fsck "$dev"; then
		result failed init "fsck_$rc"
		return 1
	fi
	if ! size=$(fs_bytes "$dev"); then
		result failed init size_unknown
		return 1
	fi
	if [ "$size" -gt "$PADDOCK_FS_TARGET_BYTES" ]; then
		if ! run resize2fs "$dev" "${PADDOCK_FS_TARGET_SECTORS}s"; then
			result failed init "resize2fs_$rc"
			return 1
		fi
	else
		log "file system already at target"
	fi
	log "shrink done"
}

# Stage 5: the LUKS2 header with the conversion key; the data is encrypted later by the agent online.
init_luks() {
	testdelay init
	splash
	run cryptsetup reencrypt --encrypt --type luks2 --init-only --reduce-device-size 32M \
		--uuid "$PADDOCK_LUKS_UUID" --key-file "$key" --batch-mode "$dev" "$PADDOCK_MAPPING"
	init_rc=$rc
	if [ "$init_rc" -eq 0 ]; then
		log "init done"
		return 0
	fi
	# Once the header is on the disk the device can only boot through it: carry on as an online reencryption.
	if run cryptsetup isLuks "$dev" && open_luks; then
		log "header written despite exit $init_rc, continuing"
		return 0
	fi
	result failed init "luks_init_$init_rc"
	if lvm_layout; then
		run lvm vgchange -ay "$PADDOCK_VG"
	fi
	return 1
}

# Stage 6: the root device must appear on top of the mapping within 30 s.
activate() {
	testdelay open
	run udevadm settle --timeout=30
	if ! wait_until test -e "$root/dev/mapper/$PADDOCK_MAPPING"; then
		result failed init mapping_missing
		return
	fi
	if lvm_layout; then
		run lvm vgchange -ay "$PADDOCK_VG"
		rootdev=$root/dev/$PADDOCK_VG/$PADDOCK_LV
	else
		rootdev=$root/dev/disk/by-uuid/$PADDOCK_FS_UUID
	fi
	if ! wait_until root_ready; then
		result failed init root_missing
		return
	fi
	result ok init
}

# root_ready reports whether the root device exists; the plain root's UUID link also exists before the conversion (on
# the raw partition), so it must point at a device-mapper device. Called through wait_until.
# shellcheck disable=SC2317
root_ready() {
	[ -e "$rootdev" ] || return 1
	lvm_layout && return 0
	target=$(readlink -f "$rootdev") || return 1
	case ${target##*/} in
	dm-*) return 0 ;;
	esac
	return 1
}

# wait_until COMMAND... polls at most 30 s for COMMAND to succeed.
wait_until() {
	i=0
	while ! "$@"; do
		[ "$i" -lt 30 ] || return 1
		sleep 1
		i=$((i + 1))
	done
}

# same_device checks that exactly one partition carries the PARTUUID and that it holds the plan's file system or VG,
# so that a second disk with a cloned partition table is never shrunk or encrypted.
same_device() {
	devs=$(run blkid -o device -t "PARTUUID=$PADDOCK_PART_UUID") || return 1
	n=0
	for _ in $devs; do
		n=$((n + 1))
	done
	[ "$n" -eq 1 ] || return 1
	if lvm_layout; then
		got=$(run lvm pvs --noheadings -o vg_name "$dev") || return 1
		want=$PADDOCK_VG
	else
		got=$(run blkid -p -s UUID -o value "$dev") || return 1
		want=$PADDOCK_FS_UUID
	fi
	got=${got#"${got%%[![:space:]]*}"}
	got=${got%"${got##*[![:space:]]}"}
	[ "$got" = "$want" ]
}

main() {
	start=$(uptime_s)
	if ! check_plan; then
		result failed init plan_invalid
		return
	fi
	if ! wait_device; then
		result failed init device_missing
		return
	fi
	# A header on the disk decides before anything else (plan M8e §14.10 I2): such a device boots only through it.
	run cryptsetup isLuks "$dev"
	case $rc in
	0)
		open_path
		return
		;;
	1) ;;
	*)
		result failed init "isluks_$rc"
		return
		;;
	esac
	# A resume from hibernation would bring back a kernel that still has root mounted (plan M8e amendment 2026-10-21).
	if dracut_arg resume= >/dev/null; then
		result skipped init resume_set
		return
	fi
	if on_battery; then
		result skipped init on_battery
		return
	fi
	if ! same_device; then
		result failed init device_mismatch
		return
	fi
	splash
	if lvm_layout; then
		shrink_lvm || return
	else
		shrink_plain || return
	fi
	init_luks || return
	activate
}

mkdir -p "$out_dir"
rm -f "$out"
(main)
status=$?
if [ ! -e "$out" ]; then
	result failed init "script_$status"
fi
rm -f "$err"
exit 0
