// Package encrypt is the in-place encryption of an installed device's root volume (ADR 0039, plan M8e): the
// preflight that tells whether the disk layout qualifies, the preparation for the conversion at the next restart, its
// abort and cleanup, the restart notification and, in a later ticket, the resume of the online reencryption.
package encrypt

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/phischl/paddock-mdm/agent/internal/luks"
)

// Preflight reasons (plan M8e decision 2), a closed set. The agent reports every failing one, sorted.
const (
	ReasonAlreadyEncrypted         = "already_encrypted"
	ReasonBootOnRootDevice         = "boot_on_root_device"
	ReasonCleanupPending           = "cleanup_pending"
	ReasonDMCryptMissing           = "dm_crypt_missing" // checked at the preparation only (decision 7)
	ReasonHibernationConfigured    = "hibernation_configured"
	ReasonInitrdToolsMissing       = "initrd_tools_missing"
	ReasonLowFreeSpace             = "low_free_space"
	ReasonLVMDevicesFile           = "lvm_devicesfile"
	ReasonLVMFilter                = "lvm_filter"
	ReasonLVMUnknown               = "lvm_unknown"
	ReasonNoSeparateBoot           = "no_separate_boot"
	ReasonNoTPM2                   = "no_tpm2"
	ReasonNoUEFI                   = "no_uefi"
	ReasonOtherLUKSPresent         = "other_luks_present"
	ReasonPVTailInUse              = "pv_tail_in_use"
	ReasonReleaseUnsupported       = "release_unsupported"
	ReasonRootLayoutUnsupported    = "root_layout_unsupported"
	ReasonRootNotExt4              = "root_not_ext4"
	ReasonRootReferenceUnsupported = "root_reference_unsupported"
)

// Layouts a device can be converted from (plan M8e §3.1).
const (
	KindLVM   = "lvm"   // the root LV in one VG on one PV on one GPT partition
	KindPlain = "plain" // ext4 directly on one GPT partition
)

// Initramfs generators (plan M8e decision 34).
const (
	InitramfsDracut = "dracut"
	InitramfsTools  = "initramfs-tools"
)

// MinFreeBytes is the free space the root file system needs (reason low_free_space).
const MinFreeBytes = 1 << 30

// releases are the VERSION_IDs a conversion supports.
var releases = []string{"24.04", "26.04"}

// Layout is the result of a preflight; Reasons is empty when Eligible.
type Layout struct {
	Eligible  bool
	Reasons   []string // closed set above, sorted
	Kind      string   // "lvm" | "plain" | "" when not eligible for a layout reason
	Partition string   // /dev/disk/by-partuuid/<uuid> of the root partition (the future LUKS device)
	PartUUID  string
	VG, LV    string // lvm only
	FSUUID    string // the ext4 UUID of the root file system
	Release   string // VERSION_ID of /etc/os-release
	// Initramfs is the installed generator; InitramfsRemoves, under initramfs-tools only, the packages installing
	// dracut would remove (sorted; nil when the simulation failed).
	Initramfs                            string
	InitramfsRemoves                     []string
	PartitionBytes, FSBytes, FSFreeBytes int64
}

// Preflight reports whether the device's disk can be encrypted in place (ADR 0039 decision 2). It reads the layout
// with findmnt, lsblk, blkid and lvm, asks dpkg-query for dracut and, without dracut, apt-get -s for what the
// switch would remove (plan §14.4 decision 34), and changes nothing. Cost: one dpkg-query (milliseconds) and, on a
// device still on initramfs-tools, one apt-get -s (about a second of CPU and a read of the apt cache, no lock, no
// network); callers run it at most every 10 minutes and only while the device is unencrypted. root is the layout root
// the files are read below. cleanupPending (the conversion state's CleanupPending, invariant I3 of plan §14.10)
// reports the reason cleanup_pending alone and skips every other check.
func Preflight(ctx context.Context, sys System, root string, cleanupPending bool) Layout {
	if cleanupPending {
		return Layout{Reasons: []string{ReasonCleanupPending}}
	}
	p := &preflight{ctx: ctx, sys: sys, root: root}
	p.release()
	if ok, err := sys.Stat(filepath.Join(root, "/sys/firmware/efi")); err != nil || !ok {
		p.fail(ReasonNoUEFI)
	}
	if !luks.TPM2Present(root) {
		p.fail(ReasonNoTPM2)
	}
	part := p.rootLayout()
	p.otherLUKS()
	p.hibernation()
	if p.l.Kind == KindLVM {
		p.lvmConfig()
	}
	p.rootFS()
	p.boot(part)
	p.reference()
	p.initramfs()
	slices.Sort(p.reasons)
	p.l.Reasons = slices.Compact(p.reasons)
	p.l.Eligible = len(p.l.Reasons) == 0
	return p.l
}

type preflight struct {
	ctx     context.Context
	sys     System
	root    string
	l       Layout
	reasons []string
	// source is the root file system's device (findmnt SOURCE without a btrfs subvolume); vg, lv, vgUUID and lvUUID
	// name the root LV when the root is one, whatever the layout.
	source, vg, lv, vgUUID, lvUUID string
	// rootChain is the device chain below / (rootLayout).
	rootChain []blockDevice
}

func (p *preflight) fail(reason string) { p.reasons = append(p.reasons, reason) }

// run runs a tool and returns its trimmed stdout; ok is false on an error or a non-zero exit.
func (p *preflight) run(name string, args ...string) (string, bool) {
	out, _, exit, err := p.sys.Command(p.ctx, name, args...)
	return strings.TrimSpace(out), err == nil && exit == 0
}

// release reads VERSION_ID of /etc/os-release.
func (p *preflight) release() {
	raw, err := p.sys.ReadFile(filepath.Join(p.root, "/etc/os-release"))
	if err == nil {
		sc := bufio.NewScanner(bytes.NewReader(raw))
		for sc.Scan() {
			if v, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "VERSION_ID="); ok {
				p.l.Release = strings.Trim(v, `"'`)
			}
		}
	}
	if !slices.Contains(releases, p.l.Release) {
		p.fail(ReasonReleaseUnsupported)
	}
}

// blockDevice is a node of lsblk --inverse --json: Children are the devices it is built on.
type blockDevice struct {
	Name     string        `json:"name"`
	Type     string        `json:"type"`
	FSType   string        `json:"fstype"`
	PartUUID string        `json:"partuuid"`
	Size     byteSize      `json:"size"`
	Children []blockDevice `json:"children"`
}

// byteSize is an lsblk --bytes size, which util-linux prints as a number or, in older releases, as a string.
type byteSize int64

func (s *byteSize) UnmarshalJSON(b []byte) error {
	v := strings.Trim(string(b), `"`)
	if v == "null" || v == "" {
		return nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	*s = byteSize(n)
	return err
}

// rootLayout classifies the device chain below / (reason root_layout_unsupported, pv_tail_in_use, already_encrypted)
// and returns the root partition ("" when the layout is unsupported).
func (p *preflight) rootLayout() string {
	src, _ := p.run("findmnt", "-no", "SOURCE", "/")
	p.source, _, _ = strings.Cut(src, "[")
	chain, ok := p.chain()
	p.rootChain = chain
	if chain != nil && encrypted(chain) {
		p.fail(ReasonAlreadyEncrypted)
	}
	if len(chain) > 0 && chain[0].Type == "lvm" {
		p.readLV()
	}
	var part, disk blockDevice
	switch {
	case ok && types(chain) == "lvm,part,disk" && chain[1].FSType == "LVM2_member":
		p.l.Kind, part, disk = KindLVM, chain[1], chain[2]
		ok = p.lv != "" && p.onePV(part.Name)
	case ok && types(chain) == "part,disk" && chain[0].FSType == "ext4":
		p.l.Kind, part, disk = KindPlain, chain[0], chain[1]
	default:
		ok = false
	}
	if ok {
		pt, _ := p.run("blkid", "-p", "-o", "value", "-s", "PTTYPE", disk.Name)
		ok = pt == "gpt" && part.PartUUID != ""
	}
	if !ok {
		p.fail(ReasonRootLayoutUnsupported)
		p.l.Kind = ""
		return ""
	}
	if p.l.Kind == KindLVM {
		p.l.VG, p.l.LV = p.vg, p.lv
	}
	p.l.PartUUID, p.l.Partition, p.l.PartitionBytes = part.PartUUID, "/dev/disk/by-partuuid/"+part.PartUUID, int64(part.Size)
	if p.l.Kind == KindLVM && !p.pvTailFree(part.Name) {
		p.fail(ReasonPVTailInUse)
	}
	return part.Name
}

// chain returns the devices from the root file system's device down to the disk; ok is false when lsblk fails or a
// device is built on more than one other (raid, an LV across several PVs).
func (p *preflight) chain() ([]blockDevice, bool) {
	if p.source == "" {
		return nil, false
	}
	out, ok := p.run("lsblk", "--inverse", "--json", "--paths", "--bytes", "--output", "NAME,TYPE,FSTYPE,PKNAME,PARTUUID,SIZE", "--", p.source)
	var tree struct {
		BlockDevices []blockDevice `json:"blockdevices"`
	}
	if !ok || json.Unmarshal([]byte(out), &tree) != nil {
		return nil, false
	}
	var chain []blockDevice
	devs, single := tree.BlockDevices, true
	for len(devs) > 0 {
		if len(devs) > 1 {
			single = false
		}
		chain = append(chain, devs[0])
		devs = devs[0].Children
	}
	return chain, single
}

func types(chain []blockDevice) string {
	t := make([]string, len(chain))
	for i, d := range chain {
		t[i] = d.Type
	}
	return strings.Join(t, ",")
}

// encrypted reports whether a LUKS volume lies below a crypt mapping in the chain, the condition under which the luks
// reconciler's state is not not_encrypted (luks.Root).
func encrypted(chain []blockDevice) bool {
	for i := 1; i < len(chain); i++ {
		if chain[i-1].Type == "crypt" && chain[i].FSType == "crypto_LUKS" {
			return true
		}
	}
	return false
}

// readLV reads the names and UUIDs of the root LV and its VG.
func (p *preflight) readLV() {
	out, ok := p.run("lvm", "lvs", "--noheadings", "-o", "vg_name,lv_name,vg_uuid,lv_uuid", "--", p.source)
	if f := strings.Fields(out); ok && len(f) == 4 {
		p.vg, p.lv, p.vgUUID, p.lvUUID = f[0], f[1], f[2], f[3]
	}
}

// onePV checks that the root LV's VG has exactly one PV, partition.
func (p *preflight) onePV(partition string) bool {
	out, ok := p.run("lvm", "pvs", "--noheadings", "-o", "pv_name,vg_name")
	if !ok {
		return false
	}
	var pvs []string
	for line := range strings.Lines(out) {
		if f := strings.Fields(line); len(f) == 2 && f[1] == p.vg {
			pvs = append(pvs, f[0])
		}
	}
	return len(pvs) == 1 && pvs[0] == partition
}

// pvTailFree reports whether the last allocated segment of the PV belongs to the root LV.
func (p *preflight) pvTailFree(pv string) bool {
	out, ok := p.run("lvm", "pvs", "--segments", "--noheadings", "--units", "b", "-o", "pv_name,pvseg_start,pvseg_size,lv_name")
	if !ok {
		return false
	}
	last, lv := int64(-1), ""
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) != 4 || f[0] != pv {
			continue
		}
		start, err := strconv.ParseInt(strings.TrimSuffix(f[1], "B"), 10, 64)
		if err != nil {
			return false
		}
		if start > last {
			last, lv = start, f[3]
		}
	}
	return lv != "" && lv == p.lv
}

// otherLUKS fails when a LUKS volume outside the root chain exists (reason other_luks_present): the init step's
// initrd disables dracut's LUKS handling with rd.luks=0 (plan M8e decision 15 as amended 2026-10-21), so such a
// volume would no longer be opened at boot. A failing lsblk fails closed.
func (p *preflight) otherLUKS() {
	out, ok := p.run("lsblk", "--noheadings", "--list", "--paths", "--output", "NAME,FSTYPE")
	if !ok {
		p.fail(ReasonOtherLUKSPresent)
		return
	}
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) != 2 || f[1] != "crypto_LUKS" {
			continue
		}
		if !slices.ContainsFunc(p.rootChain, func(d blockDevice) bool { return d.Name == f[0] }) {
			p.fail(ReasonOtherLUKSPresent)
			return
		}
	}
}

// hibernationEFIVar is the EFI variable systemd sets when it hibernates to a swap device it then resumes from.
const hibernationEFIVar = "/sys/firmware/efi/efivars/HibernateLocation-8cf2644b-4b0b-428f-9387-6d876050dc67"

// hibernation fails when a resume from hibernation is configured (reason hibernation_configured): the init step would
// shrink and encrypt a file system the hibernated kernel still has mounted (plan M8e amendment 2026-10-21). Configured
// means resume= on the kernel command line, in dracut's /etc/cmdline.d or in a kernel_cmdline of dracut's
// configuration, a resume device in /sys/power/resume, or systemd's HibernateLocation EFI variable.
func (p *preflight) hibernation() {
	files := []string{filepath.Join(p.root, "/proc/cmdline")}
	for _, pattern := range []string{"/etc/cmdline.d/*.conf", "/etc/dracut.conf.d/*.conf", "/usr/lib/dracut/dracut.conf.d/*.conf"} {
		confs, _ := filepath.Glob(filepath.Join(p.root, pattern))
		files = append(files, confs...)
	}
	for _, f := range files {
		raw, err := p.sys.ReadFile(f)
		if err != nil {
			continue
		}
		for _, arg := range strings.Fields(strings.NewReplacer(`"`, " ", "'", " ").Replace(string(raw))) {
			if strings.HasPrefix(arg, "resume=") || strings.HasPrefix(arg, "kernel_cmdline=resume=") {
				p.fail(ReasonHibernationConfigured)
				return
			}
		}
	}
	if raw, err := p.sys.ReadFile(filepath.Join(p.root, "/sys/power/resume")); err == nil {
		if dev := strings.TrimSpace(string(raw)); dev != "" && dev != "0:0" {
			p.fail(ReasonHibernationConfigured)
			return
		}
	}
	if ok, err := p.sys.Stat(filepath.Join(p.root, hibernationEFIVar)); err != nil || ok {
		p.fail(ReasonHibernationConfigured)
	}
}

// lvmConfig fails when LVM would not see the PV once it moves onto the mapping (plan M8e amendment 2026-10-21): an
// active devices file lists the partition, not the mapping (reason lvm_devicesfile), and a filter set by the
// administrator may reject dm devices (reason lvm_filter). An lvm config that fails or prints something unexpected
// fails closed with lvm_unknown.
func (p *preflight) lvmConfig() {
	out, ok := p.run("lvm", "config", "--typeconfig", "full", "devices/use_devicesfile")
	switch {
	case !ok || (out != "use_devicesfile=0" && out != "use_devicesfile=1"):
		p.fail(ReasonLVMUnknown)
	case out == "use_devicesfile=1":
		if exists, err := p.sys.Stat(filepath.Join(p.root, "/etc/lvm/devices/system.devices")); err != nil || exists {
			p.fail(ReasonLVMDevicesFile)
		}
	}
	// Asking for the two nodes directly exits 5 when they are unset (the default), hence the whole section; it is
	// empty when nothing differs from the defaults.
	out, ok = p.run("lvm", "config", "--typeconfig", "diff", "devices")
	if first, _, _ := strings.Cut(out, "\n"); !ok || (out != "" && strings.TrimSpace(first) != "devices {") {
		p.fail(ReasonLVMUnknown)
		return
	}
	for line := range strings.Lines(out) {
		if l := strings.TrimSpace(line); strings.HasPrefix(l, "filter=") || strings.HasPrefix(l, "global_filter=") {
			p.fail(ReasonLVMFilter)
			return
		}
	}
}

// rootFS checks the root file system's type and free space (reasons root_not_ext4, low_free_space).
func (p *preflight) rootFS() {
	if fstype, _ := p.run("findmnt", "-no", "FSTYPE", "/"); fstype != "ext4" {
		p.fail(ReasonRootNotExt4)
	}
	p.l.FSUUID, _ = p.run("findmnt", "-no", "UUID", "/")
	out, ok := p.run("findmnt", "-bno", "SIZE,AVAIL", "/")
	f := strings.Fields(out)
	if ok && len(f) == 2 {
		size, serr := strconv.ParseInt(f[0], 10, 64)
		avail, aerr := strconv.ParseInt(f[1], 10, 64)
		if serr == nil && aerr == nil {
			p.l.FSBytes, p.l.FSFreeBytes = size, avail
		}
	}
	if p.l.FSFreeBytes < MinFreeBytes {
		p.fail(ReasonLowFreeSpace)
	}
}

// boot checks that /boot is a partition of its own other than the root partition (reasons no_separate_boot,
// boot_on_root_device).
func (p *preflight) boot(rootPartition string) {
	if target, _ := p.run("findmnt", "--noheadings", "--output", "TARGET", "--target", "/boot"); target != "/boot" {
		p.fail(ReasonNoSeparateBoot)
		return
	}
	src, _ := p.run("findmnt", "-no", "SOURCE", "/boot")
	src, _, _ = strings.Cut(src, "[")
	typ, ok := "", src != ""
	if ok {
		typ, ok = p.run("lsblk", "--noheadings", "--nodeps", "--paths", "--output", "TYPE", "--", src)
	}
	if !ok || typ != "part" {
		p.fail(ReasonNoSeparateBoot)
		return
	}
	if src == rootPartition || src == p.source {
		p.fail(ReasonBootOnRootDevice)
	}
}

// reference checks how /etc/fstab and the kernel command line name the root file system (reason
// root_reference_unsupported): by its UUID or, for lvm, by a path of the root LV — /dev/mapper/<vg>-<lv>,
// /dev/<vg>/<lv> or the /dev/disk/by-id/dm-uuid-LVM-<vg uuid><lv uuid> link curtin writes (correction of plan M8e
// decision 2, 2026-10-21) — all of which still resolve once the partition below is LUKS.
func (p *preflight) reference() {
	accepted := []string{}
	if p.l.FSUUID != "" {
		accepted = append(accepted, "UUID="+p.l.FSUUID)
	}
	if p.lv != "" {
		mapper := strings.ReplaceAll(p.vg, "-", "--") + "-" + strings.ReplaceAll(p.lv, "-", "--")
		accepted = append(accepted, "/dev/mapper/"+mapper, "/dev/"+p.vg+"/"+p.lv,
			"/dev/disk/by-id/dm-uuid-LVM-"+strings.ReplaceAll(p.vgUUID, "-", "")+strings.ReplaceAll(p.lvUUID, "-", ""))
	}
	fstab, ok := p.run("findmnt", "--fstab", "-no", "SOURCE", "/")
	if !ok || !slices.Contains(accepted, fstab) || !slices.Contains(accepted, p.cmdlineRoot()) {
		p.fail(ReasonRootReferenceUnsupported)
	}
}

// cmdlineRoot is the last root= of /proc/cmdline (the one the kernel uses), "" without one.
func (p *preflight) cmdlineRoot() string {
	raw, err := p.sys.ReadFile(filepath.Join(p.root, "/proc/cmdline"))
	if err != nil {
		return ""
	}
	root := ""
	for _, f := range strings.Fields(string(raw)) {
		if v, ok := strings.CutPrefix(f, "root="); ok {
			root = v
		}
	}
	return root
}

// initramfs reports the installed generator and, under initramfs-tools, what installing dracut would remove (plan M8e
// decisions 32–34). dpkg-query is the single source of truth for "dracut installed".
func (p *preflight) initramfs() {
	if status, ok := p.run("dpkg-query", "-W", "-f=${db:Status-Status}", "dracut"); ok && status == "installed" {
		p.l.Initramfs = InitramfsDracut
		p.initrdLister()
		return
	}
	p.l.Initramfs = InitramfsTools
	p.l.InitramfsRemoves = simulatedRemovals(p.ctx, p.sys)
}

// initrdLister fails with initrd_tools_missing when lsinitrd cannot list the running kernel's initrd (amendment
// 2026-10-21, item 15): every verification of the conversion reads initrds with it, and dracut-ng's lsinitrd needs 3cpio
// or dracut-extractinitrd. Under initramfs-tools lsinitrd arrives with dracut, so step 8 of the preparation checks it
// (initrd_incomplete).
func (p *preflight) initrdLister() {
	release, err := p.sys.ReadFile(filepath.Join(p.root, "/proc/sys/kernel/osrelease"))
	if err != nil {
		p.fail(ReasonInitrdToolsMissing)
		return
	}
	if _, ok := p.run("lsinitrd", filepath.Join(p.root, "/boot/initrd.img-"+strings.TrimSpace(string(release)))); !ok {
		p.fail(ReasonInitrdToolsMissing)
	}
}

// simulatedRemovals returns the packages installing dracut would remove: the Remv lines of
// apt-get -s -o Debug::NoLocking=true install dracut, sorted; nil when the simulation failed (plan M8e decision 33).
func simulatedRemovals(ctx context.Context, sys System) []string {
	pkgs, ok := simulateRemovals(ctx, sys)
	if !ok {
		return nil
	}
	return pkgs
}

// simulateRemovals is simulatedRemovals that tells a failed simulation (ok false) from an empty set.
func simulateRemovals(ctx context.Context, sys System) (pkgs []string, ok bool) {
	out, _, exit, err := sys.Command(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=true", "install", "dracut")
	if err != nil || exit != 0 {
		return nil, false
	}
	for line := range strings.Lines(out) {
		if rest, ok := strings.CutPrefix(line, "Remv "); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				pkgs = append(pkgs, f[0])
			}
		}
	}
	slices.Sort(pkgs)
	return slices.Compact(pkgs), true
}
