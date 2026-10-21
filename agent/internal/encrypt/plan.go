package encrypt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// Sizes of plan M8e decision 17.
const (
	// HeaderBytes is the room the LUKS2 header takes at the start of the partition (--reduce-device-size 32M).
	HeaderBytes = 32 << 20
	// plainMarginBytes is what a plain layout's file system gives up: the header and as much again of headroom.
	plainMarginBytes = 64 << 20
	// lvmMarginExtents is what the root LV gives up, in extents of its VG.
	lvmMarginExtents = 16
)

// Plan is /var/lib/paddock/encrypt/plan.json (plan M8e §6.3): what the init step converts and how. It holds no secret.
type Plan struct {
	ConversionID     string    `json:"conversion_id"`
	Layout           string    `json:"layout"`
	Partition        string    `json:"partition"`
	PartUUID         string    `json:"part_uuid"`
	LUKSUUID         string    `json:"luks_uuid"`
	Mapping          string    `json:"mapping"`
	VG               string    `json:"vg,omitempty"`
	LV               string    `json:"lv,omitempty"`
	FSUUID           string    `json:"fs_uuid"`
	FSTargetBytes    int64     `json:"fs_target_bytes"`
	PVTargetBytes    int64     `json:"pv_target_bytes"`
	DataBytes        int64     `json:"data_bytes"`
	UnlockMode       string    `json:"unlock_mode"`
	BootPINMinLength int       `json:"boot_pin_min_length"`
	CreatedAt        time.Time `json:"created_at"`
}

// envValue is the charset of every plan.env value: the init script sources the file (plan M8e §6.3).
var envValue = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Env renders the shell form of the plan, plan.env; it fails when a value is outside the safe charset.
func (p Plan) Env() ([]byte, error) {
	vars := [][2]string{
		{"PADDOCK_LAYOUT", p.Layout}, {"PADDOCK_PART_UUID", p.PartUUID}, {"PADDOCK_LUKS_UUID", p.LUKSUUID},
		{"PADDOCK_MAPPING", p.Mapping}, {"PADDOCK_VG", p.VG}, {"PADDOCK_LV", p.LV}, {"PADDOCK_FS_UUID", p.FSUUID},
		{"PADDOCK_FS_TARGET_BYTES", strconv.FormatInt(p.FSTargetBytes, 10)},
		{"PADDOCK_FS_TARGET_SECTORS", strconv.FormatInt(p.FSTargetBytes/512, 10)},
		{"PADDOCK_PV_TARGET_BYTES", strconv.FormatInt(p.PVTargetBytes, 10)},
	}
	var b strings.Builder
	for _, v := range vars {
		optional := (v[0] == "PADDOCK_VG" || v[0] == "PADDOCK_LV") && p.Layout == KindPlain
		if v[1] == "" && optional {
			b.WriteString(v[0] + "=\n")
			continue
		}
		if !envValue.MatchString(v[1]) {
			return nil, fmt.Errorf("plan value %s=%q is not in [A-Za-z0-9_.-]", v[0], v[1])
		}
		b.WriteString(v[0] + "=" + v[1] + "\n")
	}
	return []byte(b.String()), nil
}

// ReadPlan reads plan.json; nil without one.
func ReadPlan(l paths.Layout) (*Plan, error) {
	raw, err := os.ReadFile(l.EncryptPlan())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p Plan
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", l.EncryptPlan(), err)
	}
	return &p, nil
}

// writePlan writes plan.json (0600 in a 0700 directory).
func writePlan(l paths.Layout, p Plan) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return fsutil.WriteFile(l.EncryptPlan(), raw, 0o600, 0o700)
}

// targets fills the sizes of decision 17 into p: P from blockdev, the LV size and the VG's extent size from lvm. The
// preflight guarantees that the PV's last allocated segment belongs to the root LV (reason pv_tail_in_use).
func targets(ctx context.Context, sys System, p *Plan) error {
	partBytes, err := bytesOf(ctx, sys, "blockdev", "--getsize64", p.Partition)
	if err != nil {
		return err
	}
	p.PVTargetBytes, p.DataBytes = partBytes-HeaderBytes, partBytes-HeaderBytes
	if p.Layout == KindPlain {
		p.FSTargetBytes = partBytes - plainMarginBytes
		return nil
	}
	lvBytes, err := bytesOf(ctx, sys, "lvm", "lvs", "--noheadings", "--units", "b", "--nosuffix", "-o", "lv_size", "/dev/"+p.VG+"/"+p.LV)
	if err != nil {
		return err
	}
	extent, err := bytesOf(ctx, sys, "lvm", "vgs", "--noheadings", "--units", "b", "--nosuffix", "-o", "vg_extent_size", p.VG)
	if err != nil {
		return err
	}
	p.FSTargetBytes = lvBytes - lvmMarginExtents*extent
	return nil
}

// bytesOf runs a tool that prints one byte count (lvm's "B" suffix tolerated).
func bytesOf(ctx context.Context, sys System, name string, args ...string) (int64, error) {
	out, stderr, exit, err := sys.Command(ctx, name, args...)
	if err == nil && exit != 0 {
		err = fmt.Errorf("%s: exit %d: %s", name, exit, firstLine(stderr))
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(out), "B"), 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: unexpected size %q", name, strings.TrimSpace(out))
	}
	return n, nil
}

// firstLine is the first non-empty line of s, cut at 200 runes (the bound of a failure reason, plan M8e decision 13).
func firstLine(s string) string {
	for line := range strings.Lines(s) {
		if line = strings.TrimSpace(line); line != "" {
			return cut(line)
		}
	}
	return ""
}

// cut bounds a reason at 200 runes.
func cut(s string) string {
	if r := []rune(s); len(r) > 200 {
		return string(r[:200])
	}
	return s
}
