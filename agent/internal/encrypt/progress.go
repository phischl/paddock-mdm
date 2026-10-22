package encrypt

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// Why the background phase does not advance (health.disk.conversion.paused_reason, plan M8e decisions 21 and 22).
const (
	PausedOnBattery        = "on_battery"
	PausedHelperNotRunning = "helper_not_running"
	// PausedPackagesBusy: the preparation waits for a package run holding dpkg's locks.
	PausedPackagesBusy = "packages_busy"
)

// Why the initrd work of a conversion cannot go on (health.disk.conversion.initrd_issue, plan M8e amendment
// 2026-10-21, item 19).
const (
	IssueBootSpaceLow     = "boot_space_low"
	IssueNoBootableKernel = "no_bootable_kernel"
	// IssueOrphanInitrdRemoved: a cleanup removed the initrd of a kernel without modules that carried the module.
	IssueOrphanInitrdRemoved = "orphan_initrd_removed"
	// IssueKernelNotBuildable: a bootable kernel has modules.dep.bin only; dracut cannot build its initrd.
	IssueKernelNotBuildable = "kernel_not_buildable"
	// IssueKeyMaterialHardlinked: an initrd that may carry the conversion key has a hard link outside the initrds
	// Paddock lists; it is neither overwritten nor removed until that link is gone.
	IssueKeyMaterialHardlinked = "key_material_hardlinked"
	// IssueKeyMaterialSharedBootable: a bootable kernel's initrd is a symlink to a file that may carry the conversion
	// key; it stays (with initrd_issue_kernel) until that kernel's verified rebuild replaces the link.
	IssueKeyMaterialSharedBootable = "key_material_shared_bootable"
)

// Outcomes of the background phase (result.json).
const (
	OutcomeCompleted = "completed"
	OutcomeFailed    = "failed"
)

// Progress is progress.json (plan M8e §6.3), the background phase's last reported position.
type Progress struct {
	DoneBytes    int64     `json:"done_bytes"`
	DataBytes    int64     `json:"data_bytes"`
	SpeedBPS     int64     `json:"speed_bps"`
	ETASeconds   int64     `json:"eta_s"`
	PausedReason string    `json:"paused_reason,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Result is result.json (plan M8e §6.3): how the background phase ended.
type Result struct {
	Outcome    string    `json:"outcome"`
	Reason     string    `json:"reason,omitempty"`
	DataBytes  int64     `json:"data_bytes"`
	DurationS  int64     `json:"duration_s"`
	FinishedAt time.Time `json:"finished_at"`
}

// ParseProgress reads one line of cryptsetup reencrypt --progress-json, for example
// {"device_bytes":"8192","device_size":"44040192","speed":"126877696","eta_ms":"2520012"}: cryptsetup writes the
// numbers as strings, plain numbers are accepted as well. ok is false for any other line.
func ParseProgress(line string) (p Progress, ok bool) {
	var raw struct {
		DeviceBytes json.RawMessage `json:"device_bytes"`
		DeviceSize  json.RawMessage `json:"device_size"`
		Speed       json.RawMessage `json:"speed"`
		ETAMs       json.RawMessage `json:"eta_ms"`
	}
	if !strings.HasPrefix(strings.TrimSpace(line), "{") || json.Unmarshal([]byte(line), &raw) != nil {
		return Progress{}, false
	}
	done, ok1 := jsonInt(raw.DeviceBytes)
	size, ok2 := jsonInt(raw.DeviceSize)
	if !ok1 || !ok2 {
		return Progress{}, false
	}
	speed, _ := jsonInt(raw.Speed)
	eta, _ := jsonInt(raw.ETAMs)
	return Progress{DoneBytes: done, DataBytes: size, SpeedBPS: speed, ETASeconds: eta / 1000}, true
}

// jsonInt is a non-negative integer written as a JSON string or number.
func jsonInt(raw json.RawMessage) (int64, bool) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n >= 0
}

// ReadProgress reads progress.json; nil without one.
func ReadProgress(l paths.Layout) (*Progress, error) {
	var p Progress
	if ok, err := readJSON(l.EncryptProgress(), &p); !ok {
		return nil, err
	}
	return &p, nil
}

// ReadResult reads result.json; nil without one.
func ReadResult(l paths.Layout) (*Result, error) {
	var r Result
	if ok, err := readJSON(l.EncryptResult(), &r); !ok {
		return nil, err
	}
	return &r, nil
}

// RemoveProgress removes progress.json and result.json — and nothing else of the conversion (plan M8e decision 22,
// invariant I1: plan.env, the module and its configuration stay until the initrd regeneration).
func RemoveProgress(l paths.Layout) error {
	for _, p := range []string{l.EncryptProgress(), l.EncryptResult()} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// RemoveResult removes result.json once the agent recorded it.
func RemoveResult(l paths.Layout) error {
	if err := os.Remove(l.EncryptResult()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func writeProgress(l paths.Layout, p Progress) error { return writeJSON(l.EncryptProgress(), p) }

func writeResult(l paths.Layout, r Result) error { return writeJSON(l.EncryptResult(), r) }

// readJSON decodes path into v; false without the file or on an error.
func readJSON(path string, v any) (bool, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // a data file of the layout
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return false, fmt.Errorf("parse %s: %w", path, err)
	}
	return true, nil
}

// writeJSON writes v atomically (0600 in the 0700 directory of the conversion).
func writeJSON(path string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return fsutil.WriteFile(path, raw, 0o600, 0o700)
}
