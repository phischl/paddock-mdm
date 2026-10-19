package uninstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/pkg/policy"
)

// Units Paddock runs, stopped first; the supervisor stops the agent with it.
var paddockUnits = []string{"paddock-supervisor.service", reconcile.RegularTimerUnit, "paddock-disk-setup.service"}

// stopServices stops and disables the supervisor (and with it the agent), the regular update timer and the disk
// setup. Only a supervisor that keeps running fails the step.
func (h *Helper) stopServices(ctx context.Context) string {
	var errs []string
	if err := h.run(ctx, "systemctl", "stop", paddockUnits[0]); err != nil {
		errs = append(errs, err.Error())
	}
	for _, args := range [][]string{{"disable", paddockUnits[0]}, {"stop", paddockUnits[1]}, {"stop", paddockUnits[2]},
		append([]string{"reset-failed"}, paddockUnits...)} {
		_ = h.run(ctx, "systemctl", args...)
	}
	if len(errs) > 0 {
		return failed("%s", strings.Join(errs, "; "))
	}
	return stepDone
}

// updateFiles are the update configuration Paddock wrote (plan M5b decision 5).
var updateFiles = []string{reconcile.PinFile, reconcile.UnattendedConf, reconcile.UpgradeTimerDropIn,
	reconcile.SecurityServiceDropIn, reconcile.RegularService, reconcile.RegularTimer}

// heldPackages lists the packages Paddock holds with apt-mark (reconcile.Updates).
const heldPackages = "/var/lib/paddock/state/held-packages"

// updateConfiguration releases Paddock's package holds and removes its update configuration.
func (h *Helper) updateConfiguration(ctx context.Context) string {
	var errs []string
	if data, err := os.ReadFile(h.path(heldPackages)); err == nil {
		if held := strings.Fields(string(data)); len(held) > 0 {
			if err := h.run(ctx, "apt-mark", append([]string{"unhold"}, held...)...); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	for _, f := range updateFiles {
		if err := h.remove(f); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if err := h.run(ctx, "systemctl", "daemon-reload"); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return failed("%s", strings.Join(errs, "; "))
	}
	return stepDone
}

// Paddock's sudoers files of directory users and the notices (plan M3b, M8x).
const (
	sudoersDir    = "/etc/sudoers.d"
	sudoersPrefix = "paddock-u-"
)

// sudoersAndNotices removes Paddock's sudoers files (one visudo check afterwards; a failing check restores the file
// removed last), the login deny list and the notices.
func (h *Helper) sudoersAndNotices(ctx context.Context) string {
	var errs []string
	entries, _ := os.ReadDir(h.path(sudoersDir))
	var last string
	var lastData []byte
	var lastMode fs.FileMode
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), sudoersPrefix) || !e.Type().IsRegular() {
			continue
		}
		file := filepath.Join(sudoersDir, e.Name())
		data, err := os.ReadFile(h.path(file))
		info, ierr := e.Info()
		if err != nil || ierr != nil {
			errs = append(errs, file+": unreadable")
			continue
		}
		if err := os.Remove(h.path(file)); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		last, lastData, lastMode = file, data, info.Mode().Perm()
	}
	if last != "" {
		if err := h.run(ctx, "visudo", "-c"); err != nil {
			errs = append(errs, err.Error())
			if werr := os.WriteFile(h.path(last), lastData, lastMode); werr != nil { //nolint:gosec // a paddock-u- file just read from sudoers.d
				errs = append(errs, "restore "+last+": "+werr.Error())
			}
		}
	}
	for _, f := range []string{reconcile.DenyList, reconcile.NoticeSSH, reconcile.NoticeIssue} {
		if err := h.remove(f); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if removed, err := h.removed(reconcile.NoticeSSHConfig); err != nil {
		errs = append(errs, err.Error())
	} else if removed {
		_ = h.run(ctx, "systemctl", "try-reload-or-restart", "ssh.service")
	}
	if removed, err := h.removed(reconcile.NoticeGDM); err != nil {
		errs = append(errs, err.Error())
	} else if removed {
		if err := h.run(ctx, "dconf", "update"); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return failed("%s", strings.Join(errs, "; "))
	}
	return stepDone
}

// quarantine holds the sudoers files the agent quarantined; nothing of it goes back to /etc/sudoers.d.
const quarantine = "/var/lib/paddock/quarantine"

// quarantineCopy keeps the quarantined files in ResultDir.
func (h *Helper) quarantineCopy() string {
	src := h.path(quarantine)
	if _, err := os.Stat(src); errors.Is(err, fs.ErrNotExist) {
		return stepSkipped
	}
	if err := copyTree(src, h.path(filepath.Join(ResultDir, "quarantine"))); err != nil {
		return failed("%v", err)
	}
	return stepDone
}

// managedFiles removes the files Paddock manages whose content is unchanged; changed files and files on a path the
// policy denies stay.
func (h *Helper) managedFiles(ctx context.Context) string {
	data, err := os.ReadFile(h.path("/var/lib/paddock/state/managed.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return stepSkipped
	}
	var m struct {
		Files map[string]string `json:"files"`
	}
	if err != nil || json.Unmarshal(data, &m) != nil {
		return failed("managed.json unreadable")
	}
	var errs []string
	for _, p := range slices.Sorted(func(yield func(string) bool) {
		for p := range m.Files {
			if !yield(p) {
				return
			}
		}
	}) {
		if policy.ValidatePath(p) != nil {
			continue
		}
		content, err := os.ReadFile(h.path(p))
		if err != nil {
			continue
		}
		if sum := sha256.Sum256(content); hex.EncodeToString(sum[:]) != m.Files[p] {
			continue
		}
		if err := os.Remove(h.path(p)); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if err := h.run(ctx, "systemctl", "daemon-reload"); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return failed("%s", strings.Join(errs, "; "))
	}
	return stepDone
}

// Himmelblau's caches and configuration; home directories of directory users are never touched.
var himmelblauPaths = []string{"/etc/himmelblau", "/var/cache/himmelblau", "/var/lib/himmelblau",
	"/etc/apt/sources.list.d/paddock-himmelblau.list", "/etc/apt/keyrings/himmelblau.gpg"}

// himmelblau purges the Himmelblau packages and removes their configuration and caches.
func (h *Helper) himmelblau(ctx context.Context) string {
	var errs []string
	if err := h.run(ctx, "apt-get", append([]string{"remove", "--purge", "-y"}, reconcile.HimmelblauPackages...)...); err != nil {
		errs = append(errs, err.Error())
	}
	for _, p := range himmelblauPaths {
		if err := os.RemoveAll(h.path(p)); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return failed("%s", strings.Join(errs, "; "))
	}
	return stepDone
}

// packages purges Paddock's packages and fleetd and removes what they leave. The helper runs from /run, so removing
// paddock-agent does not remove it.
func (h *Helper) packages(ctx context.Context) string {
	var errs []string
	if err := h.run(ctx, "apt-get", "remove", "--purge", "-y", reconcile.FleetdPackage, "paddock-revoke", "paddock-agent",
		"paddock-supervisor"); err != nil {
		errs = append(errs, err.Error())
	}
	for _, p := range []string{"/opt/orbit", reconcile.FleetdEnv, "/etc/systemd/system/orbit.service.d", "/opt/paddock",
		"/var/lib/paddock/packages", "/var/lib/paddock/staging", "/var/lib/paddock/rollback", quarantine} {
		if err := os.RemoveAll(h.path(p)); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return failed("%s", strings.Join(errs, "; "))
	}
	return stepDone
}

// remove deletes a file; a missing file is no error.
func (h *Helper) remove(p string) error {
	_, err := h.removed(p)
	return err
}

// removed deletes a file and reports whether it existed.
func (h *Helper) removed(p string) (bool, error) {
	err := os.Remove(h.path(p))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, err
}

// copyTree copies the regular files of a directory tree; directories are created 0700.
func copyTree(from, to string) error {
	return filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(to, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(dst, 0o700)
		case !d.Type().IsRegular():
			return nil
		}
		data, err := os.ReadFile(p) //nolint:gosec // below the quarantine directory
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o600) //nolint:gosec // below the quarantine directory
	})
}
