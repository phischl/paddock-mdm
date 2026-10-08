package reconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// The files and units of update management (plan M5b decision 5). The files are protected: a change is reverted at
// the next drift pass and reported as tamper.protected_file_changed.
const (
	// UnattendedConf restricts unattended-upgrades to the security pocket and blacklists the held packages; it sorts
	// after the distribution's 50unattended-upgrades and 20auto-upgrades, whose lists it clears.
	UnattendedConf = "/etc/apt/apt.conf.d/52paddock-unattended"
	// UpgradeTimerDropIn moves apt-daily-upgrade.timer, which runs unattended-upgrades, to security_daily_at.
	UpgradeTimerDropIn = "/etc/systemd/system/apt-daily-upgrade.timer.d/50-paddock.conf"
	// PinFile pins the packages held with a version.
	PinFile = "/etc/apt/preferences.d/50paddock"
	// RegularService and RegularTimer run `paddockd updates run` on regular_schedule.
	RegularService = "/etc/systemd/system/paddock-updates.service"
	RegularTimer   = "/etc/systemd/system/paddock-updates.timer"
	// RegularTimerUnit is the timer of regular updates.
	RegularTimerUnit = "paddock-updates.timer"
	// SecurityUnit is the service of apt-daily-upgrade.timer that runs unattended-upgrades.
	SecurityUnit = "apt-daily-upgrade.service"
	// heldRecord lists the packages Paddock holds with apt-mark, one per line: holds it did not set are left alone.
	heldRecord = "/var/lib/paddock/state/held-packages"
	// UnattendedPackage runs the daily security updates.
	UnattendedPackage = "unattended-upgrades"
	// UpdatesRunLimit bounds `paddockd updates run` (plan M5b decision 6); TimeoutStartSec leaves room for the agent's
	// process group kill.
	UpdatesRunLimit = "75min"
)

// aptTimers are the distribution's timers that refresh the package lists and run unattended-upgrades.
var aptTimers = []string{"apt-daily.timer", "apt-daily-upgrade.timer"}

// Updates configures daily security updates, regular updates and package holds (plan M5b decision 5).
type Updates struct {
	Sys    System
	Events *Events
	// applied is the spec of the last successful Apply: a file that differs from the same spec was changed outside
	// Paddock.
	applied []byte
}

// Type implements Reconciler.
func (u *Updates) Type() string { return bundle.TypeUpdates }

func (u *Updates) spec(r bundle.Resource) (bundle.UpdatesSpec, error) {
	var s bundle.UpdatesSpec
	if err := json.Unmarshal(r.Spec, &s); err != nil {
		return s, fmt.Errorf("invalid updates spec: %w", err)
	}
	return s, bundle.ValidateUpdates(s)
}

// updatesFile is a file of the updates resource; nil data means the file must not exist.
type updatesFile struct {
	path string
	data []byte
	unit string // the unit to restart when the file changed, "" for none
}

// updatesFiles renders the files of a spec.
func updatesFiles(s bundle.UpdatesSpec) []updatesFile {
	var blacklist, pins strings.Builder
	for _, h := range s.Holds {
		// Package-Blacklist entries are regular expressions; brackets keep the package name literal without
		// backslashes, which apt's configuration parser would interpret.
		name := strings.NewReplacer("+", "[+]", ".", "[.]").Replace(h.Package)
		fmt.Fprintf(&blacklist, "  \"^%s$\";\n", name)
		if h.Version != nil {
			fmt.Fprintf(&pins, "\nPackage: %s\nPin: version %s\nPin-Priority: 1001\n", h.Package, *h.Version)
		}
	}
	unattended := "//" + strings.TrimPrefix(managedHeader, "#") +
		"#clear Unattended-Upgrade::Allowed-Origins;\n#clear Unattended-Upgrade::Origins-Pattern;\n" +
		"#clear Unattended-Upgrade::Package-Blacklist;\n" +
		"Unattended-Upgrade::Allowed-Origins {\n  \"${distro_id}:${distro_codename}-security\";\n};\n" +
		"Unattended-Upgrade::Package-Blacklist {\n" + blacklist.String() + "};\n" +
		"Unattended-Upgrade::Automatic-Reboot \"false\";\n" +
		"APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
	delay := fmt.Sprintf("RandomizedDelaySec=%dm\n", s.MaxRandomDelayMin)
	dropIn := "# " + managedHeader + "\n[Timer]\nOnCalendar=\nOnCalendar=*-*-* " + s.SecurityDailyAt + "\n" + delay
	service := "# " + managedHeader + "\n[Unit]\nDescription=Paddock regular updates\n" +
		"After=network-online.target\nWants=network-online.target\n\n" +
		"[Service]\nType=oneshot\nExecStart=/opt/paddock/agent/current/paddockd updates run\nTimeoutStartSec=" + UpdatesRunLimit + "\n"
	timer := "# " + managedHeader + "\n[Unit]\nDescription=Paddock regular updates\n\n" +
		"[Timer]\nOnCalendar=" + s.RegularSchedule + "\n" + delay + "Persistent=true\n\n[Install]\nWantedBy=timers.target\n"
	var pinData []byte
	if pins.Len() > 0 {
		pinData = []byte(managedHeader + pins.String())
	}
	return []updatesFile{
		{path: UnattendedConf, data: []byte(unattended)},
		{path: UpgradeTimerDropIn, data: []byte(dropIn), unit: "apt-daily-upgrade.timer"},
		{path: PinFile, data: pinData},
		{path: RegularService, data: []byte(service)},
		{path: RegularTimer, data: []byte(timer), unit: RegularTimerUnit},
	}
}

func (u *Updates) fileIs(f updatesFile) bool {
	if f.data == nil {
		_, _, err := u.Sys.ReadFile(f.path)
		return errors.Is(err, fs.ErrNotExist)
	}
	return fileHas(u.Sys, f.path, f.data, 0o644)
}

// versionless returns the packages held without a version.
func versionless(s bundle.UpdatesSpec) []string {
	var out []string
	for _, h := range s.Holds {
		if h.Version == nil {
			out = append(out, h.Package)
		}
	}
	return out
}

// holdChanges compares the versionless holds with apt's holds and the record of the holds Paddock set: hold what is
// wanted and not held, unhold what Paddock held and is no longer wanted.
func (u *Updates) holdChanges(ctx context.Context, s bundle.UpdatesSpec) (hold, unhold []string, record bool, err error) {
	out, exit, err := u.Sys.AptMark(ctx, "showhold")
	if err != nil || exit != 0 {
		return nil, nil, false, fmt.Errorf("apt-mark showhold: exit %d %v", exit, err)
	}
	held := strings.Fields(out)
	wanted := versionless(s)
	recorded := u.recorded()
	for _, p := range wanted {
		if !slices.Contains(held, p) {
			hold = append(hold, p)
		}
	}
	for _, p := range recorded {
		if !slices.Contains(wanted, p) && slices.Contains(held, p) {
			unhold = append(unhold, p)
		}
	}
	return hold, unhold, !slices.Equal(recorded, wanted), nil
}

// recorded returns the packages Paddock held with apt-mark.
func (u *Updates) recorded() []string {
	data, _, err := u.Sys.ReadFile(heldRecord)
	if err != nil {
		return nil
	}
	return strings.Fields(string(data))
}

// unitPlan returns the unit changes: the distribution's apt timers enabled and active, the regular timer as the spec
// says. A regular timer whose file does not exist yet is planned as a change of its file only.
func (u *Updates) unitPlan(ctx context.Context, s bundle.UpdatesSpec) ([]string, error) {
	var changes []string
	for _, t := range aptTimers {
		c, err := unitChanges(ctx, u.Sys, t, true, true)
		if err != nil {
			return nil, err
		}
		changes = append(changes, c...)
	}
	if _, _, err := u.Sys.ReadFile(RegularTimer); errors.Is(err, fs.ErrNotExist) {
		return changes, nil
	}
	c, err := unitChanges(ctx, u.Sys, RegularTimerUnit, s.RegularUpdatesEnabled, s.RegularUpdatesEnabled)
	if err != nil {
		return nil, err
	}
	return append(changes, c...), nil
}

// Plan implements Reconciler.
func (u *Updates) Plan(ctx context.Context, r bundle.Resource) ([]string, error) {
	s, err := u.spec(r)
	if err != nil {
		return nil, err
	}
	var changes []string
	for _, f := range updatesFiles(s) {
		if !u.fileIs(f) {
			changes = append(changes, "file "+f.path)
		}
	}
	hold, unhold, record, err := u.holdChanges(ctx, s)
	if err != nil {
		return nil, err
	}
	for _, p := range hold {
		changes = append(changes, "apt-mark hold "+p)
	}
	for _, p := range unhold {
		changes = append(changes, "apt-mark unhold "+p)
	}
	if record && len(hold)+len(unhold) == 0 {
		changes = append(changes, "file "+heldRecord)
	}
	units, err := u.unitPlan(ctx, s)
	if err != nil {
		return nil, err
	}
	return append(changes, units...), nil
}

// Apply implements Reconciler: the files, then the holds, then the units. Without unattended-upgrades the rest is
// applied and the resource reports the missing package.
func (u *Updates) Apply(ctx context.Context, r bundle.Resource) Result {
	s, err := u.spec(r)
	if err != nil {
		return errorResult(r.ID, err)
	}
	changed, reload, restart, err := u.writeFiles(s, r.Spec)
	if err != nil {
		return errorResult(r.ID, err)
	}
	if reload {
		if err := run(ctx, u.Sys, []string{"systemctl daemon-reload"}); err != nil {
			return errorResult(r.ID, err)
		}
	}
	held, err := u.applyHolds(ctx, s)
	if err != nil {
		return errorResult(r.ID, err)
	}
	units, err := u.unitPlan(ctx, s)
	if err != nil {
		return errorResult(r.ID, err)
	}
	for _, unit := range restart {
		// A changed schedule takes effect when the timer starts again; a disabled regular timer stays stopped.
		if unit != RegularTimerUnit || s.RegularUpdatesEnabled {
			units = append(units, "systemctl restart "+unit)
		}
	}
	if err := run(ctx, u.Sys, units); err != nil {
		return errorResult(r.ID, err)
	}
	u.applied = bytes.Clone(r.Spec)
	if !u.Sys.PackageInstalled(UnattendedPackage) {
		return errorResult(r.ID, errors.New("unattended-upgrades is not installed: daily security updates do not run"))
	}
	if !changed && !held && len(units) == 0 {
		return Result{ID: r.ID, Status: OK}
	}
	return Result{ID: r.ID, Status: Changed}
}

// writeFiles writes the files that differ and reports whether systemd must reload its units and which timers to
// restart. A file that differs from the spec applied before was changed outside Paddock.
func (u *Updates) writeFiles(s bundle.UpdatesSpec, raw []byte) (changed, reload bool, restart []string, err error) {
	for _, f := range updatesFiles(s) {
		if u.fileIs(f) {
			continue
		}
		if bytes.Equal(u.applied, raw) {
			u.Events.emit(protocol.EventTamperProtectedFileChanged, protocol.TamperProtectedFileChanged{File: f.path})
		}
		if f.data == nil {
			err = u.Sys.Remove(f.path)
		} else {
			err = u.Sys.WriteFileAtomic(f.path, f.data, 0o644, 0, 0)
		}
		if err != nil {
			return changed, reload, restart, err
		}
		changed = true
		reload = reload || strings.HasPrefix(f.path, "/etc/systemd/")
		if f.unit != "" {
			restart = append(restart, f.unit)
		}
	}
	return changed, reload, restart, nil
}

// applyHolds holds and unholds packages with apt-mark and records the holds Paddock set.
func (u *Updates) applyHolds(ctx context.Context, s bundle.UpdatesSpec) (bool, error) {
	hold, unhold, record, err := u.holdChanges(ctx, s)
	if err != nil {
		return false, err
	}
	for verb, pkgs := range map[string][]string{"hold": hold, "unhold": unhold} {
		if len(pkgs) == 0 {
			continue
		}
		if out, exit, err := u.Sys.AptMark(ctx, append([]string{verb, "--"}, pkgs...)...); err != nil || exit != 0 {
			return false, fmt.Errorf("apt-mark %s: exit %d %v %s", verb, exit, err, strings.TrimSpace(out))
		}
	}
	if record || len(hold)+len(unhold) > 0 {
		data := []byte(strings.Join(versionless(s), "\n") + "\n")
		if err := u.Sys.WriteFileAtomic(heldRecord, data, 0o600, 0, 0); err != nil {
			return false, err
		}
	}
	return len(hold)+len(unhold) > 0, nil
}
