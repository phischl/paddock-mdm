package reconcile_test

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
)

func fileRes(t *testing.T, path, mode, owner, group, content string) bundle.Resource {
	t.Helper()
	r, err := bundle.FileResource(bundle.FileSpec{Path: path, Mode: mode, Owner: owner, Group: group, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func unitRes(t *testing.T, unit string, enabled, active bool) bundle.Resource {
	t.Helper()
	r, err := bundle.UnitResource(bundle.UnitSpec{Unit: unit, Enabled: enabled, Active: active})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func managed(t *testing.T) *reconcile.Managed {
	t.Helper()
	m, err := reconcile.LoadManaged(filepath.Join(t.TempDir(), "managed.json"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestFileOnFake(t *testing.T) {
	ctx := context.Background()
	sys := fakesys.New()
	f := &reconcile.File{Sys: sys, Managed: managed(t)}
	r := fileRes(t, "/etc/motd", "0644", "root", "adm", "hello\n")

	if changes, err := f.Plan(ctx, r); err != nil || !slices.Equal(changes, []string{"create"}) {
		t.Fatalf("plan on a missing file: %v, %v", changes, err)
	}
	if len(sys.TakeCalls()) != 0 {
		t.Fatal("Plan changed the system")
	}
	if res := f.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("first apply: %+v", res)
	}
	got := sys.Files["/etc/motd"]
	if string(got.Data) != "hello\n" || got.Mode != 0o644 || got.UID != 0 || got.GID != 4 {
		t.Fatalf("written file %+v", got)
	}
	if res := f.Apply(ctx, r); res.Status != reconcile.OK || len(sys.TakeCalls()) != 1 {
		t.Fatalf("second apply must be a no-op: %+v", res)
	}
	if f.Managed.Files["/etc/motd"] == "" {
		t.Fatal("written file not recorded in managed.json")
	}

	// Drift in each attribute is planned and corrected.
	for name, mutate := range map[string]func(*fakesys.File){
		"content": func(f *fakesys.File) { f.Data = []byte("local edit\n") },
		"mode":    func(f *fakesys.File) { f.Mode = 0o666 },
		"owner":   func(f *fakesys.File) { f.UID = 65534 },
		"group":   func(f *fakesys.File) { f.GID = 0 },
		"setuid":  func(f *fakesys.File) { f.Mode = 0o644 | os.ModeSetuid },
		"symlink": func(f *fakesys.File) { f.Symlink = true },
	} {
		mutate(sys.Files["/etc/motd"])
		if changes, _ := f.Plan(ctx, r); len(changes) == 0 {
			t.Errorf("%s drift not planned", name)
		}
		if res := f.Apply(ctx, r); res.Status != reconcile.Changed {
			t.Errorf("%s drift: %+v", name, res)
		}
		if changes, _ := f.Plan(ctx, r); len(changes) != 0 {
			t.Errorf("%s drift not corrected: %v", name, changes)
		}
	}
}

func TestFileRefusesPolicyViolations(t *testing.T) {
	sys := fakesys.New()
	f := &reconcile.File{Sys: sys, Managed: managed(t)}
	bad := []bundle.Resource{
		fileRes(t, "/etc/sudoers.d/evil", "0440", "root", "root", "x"),
		fileRes(t, "/etc/paddock/agent.yml", "0644", "root", "root", "x"),
		fileRes(t, "/var/tmp/x", "0644", "root", "root", "x"),
		fileRes(t, "/etc/x", "4755", "root", "root", "x"),
		fileRes(t, "/etc/x", "0644", "ghost", "root", "x"),
	}
	tampered := fileRes(t, "/etc/x", "0644", "root", "root", "x")
	tampered.Spec = []byte(strings.Replace(string(tampered.Spec), `"content":"x"`, `"content":"y"`, 1))
	bad = append(bad, tampered)
	for _, r := range bad {
		if res := f.Apply(context.Background(), r); res.Status != reconcile.Error {
			t.Errorf("%s: %+v", r.Spec, res)
		}
	}
	if len(sys.TakeCalls()) != 0 {
		t.Fatal("a refused resource changed the system")
	}
}

func TestFileRemove(t *testing.T) {
	ctx := context.Background()
	sys := fakesys.New()
	f := &reconcile.File{Sys: sys, Managed: managed(t)}
	for _, p := range []string{"/etc/a", "/etc/b"} {
		f.Apply(ctx, fileRes(t, p, "0644", "root", "root", "managed\n"))
	}
	sys.Files["/etc/b"].Data = []byte("changed locally\n")
	if err := f.Remove("/etc/a"); err != nil {
		t.Fatalf("remove unmodified: %v", err)
	}
	if _, ok := sys.Files["/etc/a"]; ok {
		t.Fatal("unmodified file not deleted")
	}
	if err := f.Remove("/etc/b"); !errors.Is(err, reconcile.ErrModified) {
		t.Fatalf("remove modified: %v", err)
	}
	if _, ok := sys.Files["/etc/b"]; !ok {
		t.Fatal("modified file deleted")
	}
	if len(f.Managed.Files) != 0 {
		t.Fatalf("managed.json still lists %v", f.Managed.Paths())
	}
	// A file Paddock never wrote is never deleted.
	sys.Files["/etc/c"] = &fakesys.File{Data: []byte("x"), Mode: 0o644}
	if err := f.Remove("/etc/c"); err != nil || sys.Files["/etc/c"] == nil {
		t.Fatalf("unmanaged file: %v", err)
	}
}

// TestFileOnDisk runs the real OS port in a temporary root: atomic write, parent directories, mode, idempotency.
func TestFileOnDisk(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(me.Gid)
	if err != nil {
		t.Fatal(err)
	}
	sys := reconcile.OS{Root: root}
	f := &reconcile.File{Sys: sys, Managed: managed(t)}
	r := fileRes(t, "/etc/paddock-test/sub/app.conf", "0640", me.Username, group.Name, "key = value\n")
	if res := f.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply: %+v", res)
	}
	full := filepath.Join(root, "etc/paddock-test/sub/app.conf")
	fi, err := os.Stat(full)
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("file %v, %v", fi, err)
	}
	if di, _ := os.Stat(filepath.Dir(full)); di.Mode().Perm() != 0o755 {
		t.Fatalf("parent directory mode %v", di.Mode().Perm())
	}
	if res := f.Apply(ctx, r); res.Status != reconcile.OK {
		t.Fatalf("second apply: %+v", res)
	}
	if err := os.WriteFile(full, []byte("edited"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(full, 0o600); err != nil {
		t.Fatal(err)
	}
	if changes, _ := f.Plan(ctx, r); len(changes) != 2 {
		t.Fatalf("planned %v, want content and mode", changes)
	}
	if res := f.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("drift apply: %+v", res)
	}
	data, _ := os.ReadFile(full)
	entries, _ := os.ReadDir(filepath.Dir(full))
	if string(data) != "key = value\n" || len(entries) != 1 {
		t.Fatalf("content %q, %d entries (temporary files left?)", data, len(entries))
	}
	if err := f.Remove("/etc/paddock-test/sub/app.conf"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(full); !os.IsNotExist(err) {
		t.Fatal("not removed")
	}
}

func TestUnit(t *testing.T) {
	ctx := context.Background()
	sys := fakesys.New()
	sys.Units["cups.service"] = &fakesys.Unit{State: "disabled"}
	sys.Units["backup.timer"] = &fakesys.Unit{State: "enabled", Active: true}
	sys.Units["static.service"] = &fakesys.Unit{State: "static"}
	sys.Units["masked.service"] = &fakesys.Unit{State: "masked"}
	u := &reconcile.Unit{Sys: sys}

	start := unitRes(t, "cups.service", true, true)
	if changes, _ := u.Plan(ctx, start); !slices.Equal(changes, []string{"systemctl enable cups.service", "systemctl start cups.service"}) {
		t.Fatalf("plan %v", changes)
	}
	if res := u.Apply(ctx, start); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if res := u.Apply(ctx, start); res.Status != reconcile.OK {
		t.Fatalf("second apply %+v", res)
	}
	stop := unitRes(t, "backup.timer", false, false)
	u.Apply(ctx, stop)
	if sys.Units["backup.timer"].State != "disabled" || sys.Units["backup.timer"].Active {
		t.Fatalf("not stopped and disabled: %+v", sys.Units["backup.timer"])
	}
	if res := u.Apply(ctx, unitRes(t, "static.service", true, false)); res.Status != reconcile.OK {
		t.Fatalf("a static unit counts as enabled: %+v", res)
	}
	for _, r := range []bundle.Resource{
		unitRes(t, "ghost.service", true, true),                // unknown
		unitRes(t, "masked.service", true, true),               // masked
		unitRes(t, "paddock-supervisor.service", false, false), // protected (defence in depth)
		unitRes(t, "ssh.service", false, false),
	} {
		if res := u.Apply(ctx, r); res.Status != reconcile.Error {
			t.Errorf("%s: %+v", r.ID, res)
		}
	}
	sys.Units["fails.service"] = &fakesys.Unit{State: "enabled"}
	sys.FailCmd = "systemctl start fails.service"
	if res := u.Apply(ctx, unitRes(t, "fails.service", true, true)); res.Status != reconcile.Error || !strings.Contains(res.Message, "exit 1") {
		t.Fatalf("failing start: %+v", res)
	}
}

func TestTime(t *testing.T) {
	ctx := context.Background()
	r, _ := bundle.TimeResource(bundle.TimeSpec{NTP: true})
	tm := func(sys *fakesys.System) *reconcile.Time { return &reconcile.Time{Sys: sys} }

	chrony := fakesys.New()
	chrony.Packages["chrony"] = true
	chrony.Packages["systemd-timesyncd"] = true
	chrony.Units["chrony.service"] = &fakesys.Unit{State: "disabled"}
	if res := tm(chrony).Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("chrony: %+v", res)
	}
	if calls := chrony.TakeCalls(); !slices.Equal(calls, []string{"systemctl enable chrony.service", "systemctl start chrony.service"}) {
		t.Fatalf("chrony calls %v", calls)
	}
	if res := tm(chrony).Apply(ctx, r); res.Status != reconcile.OK {
		t.Fatalf("chrony second apply: %+v", res)
	}

	timesyncd := fakesys.New()
	timesyncd.Packages["systemd-timesyncd"] = true
	timesyncd.Units["systemd-timesyncd.service"] = &fakesys.Unit{State: "enabled", Active: true}
	if res := tm(timesyncd).Apply(ctx, r); res.Status != reconcile.Changed || !timesyncd.NTP {
		t.Fatalf("timesyncd: %+v", res)
	}
	if res := tm(timesyncd).Apply(ctx, r); res.Status != reconcile.OK {
		t.Fatalf("timesyncd second apply: %+v", res)
	}

	if res := tm(fakesys.New()).Apply(ctx, r); res.Status != reconcile.Error {
		t.Fatalf("no NTP client: %+v", res)
	}
	off, _ := bundle.TimeResource(bundle.TimeSpec{NTP: false})
	if res := tm(fakesys.New()).Apply(ctx, off); res.Status != reconcile.OK {
		t.Fatalf("ntp false is left alone: %+v", res)
	}
}
