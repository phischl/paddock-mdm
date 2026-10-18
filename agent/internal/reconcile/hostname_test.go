package reconcile_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
)

const ubuntuHosts = "127.0.0.1 localhost\n127.0.1.1 old\n\n# The following lines are desirable for IPv6 capable hosts\n" +
	"::1     ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff02::1 ip6-allnodes\n"

// hostnameFixture is a device named lap-0421 everywhere; managed reports whether /etc/hosts is a managed file.
func hostnameFixture(t *testing.T) (*fakesys.System, *reconcile.Hostname, *bool) {
	t.Helper()
	sys := fakesys.New()
	sys.Hostnames = fakesys.Hostnames{Static: "lap-0421", Transient: "lap-0421", Pretty: "lap-0421"}
	sys.Files[reconcile.HostsFile] = &fakesys.File{Data: []byte("127.0.0.1 localhost\n127.0.1.1\tlap-0421\n"), Mode: 0o644}
	managed := false
	return sys, &reconcile.Hostname{Sys: sys, HostsManaged: func() bool { return managed }, State: &reconcile.HostnameState{}}, &managed
}

func hostnameResource(t *testing.T, name string) bundle.Resource {
	t.Helper()
	r, err := bundle.HostnameResource(bundle.HostnameSpec{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestHostnameInSync(t *testing.T) {
	sys, h, _ := hostnameFixture(t)
	r := hostnameResource(t, "lap-0421")
	if changes, err := h.Plan(context.Background(), r); err != nil || len(changes) != 0 {
		t.Fatalf("plan %v, %v", changes, err)
	}
	if res := h.Apply(context.Background(), r); res.Status != reconcile.OK || len(sys.Calls) != 0 {
		t.Fatalf("apply %+v, calls %v", res, sys.Calls)
	}
}

// TestHostnameConverges: hostnamectl clears the pretty name when it sets a valid host name, so an empty pretty name
// is in sync and the passes after a rename change nothing (review 1 finding 1).
func TestHostnameConverges(t *testing.T) {
	sys, h, _ := hostnameFixture(t)
	sys.Hostnames = fakesys.Hostnames{Static: "lap-0421", Transient: "lap-0421"}
	r := hostnameResource(t, "lap-0421")
	if changes, err := h.Plan(context.Background(), r); err != nil || len(changes) != 0 {
		t.Fatalf("plan with an empty pretty name %v, %v", changes, err)
	}
	sys.Hostnames = fakesys.Hostnames{Static: "local", Transient: "local", Pretty: "local"}
	if res := h.Apply(context.Background(), r); res.Status != reconcile.Changed {
		t.Fatalf("rename %+v", res)
	}
	for pass := range 2 {
		if res := h.Apply(context.Background(), r); res.Status != reconcile.OK {
			t.Fatalf("pass %d after the rename %+v, names %+v", pass+1, res, sys.Hostnames)
		}
	}
	if !slices.Equal(sys.Calls, []string{"hostnamectl hostname lap-0421"}) {
		t.Fatalf("calls %v", sys.Calls)
	}
}

// TestHostnamePrettyDiffers: a pretty name of its own renames like a differing static or transient name, and the
// rename leaves the pretty name empty.
func TestHostnamePrettyDiffers(t *testing.T) {
	sys, h, _ := hostnameFixture(t)
	sys.Hostnames.Pretty = "Phillip's laptop"
	r := hostnameResource(t, "lap-0421")
	if changes, err := h.Plan(context.Background(), r); err != nil || !slices.Equal(changes, []string{"hostnamectl hostname lap-0421"}) {
		t.Fatalf("plan %v, %v", changes, err)
	}
	if res := h.Apply(context.Background(), r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if !slices.Equal(sys.Calls, []string{"hostnamectl hostname lap-0421"}) ||
		sys.Hostnames != (fakesys.Hostnames{Static: "lap-0421", Transient: "lap-0421"}) {
		t.Fatalf("calls %v, names %+v", sys.Calls, sys.Hostnames)
	}
}

// TestHostnameHostsFile: the 127.0.1.1 line is replaced in place, inserted after 127.0.0.1, appended, or the file
// is created; every other byte stays.
func TestHostnameHostsFile(t *testing.T) {
	for _, c := range []struct {
		name, before, want string
		absent             bool
	}{
		{name: "replaced", before: ubuntuHosts, want: strings.Replace(ubuntuHosts, "127.0.1.1 old\n", "127.0.1.1 lap-0421\n", 1)},
		{name: "first of two", before: "127.0.1.1 old a\n# x\n127.0.1.1 other\n", want: "127.0.1.1 lap-0421 a\n# x\n127.0.1.1 other\n"},
		// Only the first host name changes; aliases, a comment and the line ending stay (review 1 finding 3).
		{name: "aliases kept", before: "  127.0.1.1\told.corp.example  old alias # x\r\n::1 ip6-localhost\n",
			want: "  127.0.1.1\tlap-0421  old alias # x\r\n::1 ip6-localhost\n"},
		{name: "address only", before: "127.0.1.1\n", want: "127.0.1.1\tlap-0421\n"},
		{name: "address and comment", before: "127.0.1.1 # x", want: "127.0.1.1 lap-0421 # x"},
		{name: "commented line is no entry", before: "#127.0.1.1 old\n127.0.0.1 localhost\n::1 ip6-localhost\n",
			want: "#127.0.1.1 old\n127.0.0.1 localhost\n127.0.1.1\tlap-0421\n::1 ip6-localhost\n"},
		{name: "inserted after an unterminated 127.0.0.1", before: "127.0.0.1 localhost", want: "127.0.0.1 localhost\n127.0.1.1\tlap-0421\n"},
		{name: "appended", before: "::1 ip6-localhost\n10.0.0.5 intranet", want: "::1 ip6-localhost\n10.0.0.5 intranet\n127.0.1.1\tlap-0421\n"},
		{name: "created", absent: true, want: "127.0.0.1\tlocalhost\n127.0.1.1\tlap-0421\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			sys, h, _ := hostnameFixture(t)
			if c.absent {
				delete(sys.Files, reconcile.HostsFile)
			} else {
				sys.Files[reconcile.HostsFile] = &fakesys.File{Data: []byte(c.before), Mode: 0o644}
			}
			r := hostnameResource(t, "lap-0421")
			changes, err := h.Plan(context.Background(), r)
			if err != nil || !slices.Equal(changes, []string{"write /etc/hosts 127.0.1.1 lap-0421"}) {
				t.Fatalf("plan %v, %v", changes, err)
			}
			if res := h.Apply(context.Background(), r); res.Status != reconcile.Changed {
				t.Fatalf("apply %+v", res)
			}
			f := sys.Files[reconcile.HostsFile]
			if string(f.Data) != c.want || f.Mode != 0o644 || f.UID != 0 || f.GID != 0 {
				t.Fatalf("hosts %q mode %v owner %d:%d, want %q", f.Data, f.Mode, f.UID, f.GID, c.want)
			}
			if changes, err := h.Plan(context.Background(), r); err != nil || len(changes) != 0 {
				t.Fatalf("plan after apply %v, %v", changes, err)
			}
		})
	}
}

// TestHostnameHostsManaged: a bundle that manages /etc/hosts as a file owns the 127.0.1.1 line (ADR 0041 decision 6).
func TestHostnameHostsManaged(t *testing.T) {
	sys, h, managed := hostnameFixture(t)
	*managed = true
	sys.Hostnames.Static = "other"
	sys.Files[reconcile.HostsFile] = &fakesys.File{Data: []byte(ubuntuHosts), Mode: 0o644}
	r := hostnameResource(t, "lap-0421")
	if changes, err := h.Plan(context.Background(), r); err != nil || !slices.Equal(changes, []string{"hostnamectl hostname lap-0421"}) {
		t.Fatalf("plan %v, %v", changes, err)
	}
	if res := h.Apply(context.Background(), r); res.Status != reconcile.Changed || string(sys.Files[reconcile.HostsFile].Data) != ubuntuHosts {
		t.Fatalf("apply %+v, hosts %q", res, sys.Files[reconcile.HostsFile].Data)
	}
}

// TestHostnameAvahi: a running avahi-daemon is restarted after a rename; a stopped one is left alone; a failing
// restart is the resource's error and the name stays set.
func TestHostnameAvahi(t *testing.T) {
	r := hostnameResource(t, "lap-0421")
	t.Run("active", func(t *testing.T) {
		sys, h, _ := hostnameFixture(t)
		sys.Hostnames.Transient = "other"
		sys.Units["avahi-daemon.service"] = &fakesys.Unit{State: "enabled", Active: true}
		if res := h.Apply(context.Background(), r); res.Status != reconcile.Changed ||
			!slices.Equal(sys.Calls, []string{"hostnamectl hostname lap-0421", "systemctl restart avahi-daemon.service"}) {
			t.Fatalf("apply %+v, calls %v", res, sys.Calls)
		}
	})
	t.Run("inactive", func(t *testing.T) {
		sys, h, _ := hostnameFixture(t)
		sys.Hostnames.Transient = "other"
		sys.Units["avahi-daemon.service"] = &fakesys.Unit{State: "enabled"}
		if res := h.Apply(context.Background(), r); res.Status != reconcile.Changed || !slices.Equal(sys.Calls, []string{"hostnamectl hostname lap-0421"}) {
			t.Fatalf("apply %+v, calls %v", res, sys.Calls)
		}
	})
	t.Run("hosts only", func(t *testing.T) {
		sys, h, _ := hostnameFixture(t)
		sys.Files[reconcile.HostsFile] = &fakesys.File{Data: []byte(ubuntuHosts), Mode: 0o644}
		sys.Units["avahi-daemon.service"] = &fakesys.Unit{State: "enabled", Active: true}
		if res := h.Apply(context.Background(), r); res.Status != reconcile.Changed || !slices.Equal(sys.Calls, []string{"write /etc/hosts"}) {
			t.Fatalf("apply %+v, calls %v", res, sys.Calls)
		}
	})
	t.Run("restart fails", func(t *testing.T) {
		sys, h, _ := hostnameFixture(t)
		sys.Hostnames.Transient = "other"
		sys.Units["avahi-daemon.service"] = &fakesys.Unit{State: "enabled", Active: true}
		sys.FailCmd = "systemctl restart avahi-daemon.service"
		res := h.Apply(context.Background(), r)
		if res.Status != reconcile.Error || !strings.Contains(res.Message, "avahi-daemon restart failed") || sys.Hostnames.Transient != "lap-0421" {
			t.Fatalf("apply %+v, names %+v", res, sys.Hostnames)
		}
	})
	// The names are in sync after a failed restart; the next pass still retries it until it succeeds (review 1
	// finding 2).
	t.Run("restart retried", func(t *testing.T) {
		sys, h, _ := hostnameFixture(t)
		sys.Hostnames.Transient = "other"
		sys.Units["avahi-daemon.service"] = &fakesys.Unit{State: "enabled", Active: true}
		sys.FailCmd = "systemctl restart avahi-daemon.service"
		if res := h.Apply(context.Background(), r); res.Status != reconcile.Error {
			t.Fatalf("apply %+v", res)
		}
		want := []string{"systemctl restart avahi-daemon.service"}
		for range 2 {
			if changes, err := h.Plan(context.Background(), r); err != nil || !slices.Equal(changes, want) {
				t.Fatalf("plan after the failed restart %v, %v", changes, err)
			}
			if res := h.Apply(context.Background(), r); res.Status != reconcile.Error {
				t.Fatalf("retry while failing %+v", res)
			}
		}
		sys.FailCmd = ""
		sys.Calls = nil
		if res := h.Apply(context.Background(), r); res.Status != reconcile.Changed || !slices.Equal(sys.Calls, want) {
			t.Fatalf("retry %+v, calls %v", res, sys.Calls)
		}
		if changes, err := h.Plan(context.Background(), r); err != nil || len(changes) != 0 {
			t.Fatalf("plan after the restart %v, %v", changes, err)
		}
	})
	// A failing /etc/hosts write does not keep Avahi on the old name; both errors are reported.
	t.Run("hosts write fails", func(t *testing.T) {
		sys, h, _ := hostnameFixture(t)
		sys.Hostnames.Transient = "other"
		sys.Files[reconcile.HostsFile] = &fakesys.File{Data: []byte(ubuntuHosts), Mode: 0o644}
		sys.Units["avahi-daemon.service"] = &fakesys.Unit{State: "enabled", Active: true}
		h.Sys = failingWrite{sys}
		res := h.Apply(context.Background(), r)
		if res.Status != reconcile.Error || !strings.Contains(res.Message, "read-only file system") ||
			!slices.Equal(sys.Calls, []string{"hostnamectl hostname lap-0421", "systemctl restart avahi-daemon.service"}) {
			t.Fatalf("apply %+v, calls %v", res, sys.Calls)
		}
		sys.FailCmd = "systemctl restart avahi-daemon.service"
		sys.Hostnames.Transient = "other"
		res = h.Apply(context.Background(), r)
		if res.Status != reconcile.Error || !strings.Contains(res.Message, "read-only file system") ||
			!strings.Contains(res.Message, "avahi-daemon restart failed") {
			t.Fatalf("apply with both failing %+v", res)
		}
	})
}

// TestHostnameErrors: a refused rename leaves /etc/hosts alone; an invalid spec and an unavailable hostnamed are
// errors of the resource.
func TestHostnameErrors(t *testing.T) {
	t.Run("rename refused", func(t *testing.T) {
		sys, h, _ := hostnameFixture(t)
		sys.Hostnames.Static = "other"
		sys.Files[reconcile.HostsFile] = &fakesys.File{Data: []byte(ubuntuHosts), Mode: 0o644}
		sys.FailCmd = "hostnamectl hostname lap-0421"
		res := h.Apply(context.Background(), hostnameResource(t, "lap-0421"))
		if res.Status != reconcile.Error || !strings.Contains(res.Message, "Access denied") ||
			string(sys.Files[reconcile.HostsFile].Data) != ubuntuHosts {
			t.Fatalf("apply %+v, hosts %q", res, sys.Files[reconcile.HostsFile].Data)
		}
	})
	t.Run("invalid spec", func(t *testing.T) {
		sys, h, _ := hostnameFixture(t)
		for _, spec := range []string{`{"name":"Lap"}`, `{"name":"localhost"}`, `{"name":""}`, `{`} {
			r := bundle.Resource{ID: bundle.TypeHostname, Type: bundle.TypeHostname, Spec: json.RawMessage(spec)}
			if res := h.Apply(context.Background(), r); res.Status != reconcile.Error || !strings.Contains(res.Message, "invalid hostname spec") {
				t.Fatalf("%s: %+v", spec, res)
			}
		}
		if len(sys.Calls) != 0 {
			t.Fatalf("calls %v", sys.Calls)
		}
	})
	t.Run("hostnamed unavailable", func(t *testing.T) {
		_, h, _ := hostnameFixture(t)
		h.Sys = failingHostnamectl{h.Sys}
		if res := h.Apply(context.Background(), hostnameResource(t, "lap-0421")); res.Status != reconcile.Error ||
			!strings.Contains(res.Message, "hostnamed unavailable") {
			t.Fatalf("apply %+v", res)
		}
	})
}

// TestUnitsDoNotProtectHostname (ADR 0041 decision 7): with ProtectHostname= the agent would run in its own UTS
// namespace and report a stale os.Hostname().
func TestUnitsDoNotProtectHostname(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	units, err := filepath.Glob(filepath.Join(filepath.Dir(file), "..", "..", "..", "packaging", "systemd", "*.service"))
	if err != nil || len(units) == 0 {
		t.Fatalf("no units found: %v", err)
	}
	for _, unit := range units {
		data, err := os.ReadFile(unit)
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.Lines(string(data)) {
			if strings.HasPrefix(strings.TrimSpace(line), "ProtectHostname") {
				t.Errorf("%s sets %s", filepath.Base(unit), strings.TrimSpace(line))
			}
		}
	}
}

// failingWrite is a system whose files cannot be written.
type failingWrite struct{ reconcile.System }

func (failingWrite) WriteFileAtomic(string, []byte, fs.FileMode, int, int) error {
	return errors.New("read-only file system")
}

// failingHostnamectl is a system whose hostnamed does not answer.
type failingHostnamectl struct{ reconcile.System }

func (failingHostnamectl) Hostnamectl(context.Context, ...string) (string, int, error) {
	return "Failed to connect to bus: No such file or directory\n", 1, nil
}
