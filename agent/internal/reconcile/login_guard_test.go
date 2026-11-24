package reconcile_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// guardLog records the guard's calls between the system calls of the reconciler, in order.
type guardLog struct {
	sys *fakesys.System
	log []string
}

func (g *guardLog) add(entry string) {
	for _, c := range g.sys.TakeCalls() {
		if strings.HasPrefix(c, "write ") || strings.HasPrefix(c, "remove ") {
			g.log = append(g.log, c)
		}
	}
	g.log = append(g.log, entry)
}

func (g *guardLog) Expect(path string, content []byte) {
	g.add("expect " + path + " " + string(content))
}
func (g *guardLog) BeforeWrite(path string) { g.add("before " + path) }
func (g *guardLog) Written(path string, content []byte) {
	if content == nil {
		g.add("written " + path + " <removed>")
		return
	}
	g.add("written " + path + " " + string(content))
}

// managed returns the log entries of the LoginManagedFiles, with the system calls taken up to now.
func (g *guardLog) managed() []string {
	g.add("")
	var out []string
	for _, e := range g.log {
		if slices.ContainsFunc(reconcile.LoginManagedFiles, func(p string) bool { return strings.Contains(e, " "+p) }) {
			out = append(out, e)
		}
	}
	g.log = nil
	return out
}

const dropIn = "# Managed by Paddock. Do not edit: local changes are reverted.\n[Socket]\nRemoveOnStop=yes\n"

func guarded(t *testing.T) (*fakesys.System, *reconcile.Login, *guardLog) {
	t.Helper()
	sys, l, _ := loginFixture(t)
	g := &guardLog{sys: sys}
	l.Guard = g
	return sys, l, g
}

// On a fresh device Apply hands the guard no render; each write of a managed file lies between the check and the
// record of the written bytes (plan M5a amendment 2026-11-17 f). Plan never reaches the guard.
func TestLoginGuardSeesEveryWrite(t *testing.T) {
	ctx := context.Background()
	_, l, g := guarded(t)
	r := loginResource(t, loginSpec())
	if _, err := l.Plan(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got := g.managed(); len(got) != 0 {
		t.Fatalf("Plan reached the guard: %q", got)
	}
	l.Apply(ctx, r)
	// The configuration written before the installation is recorded only once the installation succeeded.
	writes := []string{"before " + reconcile.HimmelblauConf, "write " + reconcile.HimmelblauConf}
	for _, p := range reconcile.HimmelblauSocketDropIns {
		writes = append(writes, writeTriples(p, dropIn)...)
	}
	writes = append(writes, "written "+reconcile.HimmelblauConf+" "+wantConf)
	writes = append(writes, writeTriples(reconcile.DenyList, "")...)
	writes = append(writes, writeTriples(reconcile.HimmelblauConf, wantConf)...)
	if got := g.managed(); !slices.Equal(got, writes) {
		t.Fatalf("guard log\n%q\nwant\n%q", got, writes)
	}
}

// After an agent start Apply hands the guard the renders of the previously enforced spec, before any write; the socket
// drop-ins have none, and himmelblau.conf none while that spec's packages are not installed. A successful Apply makes
// its own spec the previous one, and files that already hold their render are confirmed.
func TestLoginGuardExpectsThePreviousRenders(t *testing.T) {
	ctx := context.Background()
	sys, l, g := guarded(t)
	prev := loginResource(t, loginSpec())
	l.SetPrevious(&prev, true)
	s := loginSpec()
	s.LockedUsers = []string{"erin@acme.test"}
	l.Apply(ctx, loginResource(t, s))
	if got := g.managed(); len(got) < 1 || got[0] != "expect "+reconcile.DenyList+" " ||
		slices.ContainsFunc(got[1:], func(e string) bool { return strings.HasPrefix(e, "expect ") }) {
		t.Fatalf("packages missing: guard log %q, want only the deny list expected", got)
	}
	for _, p := range reconcile.HimmelblauPackages {
		if v := sys.PackageVersion(p); !strings.HasPrefix(v, "4.0.4") {
			t.Fatalf("%s %q after the installation", p, v)
		}
	}
	l.SetPrevious(&prev, true)
	l.Apply(ctx, loginResource(t, s))
	got := g.managed()
	want := []string{"expect " + reconcile.HimmelblauConf + " " + wantConf, "expect " + reconcile.DenyList + " "}
	if len(got) < 2 || !slices.Equal(got[:2], want) {
		t.Fatalf("guard log %q, want it to start with %q", got, want)
	}
	l.Apply(ctx, loginResource(t, s))
	got = g.managed()
	if !slices.Contains(got, "expect "+reconcile.DenyList+" erin@acme.test\nerin\n") ||
		!slices.Contains(got, "written "+reconcile.DenyList+" erin@acme.test\nerin\n") ||
		!slices.Contains(got, "written "+reconcile.HimmelblauConf+" "+wantConf) || slices.ContainsFunc(got, func(e string) bool { return strings.HasPrefix(e, "before ") }) {
		t.Fatalf("unchanged apply: guard log %q, want the own spec expected and every file confirmed", got)
	}
}

// At agent start the files that hold the previous renders are confirmed; himmelblau.conf only while that spec's
// packages are installed, and nothing without a previous spec.
func TestLoginGuardConfirmPrevious(t *testing.T) {
	_, l, g := guarded(t)
	r := loginResource(t, loginSpec())
	l.Apply(context.Background(), r)
	s := loginSpec()
	s.Himmelblau.PackageVersion = "4.0.5" // not installed; the rendered file does not name the version
	other := loginResource(t, s)
	for _, tc := range []struct {
		prev     *bundle.Resource
		confirms int
	}{{nil, 0}, {&other, 4}, {&r, 5}} {
		g.managed()
		l.SetPrevious(tc.prev, true)
		l.ConfirmPrevious()
		got := g.managed()
		withConf := slices.Contains(got, "written "+reconcile.HimmelblauConf+" "+wantConf)
		if len(got) != tc.confirms || withConf != (tc.confirms == 5) || tc.confirms > 0 && !slices.Contains(got, "written "+reconcile.DenyList+" ") {
			t.Fatalf("%d confirms expected: guard log %q", tc.confirms, got)
		}
	}
}

// A failed installation takes the configuration back without the guard: neither the configuration it wrote nor the
// restored or removed file becomes the baseline.
func TestLoginGuardSeesTheRollback(t *testing.T) {
	for _, tc := range []struct{ name, previous, undo string }{{"restore", "[global]\n", "write"}, {"remove", "", "remove"}} {
		t.Run(tc.name, func(t *testing.T) {
			sys, l, g := guarded(t)
			sys.FailCmd = "apt-get install"
			if tc.previous != "" {
				sys.Files[reconcile.HimmelblauConf] = &fakesys.File{Data: []byte(tc.previous), Mode: 0o644}
			}
			l.Apply(context.Background(), loginResource(t, loginSpec()))
			var conf []string
			for _, e := range g.managed() {
				if strings.Contains(e, " "+reconcile.HimmelblauConf) && !strings.HasPrefix(e, "expect ") {
					conf = append(conf, e)
				}
			}
			want := []string{"before " + reconcile.HimmelblauConf, "write " + reconcile.HimmelblauConf, tc.undo + " " + reconcile.HimmelblauConf}
			if !slices.Equal(conf, want) {
				t.Fatalf("himmelblau.conf in the guard log %q, want %q", conf, want)
			}
		})
	}
}

// EnsureDenyList writes through the guard; it expects the empty list only after an enforced bundle, whose agent kept
// the list in place.
func TestLoginGuardEnsureDenyList(t *testing.T) {
	for _, applied := range []bool{false, true} {
		_, l, g := guarded(t)
		l.SetPrevious(nil, applied)
		if written, err := l.EnsureDenyList(); !written || err != nil {
			t.Fatalf("EnsureDenyList %v %v", written, err)
		}
		want := writeTriples(reconcile.DenyList, "")
		if applied {
			want = append([]string{"expect " + reconcile.DenyList + " "}, want...)
		}
		if got := g.managed(); !slices.Equal(got, want) {
			t.Fatalf("applied %v: guard log %q, want %q", applied, got, want)
		}
	}
}

func writeTriples(path, content string) []string {
	return []string{"before " + path, "write " + path, "written " + path + " " + content}
}

// A failed write is never recorded as Paddock's.
func TestLoginGuardFailedWriteNotRecorded(t *testing.T) {
	sys, l, g := guarded(t)
	sys.FailWrite = reconcile.DenyList
	l.Apply(context.Background(), loginResource(t, loginSpec()))
	got := g.managed()
	if i := slices.Index(got, "write "+reconcile.DenyList); i < 1 || got[i-1] != "before "+reconcile.DenyList ||
		slices.ContainsFunc(got, func(e string) bool { return strings.HasPrefix(e, "written "+reconcile.DenyList) }) {
		t.Fatalf("guard log %q", got)
	}
}

// An installation killed at its timeout keeps the configuration it wrote, so the guard records it.
func TestLoginGuardTimeoutKeepsTheRecord(t *testing.T) {
	sys, l, g := guarded(t)
	sys.AptTimeout = true
	l.Apply(context.Background(), loginResource(t, loginSpec()))
	if got := g.managed(); !slices.Contains(got, "written "+reconcile.HimmelblauConf+" "+wantConf) {
		t.Fatalf("guard log %q", got)
	}
}
