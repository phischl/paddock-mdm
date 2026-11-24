package reconcile_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
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
	writes := writeTriples(reconcile.HimmelblauConf, wantConf)
	for _, p := range reconcile.HimmelblauSocketDropIns {
		writes = append(writes, writeTriples(p, dropIn)...)
	}
	writes = append(writes, writeTriples(reconcile.DenyList, "")...)
	writes = append(writes, writeTriples(reconcile.HimmelblauConf, wantConf)...)
	if got := g.managed(); !slices.Equal(got, writes) {
		t.Fatalf("guard log\n%q\nwant\n%q", got, writes)
	}
}

// After an agent update Apply hands the guard the renders of the previously enforced spec, before any write; the
// socket drop-ins have none. A successful Apply makes its own spec the previous one.
func TestLoginGuardExpectsThePreviousRenders(t *testing.T) {
	ctx := context.Background()
	_, l, g := guarded(t)
	prev := loginResource(t, loginSpec())
	l.SetPrevious(&prev, true)
	s := loginSpec()
	s.LockedUsers = []string{"erin@acme.test"}
	l.Apply(ctx, loginResource(t, s))
	got := g.managed()
	want := []string{"expect " + reconcile.HimmelblauConf + " " + wantConf, "expect " + reconcile.DenyList + " "}
	if len(got) < 2 || !slices.Equal(got[:2], want) || slices.ContainsFunc(got[2:], func(e string) bool { return strings.HasPrefix(e, "expect ") }) {
		t.Fatalf("guard log %q, want it to start with %q and no other expect", got, want)
	}
	l.Apply(ctx, loginResource(t, s))
	if got := g.managed(); len(got) != 2 || got[1] != "expect "+reconcile.DenyList+" erin@acme.test\nerin\n" {
		t.Fatalf("second apply: guard log %q", got)
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

// A failed installation takes the configuration back through the guard: the previous file, or its removal.
func TestLoginGuardSeesTheRollback(t *testing.T) {
	for _, tc := range []struct {
		name, previous string
		want           []string
	}{
		{"restore", "[global]\n", writeTriples(reconcile.HimmelblauConf, "[global]\n")},
		{"remove", "", []string{"before " + reconcile.HimmelblauConf, "remove " + reconcile.HimmelblauConf,
			"written " + reconcile.HimmelblauConf + " <removed>"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sys, l, g := guarded(t)
			sys.FailCmd = "apt-get install"
			if tc.previous != "" {
				sys.Files[reconcile.HimmelblauConf] = &fakesys.File{Data: []byte(tc.previous), Mode: 0o644}
			}
			l.Apply(context.Background(), loginResource(t, loginSpec()))
			got := g.managed()
			var conf []string
			for _, e := range got {
				if strings.Contains(e, " "+reconcile.HimmelblauConf) && !strings.HasPrefix(e, "expect ") {
					conf = append(conf, e)
				}
			}
			if len(conf) < 3 || !slices.Equal(conf[len(conf)-3:], tc.want) {
				t.Fatalf("himmelblau.conf in the guard log %q, want it to end with %q", conf, tc.want)
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
