package integrity

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
)

const (
	conf   = reconcile.HimmelblauConf
	render = "[global]\ndomain = acme.test\n"
)

// paddockWrite writes path as the login reconciler does: check, write, record.
func (d *device) paddockWrite(path, content string) {
	d.t.Helper()
	d.c.BeforeWrite(path)
	d.write(path, content)
	d.c.Written(path, []byte(content))
}

// upgraded is a device on which the agent update with the identity check meets conf as Paddock wrote it.
func upgraded(t *testing.T) *device {
	t.Helper()
	d := newDevice(t)
	d.write(conf, render)
	d.quiet(1, Pass{})
	return d
}

// 1126c-3: the first start after the update reports nothing for files that match Paddock's render.
func TestIdentityUpgradeReportsNothing(t *testing.T) {
	d := upgraded(t)
	for _, p := range reconcile.LoginManagedFiles {
		d.c.Expect(p, []byte(render))
	}
	d.write(reconcile.DenyList, render)
	for _, p := range reconcile.HimmelblauSocketDropIns {
		d.write(p, render)
	}
	d.quiet(3, Pass{})
	d.c.BeforeWrite(conf)
	if len(d.events) != 0 || d.baseline().Expected[conf] != sha(render) {
		t.Fatalf("events %v, baseline %q", d.events, d.baseline().Expected[conf])
	}
}

// 1126c-4: a change made before the update is judged against the render, never taken from the disk.
func TestIdentityChangeBeforeUpgradeReported(t *testing.T) {
	d := upgraded(t)
	d.write(conf, render+"pam_allow_groups = everyone\n")
	d.quiet(1, Pass{})
	if _, ok := d.baseline().Expected[conf]; ok {
		t.Fatal("the check recorded an identity file from the disk")
	}
	d.c.Expect(conf, []byte(render))
	d.changedOnce(conf, Pass{})
}

// 1126c-1: a change after Paddock's write is reported once right before the correction, which clears the mark; the
// same change made again is reported again.
func TestIdentityChangeReportedBeforeTheCorrection(t *testing.T) {
	d := upgraded(t)
	d.c.Expect(conf, []byte(render))
	for range 2 {
		d.write(conf, "foreign")
		d.events = nil
		d.paddockWrite(conf, render)
		if !slices.Equal(d.events, []string{conf}) {
			t.Fatalf("reported %v, want [%s]", d.events, conf)
		}
		if _, marked := d.baseline().Reported[conf]; marked {
			t.Fatal("the correction left the mark")
		}
		d.quiet(2, Pass{})
	}
}

// 1126c-2: an agent update with a changed render rewrites the file without a report.
func TestIdentityTemplateChangeReportsNothing(t *testing.T) {
	d := upgraded(t)
	d.c.Expect(conf, []byte(render))
	d.restart()
	d.c.Expect(conf, []byte(render+"cache_timeout = 1\n"))
	d.events = nil
	d.paddockWrite(conf, render+"cache_timeout = 1\n")
	if len(d.events) != 0 {
		t.Fatalf("reported %v", d.events)
	}
	d.quiet(3, Pass{})
}

// A change between Paddock's write and the next pass is reported by the pass.
func TestIdentityChangeAfterTheWriteReported(t *testing.T) {
	d := upgraded(t)
	d.paddockWrite(conf, render)
	d.write(conf, "foreign")
	d.changedOnce(conf, Pass{})
}

// 1126c-5: a deleted drop-in is reported once by the pass alone, as on a report-only device; Paddock's removal is no
// change.
func TestIdentityDeletedFileReported(t *testing.T) {
	d := upgraded(t)
	dropIn := reconcile.HimmelblaudSocketDropIn
	d.paddockWrite(dropIn, "[Socket]\n")
	d.remove(dropIn)
	d.changedOnce(dropIn, Pass{})

	d.paddockWrite(conf, render)
	d.c.BeforeWrite(conf)
	d.remove(conf)
	d.c.Written(conf, nil)
	d.quiet(2, Pass{})
}

// An empty file Paddock wrote has the value the hasher observes.
func TestIdentityEmptyFile(t *testing.T) {
	d := upgraded(t)
	d.paddockWrite(reconcile.DenyList, "")
	d.quiet(2, Pass{})
	if got := d.baseline().Expected[reconcile.DenyList]; got != sha("") {
		t.Fatalf("baseline %q", got)
	}
}

// With integrity.lock held, BeforeWrite reports nothing and the write is recorded by the next pass; Expect retries.
func TestIdentityLockTimeouts(t *testing.T) {
	d := upgraded(t)
	d.paddockWrite(conf, render)
	f := holdLock(t, d)
	d.write(conf, "foreign")
	d.logs.reset()
	d.paddockWrite(conf, render+"x\n")
	d.c.Expect(reconcile.DenyList, []byte(render))
	if len(d.events) != 0 || d.logs.count(slog.LevelWarn) != 3 {
		t.Fatalf("events %v, %d warnings, want none and 3", d.events, d.logs.count(slog.LevelWarn))
	}
	_ = f.Close()
	d.quiet(2, Pass{})
	if got := d.baseline().Expected[conf]; got != sha(render+"x\n") {
		t.Fatalf("baseline %q, want Paddock's write", got)
	}
	if _, ok := d.baseline().Expected[reconcile.DenyList]; ok {
		t.Fatal("a pass recorded the deny list from the disk")
	}
	d.c.Expect(reconcile.DenyList, []byte(render))
	if got := d.baseline().Expected[reconcile.DenyList]; got != sha(render) {
		t.Fatalf("the retried Expect recorded %q", got)
	}
}

// The guard runs on the drift loop and Expect on the agent socket while a pass runs (go test -race).
func TestIdentityGuardConcurrentWithCheck(t *testing.T) {
	d := upgraded(t)
	d.c.Emit = func(string, string) {}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 20 {
			d.c.Expect(reconcile.DenyList, []byte(render))
			d.c.BeforeWrite(conf)
			d.c.Written(conf, []byte(render))
		}
	}()
	for range 20 {
		d.c.Check(context.Background(), Pass{})
	}
	wg.Wait()
}
