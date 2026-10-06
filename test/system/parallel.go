package system

import (
	"sync"
	"testing"
)

// vmGroup coordinates the per-VM subtests of one test that run in parallel, one subtest per VM (plan M4b.1 step 5).
// A step that changes what every device shares — the stack outage of S3, the releases of S4, the stopped worker of
// LA1 — runs once for all VMs at a rendezvous (Together); a step that reads or writes state of the whole
// organization runs on one VM at a time (Exclusive, Lock). A nil *vmGroup (a test that drives its VMs itself) runs
// every step directly.
type vmGroup struct {
	mu   sync.Mutex
	cond *sync.Cond
	// active are the VMs whose subtest is running; finished holds, per VM, the gates it left.
	active   map[string]bool
	finished map[string]map[string]bool
	rounds   map[string]*round
	locks    map[string]*sync.Mutex
}

// round is one rendezvous: the VMs that arrived and, once it started, the result of its step.
type round struct {
	arrived map[string]bool
	started bool
	done    chan struct{}
	value   string
	ok      bool
}

func newVMGroup() *vmGroup {
	g := &vmGroup{active: map[string]bool{}, finished: map[string]map[string]bool{}, rounds: map[string]*round{},
		locks: map[string]*sync.Mutex{}}
	g.cond = sync.NewCond(&g.mu)
	return g
}

func (g *vmGroup) leave(vm string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.active, vm)
	g.cond.Broadcast()
}

// Gate marks t as gate of vm: when t ends, the rendezvous of the gate no longer wait for vm, also if it failed before
// it arrived.
func (g *vmGroup) Gate(t *testing.T, vm, gate string) {
	if g == nil {
		return
	}
	t.Cleanup(func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.finished[vm] == nil {
			g.finished[vm] = map[string]bool{}
		}
		g.finished[vm][gate] = true
		g.cond.Broadcast()
	})
}

// Together waits until every running VM arrived at step of gate or left the gate; the VM that finds the rendezvous
// complete runs fn, and every VM returns its result. If fn fails, the other VMs fail too.
func (g *vmGroup) Together(t *testing.T, vm, gate, step string, fn func() string) string {
	t.Helper()
	if g == nil {
		return fn()
	}
	key := gate + "/" + step
	g.mu.Lock()
	r := g.rounds[key]
	if r == nil {
		r = &round{arrived: map[string]bool{}, done: make(chan struct{})}
		g.rounds[key] = r
	}
	r.arrived[vm] = true
	g.cond.Broadcast()
	for !r.started && !g.complete(r, gate) {
		g.cond.Wait()
	}
	if r.started {
		g.mu.Unlock()
		<-r.done
		if !r.ok {
			t.Fatalf("%s: step %q of %s failed on another VM", vm, step, gate)
		}
		return r.value
	}
	r.started = true
	g.mu.Unlock()
	defer close(r.done) // also when fn fails the test (runtime.Goexit runs deferred calls)
	r.value = fn()
	r.ok = true
	return r.value
}

// complete reports whether every running VM arrived at r or left gate; g.mu is held.
func (g *vmGroup) complete(r *round, gate string) bool {
	for vm := range g.active {
		if !r.arrived[vm] && !g.finished[vm][gate] {
			return false
		}
	}
	return true
}

// Lock locks the section name for one VM at a time and returns the unlock function.
func (g *vmGroup) Lock(name string) (unlock func()) {
	if g == nil {
		return func() {}
	}
	g.mu.Lock()
	m := g.locks[name]
	if m == nil {
		m = &sync.Mutex{}
		g.locks[name] = m
	}
	g.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// Exclusive holds the section name for the rest of t, including the cleanups t registers afterwards.
func (g *vmGroup) Exclusive(t *testing.T, name string) {
	t.Cleanup(g.Lock(name))
}
