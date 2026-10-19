package system

import (
	"maps"
	"slices"
	"sync"
	"testing"
)

// TestVMGroupSharedRelease: two VMs share their input before a rendezvous, the step runs once and sees both values,
// and what it registers with AfterAll runs only after both VMs left, in reverse order.
func TestVMGroupSharedRelease(t *testing.T) {
	g := newVMGroup()
	names := []string{"a", "b"}
	for _, n := range names {
		g.active[n] = true
	}
	var (
		mu      sync.Mutex
		runs    int
		seen    map[string]string
		undone  []string
		results = map[string]string{}
		wg      sync.WaitGroup
	)
	for _, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer g.leave(n)
			g.Share(n, "bucket", "b-"+n)
			v := g.Together(t, n, "gate", "release", func() string {
				mu.Lock()
				defer mu.Unlock()
				runs++
				seen = g.Shared("bucket")
				g.AfterAll(t, func(*testing.T) { undone = append(undone, "release") })
				g.AfterAll(t, func(*testing.T) { undone = append(undone, "policy") })
				return "v1"
			})
			mu.Lock()
			results[n] = v
			mu.Unlock()
		}()
	}
	wg.Wait()
	if runs != 1 || !maps.Equal(seen, map[string]string{"a": "b-a", "b": "b-b"}) || results["a"] != "v1" || results["b"] != "v1" {
		t.Fatalf("runs %d, shared %v, results %v", runs, seen, results)
	}
	if len(undone) != 0 {
		t.Fatalf("undone before the end: %v", undone)
	}
	g.runAfterAll(t)
	if !slices.Equal(undone, []string{"policy", "release"}) {
		t.Fatalf("undone %v, want policy then release", undone)
	}
}
