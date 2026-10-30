package admin

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
)

type limitClock struct{ t time.Time }

func (c *limitClock) now() time.Time { return c.t }

func (l *mcpLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.windows)
}

// TestMCPLimiter: fixed one-minute windows per account and class, 120 reads and 30 writes, Retry-After up to the end
// of the window, and idle accounts dropped after 10 minutes (plan M14 §3.4 item 21).
func TestMCPLimiter(t *testing.T) {
	clock := &limitClock{t: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	l := newMCPLimiter(clock.now)
	alice, bob := uuid.New(), uuid.New()

	for i := range MCPReadLimitPerMinute {
		if ok, _ := l.Allow(alice, mcpcatalog.ClassRead); !ok {
			t.Fatalf("read %d refused", i+1)
		}
	}
	clock.t = clock.t.Add(20*time.Second + 300*time.Millisecond)
	ok, retry := l.Allow(alice, mcpcatalog.ClassRead)
	if ok || retry != 39*time.Second+700*time.Millisecond {
		t.Fatalf("read 121: ok %v, retry after %s", ok, retry)
	}
	for i := range MCPWriteLimitPerMinute {
		if ok, _ := l.Allow(alice, mcpcatalog.ClassWrite); !ok {
			t.Fatalf("write %d refused while reads are spent", i+1)
		}
	}
	if ok, _ := l.Allow(alice, mcpcatalog.ClassWrite); ok {
		t.Fatal("write 31 allowed")
	}
	if ok, _ := l.Allow(bob, mcpcatalog.ClassRead); !ok {
		t.Fatal("another account shares the budget")
	}

	clock.t = clock.t.Add(61 * time.Second)
	if ok, _ := l.Allow(alice, mcpcatalog.ClassRead); !ok {
		t.Fatal("read refused in the next window")
	}
	if ok, _ := l.Allow(alice, mcpcatalog.ClassWrite); !ok {
		t.Fatal("write refused in the next window")
	}

	if n := l.size(); n != 3 {
		t.Fatalf("%d windows, want 3", n)
	}
	clock.t = clock.t.Add(9 * time.Minute)
	l.Allow(alice, mcpcatalog.ClassRead)
	if n := l.size(); n != 2 {
		t.Fatalf("after 9 minutes: %d windows, want 2 (alice's read and write)", n)
	}
	clock.t = clock.t.Add(10 * time.Minute)
	l.Allow(bob, mcpcatalog.ClassWrite)
	if n := l.size(); n != 1 {
		t.Fatalf("after 10 idle minutes: %d windows, want only bob's new one", n)
	}
}
