package admin

import (
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
)

// Per-account budgets of MCP requests per one-minute window (plan M14 §3.4 item 21).
const (
	MCPReadLimitPerMinute  = 120
	MCPWriteLimitPerMinute = 30
)

const (
	mcpLimitWindow = time.Minute
	// mcpLimitIdle drops the counters of an account that sent nothing for this long, so the map stays bounded by the
	// accounts active in the last minutes.
	mcpLimitIdle = 10 * time.Minute
)

type mcpLimitKey struct {
	account uuid.UUID
	class   mcpcatalog.Class
}

type mcpWindow struct {
	start, last time.Time
	count       int
}

// mcpLimiter counts MCP requests in fixed one-minute windows per account and class, in memory per api replica (several
// replicas multiply the budget; plan M14 §12).
type mcpLimiter struct {
	mu        sync.Mutex
	windows   map[mcpLimitKey]*mcpWindow
	lastSweep time.Time
	now       func() time.Time
}

func newMCPLimiter(now func() time.Time) *mcpLimiter {
	return &mcpLimiter{windows: map[mcpLimitKey]*mcpWindow{}, now: now}
}

// Allow counts one request of the account in the class and reports whether it is within the budget; when it is not,
// retryAfter is the time until the window ends.
func (l *mcpLimiter) Allow(account uuid.UUID, class mcpcatalog.Class) (ok bool, retryAfter time.Duration) {
	limit := MCPReadLimitPerMinute
	if class == mcpcatalog.ClassWrite {
		limit = MCPWriteLimitPerMinute
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)
	key := mcpLimitKey{account: account, class: class}
	w := l.windows[key]
	if w == nil || !now.Before(w.start.Add(mcpLimitWindow)) {
		w = &mcpWindow{start: now}
		l.windows[key] = w
	}
	w.last = now
	if w.count >= limit {
		return false, w.start.Add(mcpLimitWindow).Sub(now)
	}
	w.count++
	return true, 0
}

// sweep drops idle windows at most once per window length, so a request pays for the scan only once a minute.
func (l *mcpLimiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < mcpLimitWindow {
		return
	}
	l.lastSweep = now
	for k, w := range l.windows {
		if now.Sub(w.last) >= mcpLimitIdle {
			delete(l.windows, k)
		}
	}
}
