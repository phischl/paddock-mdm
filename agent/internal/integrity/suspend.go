package integrity

import (
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/state"
)

// Bounds of a blocked object, in observed time (plan M5a R3, R15.2).
const (
	// StateBound covers the baseline itself; regular holders keep integrity.lock for milliseconds.
	StateBound = 15 * time.Minute
	// FlowBound covers objects that Paddock's own flows block; the longest regular one (a dpkg run of a release
	// upgrade) stays well below it.
	FlowBound = 6 * time.Hour
	// MaxInterval caps the check's interval, so that a long drift interval cannot stretch the bounds (R15.5).
	MaxInterval = time.Hour
)

// Interval is the interval of the integrity check for a drift interval (plan M5a R15.5).
func Interval(drift time.Duration) time.Duration { return min(drift, MaxInterval) }

// Suspension is one blocked object; the agent keeps it in state.json (plan M5a R15.3).
type Suspension = state.IntegritySuspension

// The objects with their own key (plan M5a R15.2); the others are "package:<name>", "file:<path>" and "unit:<unit>".
const (
	objBaseline = "baseline"
	objSlots    = "slots"
)

// blockers are the objects blocked in a pass, each with its first active blocker.
type blockers map[string]blocker

// blocker is one active blocker; rank is its position in the column of R15.2, the lowest names the file.
type blocker struct {
	rank int
	file string
}

func (bl blockers) block(object string, rank int, file string) {
	if b, ok := bl[object]; !ok || rank < b.rank {
		bl[object] = blocker{rank: rank, file: file}
	}
}

func bound(object string) time.Duration {
	if object == objBaseline {
		return StateBound
	}
	return FlowBound
}

// track accumulates the blocked objects of a pass, once per pass, and returns the files whose object reached its
// bound in this episode (plan M5a R4, R15.4). An episode ends only in a judged pass (classified and saved) without a
// blocker of its object; a pass that was not judged starts only the baseline's episode and continues every other. A
// gap between passes counts as at most two intervals, so a suspend or a shutdown does not reach a bound.
func (c *Checker) track(active blockers, judged bool, now time.Time, interval time.Duration) []string {
	if !judged {
		counted := blockers{}
		if b, ok := active[objBaseline]; ok {
			counted[objBaseline] = b
		}
		for k, s := range c.suspended {
			if b, ok := active[k]; ok {
				counted[k] = b
			} else {
				counted[k] = blocker{file: s.File}
			}
		}
		active = counted
	}
	for k := range c.suspended {
		if _, ok := active[k]; !ok {
			delete(c.suspended, k)
		}
	}
	var report []string
	for k, b := range active {
		s, ok := c.suspended[k]
		if ok {
			if gap := now.Sub(s.Last); gap > 0 {
				s.Observed += int64(min(gap, 2*interval) / time.Second)
			}
		}
		s.File, s.Last = b.file, now
		if !s.Reported && time.Duration(s.Observed)*time.Second >= bound(k) {
			s.Reported = true
			report = append(report, b.file)
		}
		c.suspended[k] = s
	}
	return report
}
