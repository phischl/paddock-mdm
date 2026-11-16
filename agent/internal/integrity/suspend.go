package integrity

import (
	"time"
)

// Bounds of a suspension cause, in observed time (plan M5a R3).
const (
	// StateBound covers causes in the baseline itself; regular holders keep integrity.lock for milliseconds.
	StateBound = 15 * time.Minute
	// FlowBound covers causes that Paddock's own flows create; the longest regular one (a dpkg run of a release
	// upgrade) stays well below it.
	FlowBound = 6 * time.Hour
)

// The causes of the baseline itself (plan M5a R3); every other cause is one of Paddock's flows or an object.
const (
	causeLock          = "lock"
	causeBaselineRead  = "baseline_read"
	causeBaselineWrite = "baseline_write"
	causeBaselineRaced = "baseline_raced"
)

// Suspension is one active suspension cause (plan M5a R4).
type Suspension struct {
	File string `json:"file"`
	// Observed is the seconds the cause was seen active.
	Observed int64 `json:"observed_s"`
	// Last is the time of the last pass that saw it active.
	Last     time.Time `json:"last"`
	Reported bool      `json:"reported"`
}

// causes are the suspension causes active in a pass: key → the path that blocks the check.
type causes map[string]string

func (c causes) add(key, file string) { c[key] = file }

func bound(key string) time.Duration {
	switch key {
	case causeLock, causeBaselineRead, causeBaselineWrite, causeBaselineRaced:
		return StateBound
	}
	return FlowBound
}

// adopt merges the persisted suspensions into memory: memory is authoritative, an entry it lacks is adopted, and on
// a conflict the larger Observed wins with Reported OR-ed (plan M5a R4.1).
func (c *Checker) adopt(persisted map[string]Suspension) {
	if c.suspended == nil {
		c.suspended = map[string]Suspension{}
	}
	for k, p := range persisted {
		m, ok := c.suspended[k]
		switch {
		case !ok:
			c.suspended[k] = p
		case p.Observed > m.Observed:
			p.Reported = p.Reported || m.Reported
			c.suspended[k] = p
		default:
			m.Reported = m.Reported || p.Reported
			c.suspended[k] = m
		}
	}
}

// track accumulates the active causes of a pass and returns the files whose cause reached its bound in this
// episode (plan M5a R4). A cause neither active nor kept (not evaluated by this pass) ends its episode. A gap between
// passes counts as at most two intervals, so a suspend or a shutdown does not reach a bound.
func (c *Checker) track(active causes, keep func(key string) bool, now time.Time, interval time.Duration) []string {
	if c.suspended == nil {
		c.suspended = map[string]Suspension{}
	}
	for k := range c.suspended {
		if _, ok := active[k]; !ok && !keep(k) {
			delete(c.suspended, k)
		}
	}
	var report []string
	for k, file := range active {
		s, ok := c.suspended[k]
		if !ok {
			s = Suspension{File: file}
		} else if gap := now.Sub(s.Last); gap > 0 {
			s.Observed += int64(min(gap, 2*interval) / time.Second)
		}
		s.File, s.Last = file, now
		if !s.Reported && time.Duration(s.Observed)*time.Second >= bound(k) {
			s.Reported = true
			report = append(report, file)
		}
		c.suspended[k] = s
	}
	return report
}

// persisted is the memory map without the cause key, for the save (plan M5a R4.1).
func (c *Checker) persisted(without string) map[string]Suspension {
	out := map[string]Suspension{}
	for k, s := range c.suspended {
		if k != without {
			out[k] = s
		}
	}
	return out
}
