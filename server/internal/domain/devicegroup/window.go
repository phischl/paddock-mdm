package devicegroup

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// Window is the maintenance window of a device group (plan M13c decision 4), in the form the bundle carries it.
type Window = bundle.SoftwareWindow

// NormalizeWindow sorts the days, so that the order a client sends them in is no change.
func NormalizeWindow(w Window) Window {
	w.Days = slices.Clone(w.Days)
	slices.Sort(w.Days)
	return w
}

// ValidateWindow checks a normalized window: the ranges of bundle.ValidateSoftwareWindow and a timezone the server can
// load (plan M13c decision 5). The message names the field.
func ValidateWindow(w Window) error {
	if err := bundle.ValidateSoftwareWindow(w); err != nil {
		return err
	}
	// time.LoadLocation also reads "Local" and "" as zones that depend on the host; neither names an IANA zone.
	if _, err := time.LoadLocation(w.Timezone); err != nil || w.Timezone == "Local" {
		return fmt.Errorf("timezone %q is not a known IANA timezone", w.Timezone)
	}
	return nil
}

// WindowSummary is how a declarative plan shows a window: the days, the local start, the duration and the zone, for
// example "1,2,3,4,5 22:00+120m Europe/Berlin".
func WindowSummary(w Window) string {
	days := make([]string, len(w.Days))
	for i, d := range w.Days {
		days[i] = strconv.Itoa(d)
	}
	return fmt.Sprintf("%s %02d:%02d+%dm %s", strings.Join(days, ","), w.StartMinute/60, w.StartMinute%60, w.DurationMinutes, w.Timezone)
}

// UnionWindows is the maintenance window of a device in several device groups: the union of the groups' windows
// (architect-lead decision Q17), identical windows once, in a stable order.
func UnionWindows(windows []Window) []Window {
	out := make([]Window, 0, len(windows))
	seen := map[string]bool{}
	for _, w := range windows {
		k := WindowSummary(w)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, w)
	}
	slices.SortFunc(out, func(a, b Window) int { return strings.Compare(WindowSummary(a), WindowSummary(b)) })
	return out
}
