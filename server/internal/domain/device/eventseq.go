package device

import (
	"cmp"
	"slices"
)

// SeenLimit is the number of delivered event sequence numbers one evaluation reads above the scan position (plan M8b
// decision 20.2, amendment 2026-10-29); a device with more is evaluated up to the last one read and continues next
// round above it.
const SeenLimit = 10000

// SeqRange is the closed range From..To of event sequence numbers.
type SeqRange struct{ From, To int64 }

// Holes advances the contiguous pointer of a device's event numbering over the numbers that were delivered (seen,
// ascending, all above contiguous) or that the agent declared dropped, and returns the maximal ranges above it that
// are neither, up to high (plan M8b decision 20.3). high is the highest number the device claimed; a number above it
// is no hole, even below a delivered one, because an event received after the check-in may still have company in
// flight (amendment 2026-10-24). When seen holds SeenLimit numbers, holes end at the last of them: the numbers above
// were not read.
func Holes(contiguous, high int64, seen []int64, dropped []SeqRange) (newContiguous int64, holes []SeqRange) {
	if len(seen) >= SeenLimit {
		high = min(high, seen[len(seen)-1])
	}
	c := contiguous
	ranges := known(seen, dropped)
	i := 0
	for ; i < len(ranges) && ranges[i].From <= c+1; i++ {
		c = max(c, ranges[i].To)
	}
	next := c + 1
	for _, r := range ranges[i:] {
		if next > high {
			break
		}
		holes = append(holes, SeqRange{From: next, To: min(r.From-1, high)})
		next = r.To + 1
	}
	if next <= high {
		holes = append(holes, SeqRange{From: next, To: high})
	}
	return c, holes
}

// Scan looks for holes above a device's scan position scanned, the number up to which every number was delivered,
// declared dropped or lies in an open gap row (PDK-419, plan M8b amendment 2026-10-29). seen holds the delivered
// numbers above scanned, as for Holes. It returns the holes as Holes does and the new scan position: every number up
// to it is delivered, dropped or in one of the holes. A hole that never fills does not hold the position back, so the
// next scan reads above it and a later hole is still found after more than SeenLimit further numbers.
func Scan(scanned, high int64, seen []int64, dropped []SeqRange) (newScanned int64, holes []SeqRange) {
	c, holes := Holes(scanned, high, seen, dropped)
	if len(seen) >= SeenLimit {
		high = min(high, seen[len(seen)-1])
	}
	return max(c, high), holes
}

// Contiguous returns the number up to which every event of a device was delivered or declared dropped, given its scan
// position and the gap ranges that are still open: below the scan position only open ranges hold missing numbers.
func Contiguous(scanned int64, open []SeqRange) int64 {
	c := scanned
	for _, r := range open {
		c = min(c, r.From-1)
	}
	return c
}

// Uncovered returns the parts of r that none of the ranges in cut contains, in ascending order.
func Uncovered(r SeqRange, cut []SeqRange) []SeqRange {
	var out []SeqRange
	next := r.From
	for _, k := range merge(cut) {
		if k.To < next || k.From > r.To {
			continue
		}
		if k.From > next {
			out = append(out, SeqRange{From: next, To: k.From - 1})
		}
		next = k.To + 1
	}
	if next <= r.To {
		out = append(out, SeqRange{From: next, To: r.To})
	}
	return out
}

// known merges the delivered numbers and the dropped ranges into ascending, disjoint, non-adjacent ranges.
func known(seen []int64, dropped []SeqRange) []SeqRange {
	all := make([]SeqRange, 0, len(seen)+len(dropped))
	for _, s := range seen {
		all = append(all, SeqRange{From: s, To: s})
	}
	return merge(append(all, dropped...))
}

func merge(ranges []SeqRange) []SeqRange {
	sorted := slices.SortedFunc(slices.Values(ranges), func(a, b SeqRange) int { return cmp.Compare(a.From, b.From) })
	var out []SeqRange
	for _, r := range sorted {
		if r.From > r.To {
			continue
		}
		if n := len(out); n > 0 && r.From <= out[n-1].To+1 {
			out[n-1].To = max(out[n-1].To, r.To)
			continue
		}
		out = append(out, r)
	}
	return out
}
