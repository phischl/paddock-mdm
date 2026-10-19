package main

import (
	"regexp"
	"strconv"
	"strings"
)

// Classifications of a pin (plan M8d decision 59).
const (
	ClassOK      = "ok"
	ClassPatch   = "patch"
	ClassMinor   = "minor"
	ClassMajor   = "major"
	ClassDigest  = "digest"
	ClassUnknown = "unknown"
)

var digitsRE = regexp.MustCompile(`\d+`)

// Shape returns the pattern a tag of the same shape as pinned matches: every digit run becomes \d+, everything else
// is literal (2.11.6 → ^\d+\.\d+\.\d+$, 4.3.6-management → ^\d+\.\d+\.\d+-management$).
func Shape(pinned string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	last := 0
	for _, loc := range digitsRE.FindAllStringIndex(pinned, -1) {
		b.WriteString(regexp.QuoteMeta(pinned[last:loc[0]]))
		b.WriteString(`\d+`)
		last = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(pinned[last:]))
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// Floating reports whether a tag carries no version number at all (nonroot, latest): such a pin is compared by
// digest.
func Floating(tag string) bool { return !digitsRE.MatchString(tag) }

// Fields returns the numeric fields of a tag in order.
func Fields(tag string) []uint64 {
	runs := digitsRE.FindAllString(tag, -1)
	out := make([]uint64, 0, len(runs))
	for _, r := range runs {
		n, err := strconv.ParseUint(r, 10, 64)
		if err != nil {
			n = ^uint64(0)
		}
		out = append(out, n)
	}
	return out
}

// CompareTags orders two tags of the same shape by their numeric fields (4.10.0 > 4.9.9).
func CompareTags(a, b string) int {
	fa, fb := Fields(a), Fields(b)
	for i := 0; i < len(fa) && i < len(fb); i++ {
		switch {
		case fa[i] < fb[i]:
			return -1
		case fa[i] > fb[i]:
			return 1
		}
	}
	return len(fa) - len(fb)
}

// Latest returns the highest tag of the pinned tag's shape, or "" when none matches.
func Latest(pinned string, tags []string) string {
	re := Shape(pinned)
	best := ""
	for _, t := range tags {
		if !re.MatchString(t) {
			continue
		}
		if best == "" || CompareTags(t, best) > 0 {
			best = t
		}
	}
	return best
}

// Classify names the step from pinned to latest: patch when only the last numeric field grew, major when the first,
// minor when one in between; ok when latest is not newer.
func Classify(pinned, latest string) string {
	if latest == "" || CompareTags(latest, pinned) <= 0 {
		return ClassOK
	}
	fp, fl := Fields(pinned), Fields(latest)
	n := min(len(fp), len(fl))
	i := 0
	for i < n && fp[i] == fl[i] {
		i++
	}
	switch {
	case i >= n-1:
		return ClassPatch
	case i == 0:
		return ClassMajor
	default:
		return ClassMinor
	}
}
