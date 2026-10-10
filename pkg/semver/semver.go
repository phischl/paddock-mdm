// Package semver orders agent release versions by SemVer 2.0.0 precedence (PDK-025): the supervisor refuses
// downgrades with it and the server offers devices only newer releases. The SQL function paddock_version_key (column
// agent_release.version_key) orders the same way; a server test keeps both equal.
package semver

import (
	"cmp"
	"strconv"
	"strings"
)

// Compare orders two semantic versions by SemVer 2.0.0 precedence, build metadata ignored: -1, 0 or 1.
func Compare(a, b string) int {
	a, _, _ = strings.Cut(a, "+")
	b, _, _ = strings.Cut(b, "+")
	aCore, aPre, _ := strings.Cut(a, "-")
	bCore, bPre, _ := strings.Cut(b, "-")
	if c := compareIdentifiers(strings.Split(aCore, "."), strings.Split(bCore, ".")); c != 0 {
		return c
	}
	switch {
	case aPre == bPre:
		return 0
	case aPre == "": // a release ranks above its pre-releases
		return 1
	case bPre == "":
		return -1
	}
	return compareIdentifiers(strings.Split(aPre, "."), strings.Split(bPre, "."))
}

// compareIdentifiers compares dot-separated identifiers: numeric ones numerically and below alphanumeric ones, the
// others in ASCII order; with equal shared identifiers the longer list ranks higher.
func compareIdentifiers(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		an, aErr := strconv.ParseUint(a[i], 10, 64)
		bn, bErr := strconv.ParseUint(b[i], 10, 64)
		switch {
		case aErr == nil && bErr == nil && an != bn:
			return cmp.Compare(an, bn)
		case aErr == nil && bErr != nil:
			return -1
		case aErr != nil && bErr == nil:
			return 1
		case aErr != nil && a[i] != b[i]:
			return strings.Compare(a[i], b[i])
		}
	}
	return cmp.Compare(len(a), len(b))
}
