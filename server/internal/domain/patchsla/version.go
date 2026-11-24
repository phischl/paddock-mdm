package patchsla

import (
	"strconv"
	"strings"
)

// CompareVersions compares two Debian package versions ([epoch:]upstream[-revision]) the way dpkg does: -1 when a is
// older than b, 0 when they are equal, 1 when a is newer. A missing or non-numeric epoch counts as 0.
func CompareVersions(a, b string) int {
	ea, ua, ra := splitVersion(a)
	eb, ub, rb := splitVersion(b)
	switch {
	case ea < eb:
		return -1
	case ea > eb:
		return 1
	}
	if c := compareFragment(ua, ub); c != 0 {
		return c
	}
	return compareFragment(ra, rb)
}

func splitVersion(v string) (epoch int, upstream, revision string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, _ = strconv.Atoi(v[:i])
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// order is dpkg's weight of a character in a non-digit part: ~ sorts before everything, even the end of the part,
// letters before the other characters.
func order(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= '0' && c <= '9':
		return 0
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return int(c)
	}
	return int(c) + 256
}

func compareFragment(a, b string) int {
	for a != "" || b != "" {
		for (a != "" && !isDigit(a[0])) || (b != "" && !isDigit(b[0])) {
			// A digit and the end of the part both weigh 0, so equal weights here are two equal non-digits.
			var ca, cb int
			if a != "" {
				ca = order(a[0])
			}
			if b != "" {
				cb = order(b[0])
			}
			if ca != cb || a == "" || b == "" {
				return sign(ca - cb)
			}
			a, b = a[1:], b[1:]
		}
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		na, nb := digits(a), digits(b)
		if len(na) != len(nb) {
			return sign(len(na) - len(nb))
		}
		if c := strings.Compare(na, nb); c != 0 {
			return c
		}
		a, b = a[len(na):], b[len(nb):]
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func digits(s string) string {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return s[:i]
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
