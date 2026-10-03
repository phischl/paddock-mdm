package admin

import (
	"net/url"
	"strings"
)

// ValidReturnTo accepts only relative paths on this host: they start with "/" but not "//" or "/\", contain no
// scheme, host, backslash or control characters.
func ValidReturnTo(s string) bool {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\\\r\n\t") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return false
	}
	return strings.HasPrefix(u.Path, "/") && !strings.HasPrefix(u.Path, "//")
}
