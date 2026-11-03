package reconcile

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// ReadOSRelease returns the variables of the system's os-release. /etc/os-release is usually a symlink to
// /usr/lib/os-release, which ReadFile reports as no data; os-release(5) names /usr/lib/os-release as the fallback.
func ReadOSRelease(sys System) (map[string]string, error) {
	data, _, err := sys.ReadFile("/etc/os-release")
	if data == nil {
		data, _, err = sys.ReadFile("/usr/lib/os-release")
	}
	if err != nil {
		return nil, fmt.Errorf("read os-release: %w", err)
	}
	vars := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			if u, err := strconv.Unquote(v); err == nil {
				v = u
			} else if n := len(v); n >= 2 && v[0] == '\'' && v[n-1] == '\'' {
				v = v[1 : n-1] // os-release(5) allows single quotes; enrollment strips them as well
			}
			vars[k] = v
		}
	}
	return vars, nil
}
