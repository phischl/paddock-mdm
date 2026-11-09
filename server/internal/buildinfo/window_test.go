package buildinfo

import (
	"os"
	"regexp"
	"slices"
	"testing"

	"github.com/phischl/paddock-mdm/pkg/semver"
)

var seq = []string{"0.1.0-alpha.5", "0.1.0-alpha.6", "0.1.0-alpha.7", "0.1.0-alpha.8", "0.1.0-alpha.9"}

func TestWindowOf(t *testing.T) {
	for _, c := range []struct {
		target string
		want   []string
	}{
		{"0.1.0-alpha.9", []string{"0.1.0-alpha.7", "0.1.0-alpha.8", "0.1.0-alpha.9"}},
		{"0.1.0-alpha.7", []string{"0.1.0-alpha.5", "0.1.0-alpha.6", "0.1.0-alpha.7"}},
		{"0.1.0-alpha.6", []string{"0.1.0-alpha.5", "0.1.0-alpha.6"}},
		{"0.1.0-alpha.5", []string{"0.1.0-alpha.5"}},
		{"0.1.0-alpha.10", nil},
		{"unknown", nil},
		{"", nil},
	} {
		if got := windowOf(seq, c.target); !slices.Equal(got, c.want) {
			t.Errorf("windowOf(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}

func TestOutside(t *testing.T) {
	window := windowOf(seq, "0.1.0-alpha.9")
	for v, want := range map[string]bool{
		"0.1.0-alpha.6":         true,
		"0.1.0-alpha.1":         true, // older than every known release
		"0.0.1":                 true,
		"0.1.0-alpha.6+build":   true,
		"0.1.0-alpha.7":         false,
		"0.1.0-alpha.8":         false,
		"0.1.0-alpha.9":         false,
		"0.1.0-alpha.10":        false, // newer than the server
		"0.1.0":                 false,
		"0.0.0-dev":             false,
		"0.0.0-devicesim":       false,
		"0.2.1700000000-good":   false,
		"edge-20261104-abcdef0": false,
		"":                      false,
	} {
		if got := Outside(window, v); got != want {
			t.Errorf("Outside(%q) = %v, want %v", v, got, want)
		}
	}
	if Outside(nil, "0.0.1") {
		t.Error("an empty window judged a version")
	}
}

// TestOlderRelease: release versions compare by SemVer precedence (alpha.10 after alpha.9), build metadata ignored;
// development builds are never older.
func TestOlderRelease(t *testing.T) {
	for v, want := range map[string]bool{
		"0.1.0-alpha.9":        true,
		"0.1.0-alpha.9+build":  true,
		"0.1.0-alpha.10":       false,
		"0.1.0-alpha.10+build": false,
		"0.1.0-alpha.11":       false,
		"0.1.0":                false,
		"0.0.0-dev":            false,
		"":                     false,
	} {
		if got := OlderRelease(v, "0.1.0-alpha.10"); got != want {
			t.Errorf("OlderRelease(%q) = %v, want %v", v, got, want)
		}
	}
}

// TestReleaseSequence: the generated list is ordered, ends with the release under development and holds every
// release section of CHANGELOG.md (a stale list fails here: run make gen).
func TestReleaseSequence(t *testing.T) {
	got := ReleaseSequence()
	if len(got) == 0 || !slices.IsSortedFunc(got, semver.Compare) {
		t.Fatalf("sequence %v is not in SemVer order", got)
	}
	if Current() != got[len(got)-1] && !slices.Contains(got, Version) {
		t.Errorf("Current() = %q", Current())
	}
	raw, err := os.ReadFile("../../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`(?m)^## \[([^\]]+)\] - `).FindAllSubmatch(raw, -1) {
		if v := string(m[1]); !slices.Contains(got, v) {
			t.Errorf("release %s of CHANGELOG.md is missing from releases.gen.go: run make gen", v)
		}
	}
	if w := Window(Current()); len(w) == 0 || w[len(w)-1] != Current() {
		t.Errorf("Window(Current()) = %v", w)
	}
}
