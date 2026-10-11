package semver_test

import (
	"testing"

	"github.com/phischl/paddock-mdm/pkg/semver"
)

// ordered is ascending by SemVer 2.0.0 precedence: its own example list, Paddock's pre-release sequence, build
// metadata and wide numbers.
var ordered = []string{"0.0.0-dev", "0.1.0-alpha.1", "0.1.0-alpha.2", "0.1.0-beta.1", "0.1.0-rc.1", "0.1.0", "0.2.0",
	"0.9.0", "0.10.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
	"1.0.0-rc.1", "1.0.0", "1.0.1", "1.2.0", "1.10.0", "2.0.0", "10.0.0"}

func TestCompare(t *testing.T) {
	for i, a := range ordered {
		for j, b := range ordered {
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			if got := semver.Compare(a, b); got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", a, b, got, want)
			}
		}
	}
}

func TestCompareBuildMetadataAndSystemTestVersions(t *testing.T) {
	if semver.Compare("1.0.0+build.1", "1.0.0+build.2") != 0 || semver.Compare("0.2.1700000000-good", "0.1.0") != 1 {
		t.Error("build metadata or system test versions ordered wrongly")
	}
}
