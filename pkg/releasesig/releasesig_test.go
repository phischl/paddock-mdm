package releasesig_test

import (
	"testing"

	"github.com/phischl/paddock-mdm/pkg/releasesig"
)

func TestParse(t *testing.T) {
	c := releasesig.Comment("1.2.3-rc.1", "amd64")
	if c != "paddock-agent version=1.2.3-rc.1 arch=amd64" {
		t.Fatalf("comment %q", c)
	}
	if v, a, ok := releasesig.Parse(c); !ok || v != "1.2.3-rc.1" || a != "amd64" {
		t.Fatalf("parse: %q %q %v", v, a, ok)
	}
	// The server and the supervisor compare the signed version with the release version for equality (PDK-022): every
	// pre-release of the sequence round-trips unchanged, so neighbouring pre-releases never match each other.
	for _, v := range []string{"0.1.0-alpha.1", "0.1.0-alpha.2", "0.1.0-beta.1", "0.1.0-rc.1", "0.1.0"} {
		if got, a, ok := releasesig.Parse(releasesig.Comment(v, "arm64")); !ok || got != v || a != "arm64" {
			t.Errorf("parse %s: %q %q %v", v, got, a, ok)
		}
	}
	for _, bad := range []string{"", "timestamp:1700000000\tfile:paddockd", "paddockd 1.2.3 amd64", "paddock-agent version= arch=amd64",
		"paddock-agent version=1.2.3 arch=", "paddock-agent version=1.2.3", "paddock-agent version=1.2.3 arch=amd64 extra",
		" paddock-agent version=1.2.3 arch=amd64"} {
		if _, _, ok := releasesig.Parse(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}
