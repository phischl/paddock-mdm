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
	for _, bad := range []string{"", "timestamp:1700000000\tfile:paddockd", "paddockd 1.2.3 amd64", "paddock-agent version= arch=amd64",
		"paddock-agent version=1.2.3 arch=", "paddock-agent version=1.2.3", "paddock-agent version=1.2.3 arch=amd64 extra",
		" paddock-agent version=1.2.3 arch=amd64"} {
		if _, _, ok := releasesig.Parse(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}
