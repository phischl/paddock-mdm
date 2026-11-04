package migrate

import (
	"testing"
	"testing/fstest"
)

func TestLatest(t *testing.T) {
	fsys := fstest.MapFS{
		"paddock/00001_init.sql":    {},
		"paddock/00102_schema.sql":  {},
		"paddock/00099_other.sql":   {},
		"paddock/README.md":         {},
		"paddock/00200_draft.sql.x": {},
	}
	if v, err := latest(fsys, "paddock"); err != nil || v != 102 {
		t.Fatalf("latest = %d, %v", v, err)
	}
	if _, err := latest(fstest.MapFS{"paddock/x_bad.sql": {}}, "paddock"); err == nil {
		t.Error("a file without a version prefix was accepted")
	}
	if v, err := LatestPaddock(); err != nil || v < 102 {
		t.Errorf("LatestPaddock = %d, %v", v, err)
	}
}
