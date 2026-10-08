package schema_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/phischl/paddock-mdm/cli/internal/schema"
)

// TestCopyIsCurrent: the embedded schema equals api/schema/paddock.v1.json (make gen copies it).
func TestCopyIsCurrent(t *testing.T) {
	want, err := os.ReadFile("../../../api/schema/paddock.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(schema.JSON, want) {
		t.Fatal("cli/internal/schema/paddock.v1.json differs from api/schema/paddock.v1.json: run make gen")
	}
}
