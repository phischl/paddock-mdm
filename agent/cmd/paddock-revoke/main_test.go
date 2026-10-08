package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/pkg/revocation"
)

// TestCapabilities (PDK-009): the build reports that it understands the volumes of Lock and self-lock tokens.
func TestCapabilities(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"capabilities"}, strings.NewReader(""), &out); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var c revocation.Capabilities
	if err := json.Unmarshal(out.Bytes(), &c); err != nil || !slices.Equal(c.Capabilities, []string{revocation.CapabilityVolumes}) {
		t.Fatalf("capabilities %s: %v", out.String(), err)
	}
}
