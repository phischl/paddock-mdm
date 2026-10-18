package agent

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/testgw"
)

// TestCheckinReportsHostname (plan M8h decision 8): every check-in carries the kernel hostname in its health.
func TestCheckinReportsHostname(t *testing.T) {
	a := newAgent(t, testgw.New(t))
	want, err := os.Hostname()
	if err != nil {
		t.Skipf("no hostname: %v", err)
	}
	var h struct {
		Hostname string `json:"hostname"`
	}
	if err := json.Unmarshal(a.checkinRequest(context.Background()).Health, &h); err != nil || h.Hostname != want {
		t.Fatalf("health hostname %q (%v), want %q", h.Hostname, err, want)
	}
}
