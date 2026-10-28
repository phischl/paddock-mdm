package app_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// TestValidateMCPPolicy: mode all takes no operations, mode selected takes 1 … 500 distinct ids of exposed tools
// without a step-up, and every refusal is 400 invalid_request naming the offending value (plan M14 §3.4 item 17).
func TestValidateMCPPolicy(t *testing.T) {
	exposed := mcpcatalog.Exposed()
	if len(exposed) < 2 {
		t.Fatalf("the catalog exposes %d tools", len(exposed))
	}
	var hidden string
	for _, tool := range mcpcatalog.Tools() {
		if !tool.Expose && !tool.StepUp {
			hidden = tool.Name
			break
		}
	}
	if hidden == "" {
		t.Fatal("the catalog has no unexposed tool without a step-up")
	}
	many := make([]string, 501)
	for i := range many {
		many[i] = fmt.Sprintf("op%d", i)
	}
	for _, tc := range []struct {
		name   string
		in     app.MCPPolicyInput
		detail string // "" = valid
	}{
		{"all without operations", app.MCPPolicyInput{Enabled: true, Mode: "all"}, ""},
		{"all with an empty list", app.MCPPolicyInput{Mode: "all", AllowedOperations: []string{}}, ""},
		{"selected", app.MCPPolicyInput{Mode: "selected", AllowedOperations: []string{"listDevices", "createDeviceGroup"}}, ""},
		{"all with operations", app.MCPPolicyInput{Mode: "all", AllowedOperations: []string{"listDevices"}}, "mode all"},
		{"selected without operations", app.MCPPolicyInput{Mode: "selected", AllowedOperations: []string{}}, "at least one"},
		{"unknown mode", app.MCPPolicyInput{Mode: "some"}, `"some"`},
		{"unknown id", app.MCPPolicyInput{Mode: "selected", AllowedOperations: []string{"listDevices", "noSuchOperation"}}, `"noSuchOperation"`},
		{"step-up id", app.MCPPolicyInput{Mode: "selected", AllowedOperations: []string{"lockDevice"}}, `"lockDevice"`},
		{"unexposed id", app.MCPPolicyInput{Mode: "selected", AllowedOperations: []string{hidden}}, `"` + hidden + `"`},
		{"duplicate", app.MCPPolicyInput{Mode: "selected", AllowedOperations: []string{"listDevices", "getDevice", "listDevices"}}, `"listDevices" is listed twice`},
		{"501 ids", app.MCPPolicyInput{Mode: "selected", AllowedOperations: many}, "at most 500"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := app.ValidateMCPPolicy(tc.in)
			if tc.detail == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			var p *problem.Error
			if !errors.Is(err, problem.InvalidRequest) || !errors.As(err, &p) || !strings.Contains(p.Detail, tc.detail) {
				t.Fatalf("err = %v, want invalid_request naming %s", err, tc.detail)
			}
		})
	}
	// The bound is exactly 500: as many distinct exposed tools as the catalog has (up to 500) pass.
	ids := []string{}
	for _, tool := range exposed {
		if !tool.StepUp && len(ids) < app.MaxMCPAllowedOperations {
			ids = append(ids, tool.Name)
		}
	}
	if err := app.ValidateMCPPolicy(app.MCPPolicyInput{Mode: "selected", AllowedOperations: ids}); err != nil {
		t.Fatalf("%d exposed tools: %v", len(ids), err)
	}
}
