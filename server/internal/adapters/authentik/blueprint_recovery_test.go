package authentik

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestRecoveryFlowEveryStageNeedsTheLinkToken (ADR 0053 decision 2): every stage binding of paddock-recovery has the
// policy paddock-recovery-link-token bound, so a visitor without a one-time link (no restored plan, no user) is never
// shown the password prompt or the passkey setup. The blueprint is read as YAML nodes: it uses Authentik's custom tags.
func TestRecoveryFlowEveryStageNeedsTheLinkToken(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "deploy", "compose", "authentik", "blueprints", "paddock-recovery.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	field := func(m *yaml.Node, key string) *yaml.Node {
		if m == nil || m.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value == key {
				return m.Content[i+1]
			}
		}
		return nil
	}
	var stageBindings []string
	guarded := map[string]bool{}
	for _, e := range field(doc.Content[0], "entries").Content {
		switch field(e, "model").Value {
		case "authentik_flows.flowstagebinding":
			id := field(e, "id")
			if id == nil {
				t.Fatalf("a stage binding of paddock-recovery has no id: line %d", e.Line)
			}
			stageBindings = append(stageBindings, id.Value)
		case "authentik_policies.policybinding":
			ids := field(e, "identifiers")
			if field(ids, "policy").Value != "link-token" {
				continue
			}
			target := field(ids, "target")
			if target == nil {
				target = field(field(e, "attrs"), "target")
			}
			guarded[target.Value] = true
		}
	}
	if len(stageBindings) < 3 {
		t.Fatalf("stage bindings %v", stageBindings)
	}
	for _, b := range stageBindings {
		if !guarded[b] {
			t.Errorf("stage binding %s of paddock-recovery runs without the link token (bound to %v)", b,
				slices.Sorted(maps.Keys(guarded)))
		}
	}
}
