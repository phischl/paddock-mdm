package authentik

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestRecoveryFlowEveryStageNeedsTheLinkToken (ADR 0053 decision 2): every stage binding of paddock-recovery has the
// policy paddock-recovery-link-token bound, so a visitor without a one-time link (no restored plan, no user) is never
// shown the password prompt or the passkey setup. Exactly one of them, the deny stage at order 0, has it negated (and
// fails closed), so such a visitor is refused instead of silently redirected; every other binding has it as is. The
// blueprint is read as YAML nodes: it uses Authentik's custom tags.
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
	value := func(m *yaml.Node, key string) string {
		if n := field(m, key); n != nil {
			return n.Value
		}
		return ""
	}
	type linkTokenBinding struct{ negate, failureResult string }
	var stageBindings []string
	stageOf := map[string]string{}
	orderOf := map[string]string{}
	guarded := map[string][]linkTokenBinding{}
	denyStages := map[string]bool{}
	for _, e := range field(doc.Content[0], "entries").Content {
		switch field(e, "model").Value {
		case "authentik_stages_deny.denystage":
			denyStages[value(e, "id")] = true
		case "authentik_flows.flowstagebinding":
			id := field(e, "id")
			if id == nil {
				t.Fatalf("a stage binding of paddock-recovery has no id: line %d", e.Line)
			}
			stageBindings = append(stageBindings, id.Value)
			stageOf[id.Value] = value(field(e, "identifiers"), "stage")
			orderOf[id.Value] = value(field(e, "identifiers"), "order")
		case "authentik_policies.policybinding":
			ids := field(e, "identifiers")
			if field(ids, "policy").Value != "link-token" {
				continue
			}
			attrs := field(e, "attrs")
			target := field(ids, "target")
			if target == nil {
				target = field(attrs, "target")
			}
			guarded[target.Value] = append(guarded[target.Value],
				linkTokenBinding{negate: value(attrs, "negate"), failureResult: value(attrs, "failure_result")})
		}
	}
	if len(stageBindings) < 4 || len(denyStages) != 1 {
		t.Fatalf("stage bindings %v, deny stages %v", stageBindings, slices.Sorted(maps.Keys(denyStages)))
	}
	refusing := 0
	for _, b := range stageBindings {
		bound := guarded[b]
		if len(bound) != 1 {
			t.Errorf("stage binding %s of paddock-recovery has %d link token bindings, want 1 (bound to %v)", b,
				len(bound), slices.Sorted(maps.Keys(guarded)))
			continue
		}
		if !denyStages[stageOf[b]] {
			if bound[0].negate != "" && bound[0].negate != "false" {
				t.Errorf("stage binding %s of paddock-recovery runs without the link token (negate %s)", b, bound[0].negate)
			}
			continue
		}
		refusing++
		if bound[0].negate != "true" || bound[0].failureResult != "true" || orderOf[b] != "0" {
			t.Errorf("deny stage binding %s: order %s, negate %q, failure_result %q; want order 0, negate and "+
				"failure_result true, so a visitor without a valid link is refused first", b, orderOf[b],
				bound[0].negate, bound[0].failureResult)
		}
	}
	if refusing != 1 {
		t.Errorf("paddock-recovery binds the deny stage %d times, want once", refusing)
	}
}

// TestRecoveryFlowDenyMessage: the deny stage tells the visitor only that the link no longer works and what to do.
func TestRecoveryFlowDenyMessage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "compose", "authentik", "blueprints", "paddock-recovery.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Entries []struct {
			Model string `yaml:"model"`
			Ident struct {
				Name string `yaml:"name"`
			} `yaml:"identifiers"`
			Attrs struct {
				DenyMessage string `yaml:"deny_message"`
			} `yaml:"attrs"`
		} `yaml:"entries"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, e := range doc.Entries {
		if e.Model != "authentik_stages_deny.denystage" {
			continue
		}
		want := "This link is invalid, has expired or has already been used. Ask your administrator for a new link."
		if e.Ident.Name != "paddock-recovery-link-invalid" || e.Attrs.DenyMessage != want {
			t.Fatalf("deny stage %q says %q, want paddock-recovery-link-invalid saying %q", e.Ident.Name,
				e.Attrs.DenyMessage, want)
		}
		return
	}
	t.Fatal("deny stage paddock-recovery-link-invalid missing")
}

// TestRecoveryFlowPasswordOnlyForManagedAccounts (plan M12h-2 amendment f point 2 and its addendum point 2): both
// password stages of paddock-recovery are bound to the policy that requires an account without a usable password that
// Paddock created (paddock_managed true) or the host command marked (paddock_password_by_link true), so the link of an
// account synced from the organization's identity source only sets up the passkey.
func TestRecoveryFlowPasswordOnlyForManagedAccounts(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "deploy", "compose", "authentik", "blueprints", "paddock-recovery.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Entries []struct {
			Model string    `yaml:"model"`
			ID    string    `yaml:"id"`
			Ident yaml.Node `yaml:"identifiers"`
			Attrs yaml.Node `yaml:"attrs"`
		} `yaml:"entries"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	value := func(m yaml.Node, key string) string {
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value == key {
				return m.Content[i+1].Value
			}
		}
		return ""
	}
	expression := ""
	bound := map[string]bool{}
	for _, e := range doc.Entries {
		switch {
		case e.Model == "authentik_policies_expression.expressionpolicy" && e.ID == "password-missing":
			expression = value(e.Attrs, "expression")
		case e.Model == "authentik_policies.policybinding" && value(e.Ident, "policy") == "password-missing":
			bound[value(e.Attrs, "target")] = true
		}
	}
	want := `attrs = request.user.attributes
allowed = attrs.get("paddock_managed") is True or attrs.get("paddock_password_by_link") is True
return allowed and not request.user.has_usable_password()
`
	if expression != want {
		t.Fatalf("password policy %q, want %q", expression, want)
	}
	if !bound["prompt-binding"] || !bound["user-write-binding"] || len(bound) != 2 {
		t.Fatalf("password policy bound to %v, want exactly both password stages", slices.Sorted(maps.Keys(bound)))
	}
}

// TestServiceRoleEndsOlderLinks (plan M12h-2 amendment f point 1): the paddock-service role may list and delete
// tokens, which ending an account's older sign-in setup links needs, and nothing more on tokens (no view_token_key).
func TestServiceRoleEndsOlderLinks(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "deploy", "compose", "authentik", "blueprints", "paddock-portal.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Entries []struct {
			ID    string `yaml:"id"`
			Attrs struct {
				Permissions []string `yaml:"permissions"`
			} `yaml:"attrs"`
		} `yaml:"entries"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, e := range doc.Entries {
		if e.ID != "service-role" {
			continue
		}
		var token []string
		for _, p := range e.Attrs.Permissions {
			if strings.HasPrefix(p, "authentik_core.") && strings.Contains(p, "_token") {
				token = append(token, p)
			}
		}
		slices.Sort(token)
		if want := []string{"authentik_core.delete_token", "authentik_core.view_token"}; !slices.Equal(token, want) {
			t.Fatalf("token permissions %v, want %v", token, want)
		}
		return
	}
	t.Fatal("role paddock-service missing")
}

// promptField is a prompt field of a Paddock blueprint.
type promptField struct {
	file, id, key, typ, placeholder, initial, initialExpr string
}

// blueprintPromptFields reads every prompt field of the Paddock blueprints.
func blueprintPromptFields(t *testing.T) []promptField {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "deploy", "compose", "authentik", "blueprints", "*.yaml"))
	if err != nil || len(files) < 5 {
		t.Fatalf("blueprints %v %v", files, err)
	}
	var out []promptField
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Entries []struct {
				Model string `yaml:"model"`
				ID    string `yaml:"id"`
				Attrs struct {
					FieldKey    string `yaml:"field_key"`
					Type        string `yaml:"type"`
					Placeholder string `yaml:"placeholder"`
					Initial     string `yaml:"initial_value"`
					InitialExpr string `yaml:"initial_value_expression"`
				} `yaml:"attrs"`
			} `yaml:"entries"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, e := range doc.Entries {
			if e.Model == "authentik_stages_prompt.prompt" {
				out = append(out, promptField{file: filepath.Base(path), id: e.ID, key: e.Attrs.FieldKey, typ: e.Attrs.Type,
					placeholder: e.Attrs.Placeholder, initial: e.Attrs.Initial, initialExpr: e.Attrs.InitialExpr})
			}
		}
	}
	return out
}

// TestNoPromptLetsUsersWriteAttributes (plan M12h-2 amendment f addendum): paddock_password_by_link and
// paddock_managed decide whether a link may set a password, so no prompt of a Paddock flow may let a user write a user
// attribute. Authentik's user-write stage stores every prompt value whose key starts with attributes. or attributes_
// (or is attributes); the one such field is the recovery flow's hidden field, whose value Authentik takes from the
// server and which never stores true.
func TestNoPromptLetsUsersWriteAttributes(t *testing.T) {
	fields := blueprintPromptFields(t)
	if len(fields) < 3 {
		t.Fatalf("prompt fields %v", fields)
	}
	writesAttributes := func(key string) bool {
		return key == "attributes" || strings.HasPrefix(key, "attributes.") || strings.HasPrefix(key, "attributes_")
	}
	var found []string
	for _, f := range fields {
		if !writesAttributes(f.key) {
			continue
		}
		found = append(found, f.file+":"+f.id)
		if f.file != "paddock-recovery.yaml" || f.key != "attributes.paddock_password_by_link" || f.typ != "hidden" {
			t.Errorf("%s %s: prompt field %q of type %q lets a user write an attribute", f.file, f.id, f.key, f.typ)
		}
		if f.placeholder != "used" || f.initial != "used" || f.initialExpr == "true" {
			t.Errorf("%s %s: hidden value %q/%q (expression %q), want the fixed value used", f.file, f.id, f.placeholder,
				f.initial, f.initialExpr)
		}
	}
	if !slices.Equal(found, []string{"paddock-recovery.yaml:field-password-by-link-used"}) {
		t.Fatalf("attribute fields %v, want only the recovery flow's spend field", found)
	}
}

// TestRecoveryFlowSpendsPasswordByLink (plan M12h-2 amendment f addendum): the spend field belongs to the password
// prompt, which runs only together with the user-write stage that stores it, so the attribute is overwritten exactly
// when the link sets the password.
func TestRecoveryFlowSpendsPasswordByLink(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "deploy", "compose", "authentik", "blueprints", "paddock-recovery.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Entries []struct {
			Model string `yaml:"model"`
			ID    string `yaml:"id"`
			Attrs struct {
				Fields []yaml.Node `yaml:"fields"`
			} `yaml:"attrs"`
		} `yaml:"entries"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, e := range doc.Entries {
		if e.Model != "authentik_stages_prompt.promptstage" {
			continue
		}
		var ids []string
		for _, f := range e.Attrs.Fields {
			ids = append(ids, f.Value)
		}
		if e.ID != "prompt" || !slices.Equal(ids, []string{"field-password", "field-password-repeat", "field-password-by-link-used"}) {
			t.Fatalf("prompt stage %s fields %v, want the password prompt with the spend field", e.ID, ids)
		}
		return
	}
	t.Fatal("password prompt stage missing")
}

// TestServiceRoleReadsSourceConnections (plan M12h-2 amendment f addendum point 1): the paddock-service role may list
// every account's upstream source connections; without the global permission Authentik answers only the role's own,
// and the host command would let a synced platform administrator's link set a password.
func TestServiceRoleReadsSourceConnections(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "compose", "authentik", "blueprints", "paddock-portal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Entries []struct {
			ID    string `yaml:"id"`
			Attrs struct {
				Permissions []string `yaml:"permissions"`
			} `yaml:"attrs"`
		} `yaml:"entries"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, e := range doc.Entries {
		if e.ID == "service-role" {
			if !slices.Contains(e.Attrs.Permissions, "authentik_core.view_usersourceconnection") {
				t.Fatalf("permissions %v lack authentik_core.view_usersourceconnection", e.Attrs.Permissions)
			}
			return
		}
	}
	t.Fatal("role paddock-service missing")
}
