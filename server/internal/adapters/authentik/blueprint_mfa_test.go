package authentik

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The policies of the second-factor pair (ADR 0053 decision 3 and amendment e), defined in paddock-portal.yaml.
const (
	mfaPolicyAbsent = "paddock-mfa-enrol-at-login-absent"
	mfaPolicyAdmin  = "paddock-admin-login-webauthn-administrator"
	mfaPolicyEnrol  = "paddock-mfa-enrol-at-login"
	// setupLinkFile is the blueprint of the setup-link flow, whose bindings carry the link token
	// (TestRecoveryFlowEveryStageNeedsTheLinkToken).
	setupLinkFile = "paddock-recovery.yaml"
)

func productionBlueprintDir() string {
	return filepath.Join("..", "..", "..", "..", "deploy", "compose", "authentik", "blueprints")
}

// TestBlueprintsSetUpFactorsOnlyForAllowedAccounts (ADR 0053 amendment e, plan M12h-2 amendment e): in every production
// blueprint, a stage that sets up a second factor runs only where an administrator without a factor and without the
// enrolment mark cannot reach it. A validation stage that offers the setup is bound with the enrolment policy and has a
// deny sibling at the same order, bound with the policies that select exactly those administrators; a setup stage is
// bound directly only in the setup-link flow.
func TestBlueprintsSetUpFactorsOnlyForAllowedAccounts(t *testing.T) {
	problems, checked := checkFactorSetup(t, productionBlueprintDir())
	if checked < 5 {
		t.Errorf("checked %d bindings that offer a factor setup, want every pair of the portal and device sign-in", checked)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// TestBlueprintFactorSetupCheckFindsMissingBindings is the mutation check of the blueprint test: each removed policy
// binding, or a setup stage bound outside the setup-link flow, makes it fail.
func TestBlueprintFactorSetupCheckFindsMissingBindings(t *testing.T) {
	enrolBinding := "  - model: authentik_policies.policybinding\n    identifiers:\n" +
		"      policy: !Find [authentik_policies_expression.expressionpolicy, [name, paddock-mfa-enrol-at-login]]\n" +
		"      order: 3\n    attrs:\n      target: !KeyOf mfa-enrol-binding\n"
	adminBinding := "  - model: authentik_policies.policybinding\n    identifiers:\n" +
		"      policy: !Find [authentik_policies_expression.expressionpolicy, [name, paddock-admin-login-webauthn-administrator]]\n" +
		"      order: 7\n    attrs:\n      target: !KeyOf authorization-mfa-binding\n      failure_result: true\n"
	setupBinding := "  - model: authentik_flows.flowstagebinding\n    identifiers:\n      target: !KeyOf authentication-flow\n" +
		"      stage: !Find [authentik_stages_authenticator_totp.authenticatortotpstage, [name, default-authenticator-totp-setup]]\n" +
		"      order: 40\n"
	enrolStage := "      target: !KeyOf authentication-flow\n      stage: !KeyOf mfa-enrol\n      order: 30\n    attrs:\n" +
		"      evaluate_on_plan: false\n"
	denyStage := "      target: !KeyOf authorization-flow\n      stage: !KeyOf mfa\n      order: 10\n    attrs:\n" +
		"      evaluate_on_plan: false\n      re_evaluate_policies: true\n"
	for _, c := range []struct {
		name, file, old, new, want string
	}{
		{"enrolment planned up front", "paddock-device.yaml", enrolStage,
			strings.Replace(enrolStage, "evaluate_on_plan: false", "evaluate_on_plan: true", 1), "evaluated on the plan"},
		{"deny stage not re-evaluated", "paddock-device.yaml", denyStage,
			strings.Replace(denyStage, "re_evaluate_policies: true", "re_evaluate_policies: false", 1), "no deny sibling"},
		{"enrolment policy fails open", "paddock-device.yaml", enrolBinding,
			enrolBinding + "      failure_result: true\n", "fails open"},
		{"unresolvable stage reference", "paddock-device.yaml", enrolStage,
			strings.Replace(enrolStage, "stage: !KeyOf mfa-enrol", "stage: !KeyOf mfa-enrol-renamed", 1), "cannot be resolved"},
		{"enrolment policy of the device sign-in", "paddock-device.yaml", enrolBinding, "", "without the enrolment policy"},
		{"administrator policy of the device authorization", "paddock-device.yaml", adminBinding, "", "no deny sibling"},
		{"setup stage outside the setup link", "paddock-device.yaml", enrolBinding, enrolBinding + setupBinding, "outside the setup-link flow"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			src := productionBlueprintDir()
			entries, err := os.ReadDir(src)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				raw, err := os.ReadFile(filepath.Join(src, e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if e.Name() == c.file {
					if !strings.Contains(string(raw), c.old) {
						t.Fatalf("%s no longer contains the entry the mutation removes:\n%s", c.file, c.old)
					}
					raw = []byte(strings.Replace(string(raw), c.old, c.new, 1))
				}
				if err := os.WriteFile(filepath.Join(dir, e.Name()), raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			problems, _ := checkFactorSetup(t, dir)
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, c.want) }) {
				t.Errorf("the mutated blueprints pass: problems %q, want one naming %q", problems, c.want)
			}
		})
	}
}

// bpStage is a stage defined in a blueprint.
type bpStage struct {
	model, name, notConfigured string
}

// bpStageBinding is a flow stage binding of a blueprint; target and stage are canonical references.
type bpStageBinding struct {
	id, target, stage, order, mode string
	// evaluateOnPlan and reEvaluate are the binding's attributes as written, "" when omitted.
	evaluateOnPlan, reEvaluate string
	line                       int
}

// evaluatedWhenReached reports whether the binding's policies run when the stage is reached, for the identified user:
// a binding evaluated on the plan sees the anonymous user of a sign-in flow. Omitted attributes are Authentik's
// defaults (evaluate_on_plan false, re_evaluate_policies true).
func (b bpStageBinding) evaluatedWhenReached() bool {
	return b.evaluateOnPlan != "true" && b.reEvaluate != "false"
}

// bpPolicyBinding is a policy binding with its policy's name.
type bpPolicyBinding struct {
	policy        string
	failureResult bool
}

// checkFactorSetup returns the violations of the factor-setup rule in the blueprints of dir and the number of bindings
// of validation stages that offer a setup.
func checkFactorSetup(t *testing.T, dir string) (problems []string, checked int) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("blueprints in %s: %v %v", dir, files, err)
	}
	// Validation stages by name across all blueprints, because a binding may find a stage of another blueprint.
	byName := map[string]bpStage{}
	type parsed struct {
		file     string
		stages   map[string]bpStage
		bindings []bpStageBinding
		policies map[string][]bpPolicyBinding
	}
	var all []parsed
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		p := parsed{file: filepath.Base(f), stages: map[string]bpStage{}, policies: map[string][]bpPolicyBinding{}}
		policyNames := map[string]string{}
		entries := bpField(doc.Content[0], "entries")
		if entries == nil {
			t.Fatalf("%s has no entries", f)
		}
		for _, e := range entries.Content {
			model := bpField(e, "model").Value
			id := bpScalar(bpField(e, "id"))
			ids, attrs := bpField(e, "identifiers"), bpField(e, "attrs")
			switch {
			case model == "authentik_policies_expression.expressionpolicy":
				policyNames[id] = bpScalar(bpField(ids, "name"))
			case strings.HasPrefix(model, "authentik_stages_"):
				s := bpStage{model: model, name: bpScalar(bpField(ids, "name")),
					notConfigured: bpScalar(bpField(attrs, "not_configured_action"))}
				p.stages[id] = s
				byName[s.name] = s
			}
		}
		for _, e := range entries.Content {
			ids, attrs := bpField(e, "identifiers"), bpField(e, "attrs")
			switch bpField(e, "model").Value {
			case "authentik_flows.flowstagebinding":
				if bpScalar(bpField(e, "state")) == "absent" {
					continue
				}
				p.bindings = append(p.bindings, bpStageBinding{id: bpScalar(bpField(e, "id")),
					target: bpRef(bpField(ids, "target")), stage: bpRef(bpField(ids, "stage")),
					order: bpScalar(bpField(ids, "order")), mode: bpScalar(bpField(attrs, "policy_engine_mode")),
					evaluateOnPlan: bpScalar(bpField(attrs, "evaluate_on_plan")),
					reEvaluate:     bpScalar(bpField(attrs, "re_evaluate_policies")), line: e.Line})
			case "authentik_policies.policybinding":
				target := bpField(ids, "target")
				if target == nil {
					target = bpField(attrs, "target")
				}
				if target == nil || target.Tag != "!KeyOf" {
					continue
				}
				policy := bpField(ids, "policy")
				name := policyNames[policy.Value]
				if policy.Tag == "!Find" {
					name = bpFindName(policy)
				}
				p.policies[target.Value] = append(p.policies[target.Value], bpPolicyBinding{policy: name,
					failureResult: bpScalar(bpField(attrs, "failure_result")) == "true"})
			}
		}
		all = append(all, p)
	}
	stageOf := func(p parsed, ref string) (bpStage, bool) {
		if id, ok := strings.CutPrefix(ref, "key:"); ok {
			s, ok := p.stages[id]
			return s, ok
		}
		if name, ok := strings.CutPrefix(ref, "name:"); ok {
			if s, ok := byName[name]; ok {
				return s, true
			}
			// A setup stage Authentik ships (default-authenticator-*-setup) is found by name only.
			if strings.HasPrefix(name, "default-authenticator-") {
				return bpStage{model: "authentik_stages_authenticator_setup", name: name}, true
			}
		}
		return bpStage{}, false
	}
	has := func(bs []bpPolicyBinding, name string, failClosed bool) bool {
		return slices.ContainsFunc(bs, func(b bpPolicyBinding) bool { return b.policy == name && (!failClosed || b.failureResult) })
	}
	for _, p := range all {
		for _, b := range p.bindings {
			s, ok := stageOf(p, b.stage)
			if !ok {
				problems = append(problems, fmt.Sprintf("%s line %d: the stage reference %q cannot be resolved, so the "+
					"binding cannot be checked", p.file, b.line, strings.TrimSpace(b.stage)))
				continue
			}
			where := fmt.Sprintf("%s line %d (stage %s, order %s)", p.file, b.line, s.name, b.order)
			if !strings.HasPrefix(s.model, "authentik_stages_authenticator_") {
				continue
			}
			if s.model != "authentik_stages_authenticator_validate.authenticatorvalidatestage" {
				if p.file != setupLinkFile {
					problems = append(problems, where+": a factor setup stage is bound outside the setup-link flow")
				}
				continue
			}
			if s.notConfigured != "configure" {
				continue
			}
			checked++
			if b.id == "" || !has(p.policies[b.id], mfaPolicyEnrol, false) || b.mode != "all" {
				problems = append(problems, where+": the setup is offered without the enrolment policy "+mfaPolicyEnrol+
					" in policy engine mode all")
			}
			if has(p.policies[b.id], mfaPolicyEnrol, true) {
				problems = append(problems, where+": the enrolment policy fails open (failure_result true)")
			}
			if !b.evaluatedWhenReached() {
				problems = append(problems, where+": the setup binding is evaluated on the plan, not when the stage is reached")
			}
			denied := slices.ContainsFunc(p.bindings, func(o bpStageBinding) bool {
				d, ok := stageOf(p, o.stage)
				return ok && o.target == b.target && o.order == b.order && o.id != "" && o.mode == "all" && o.evaluatedWhenReached() &&
					d.model == s.model && d.notConfigured == "deny" &&
					has(p.policies[o.id], mfaPolicyAbsent, true) && has(p.policies[o.id], mfaPolicyAdmin, true)
			})
			if !denied {
				problems = append(problems, where+": no deny sibling at the same order bound with "+mfaPolicyAbsent+" and "+
					mfaPolicyAdmin+" (failure_result true, mode all, evaluated when reached)")
			}
		}
	}
	return problems, checked
}

func bpField(m *yaml.Node, key string) *yaml.Node {
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

func bpScalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// bpFindName returns the name a !Find [model, [name, <name>]] looks up, "" for another lookup.
func bpFindName(n *yaml.Node) string {
	for _, c := range n.Content {
		if c.Kind == yaml.SequenceNode && len(c.Content) == 2 && c.Content[0].Value == "name" {
			return c.Content[1].Value
		}
	}
	return ""
}

// bpRef is a canonical form of a reference: "key:<id>" for !KeyOf, "name:<name>" for a !Find by name, otherwise the
// node's YAML.
func bpRef(n *yaml.Node) string {
	switch {
	case n == nil:
		return ""
	case n.Tag == "!KeyOf":
		return "key:" + n.Value
	case n.Tag == "!Find" && bpFindName(n) != "":
		return "name:" + bpFindName(n)
	}
	out, _ := yaml.Marshal(n)
	return string(out)
}
