package declarative_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
)

// softwareDoc is a configuration with the three software sections only.
func softwareDoc() declarative.Document {
	return declarative.Document{
		APIVersion: declarative.APIVersion, Kind: declarative.Kind,
		SoftwareSources: &[]declarative.SoftwareSource{{
			Slug: "vendor", Kind: "apt", Name: "Vendor", URIs: []string{"https://apt.example.com"}, Suites: []string{"stable"},
			Components: []string{"main"}, Architectures: []string{}, SigningKey: "KEY", Fingerprint: strings.Repeat("A", 40),
		}},
		SoftwareCatalog: &[]declarative.SoftwareCatalogEntry{{
			Name: "Browser", Source: ptr("vendor"),
			Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "browser"}},
		}},
		SoftwareAssignments: &[]declarative.SoftwareAssignment{
			{Entry: "Browser", Target: declarative.SoftwareTarget{Type: "organization"}, Intent: "required", UpdateRule: "latest"},
			{Entry: "Browser", Target: declarative.SoftwareTarget{Type: "device_group", Name: "laptops"}, Intent: "forbid", UpdateRule: "latest"},
			{Entry: "Browser", Target: declarative.SoftwareTarget{Type: "user", Username: "ada@example.com"}, Intent: "available", UpdateRule: "latest"},
			{Entry: "Browser", Target: declarative.SoftwareTarget{Type: "user_group", Slug: "devs"}, Intent: "available", UpdateRule: "latest"},
		},
	}
}

func TestSoftwareSectionsOrder(t *testing.T) {
	s := declarative.Sections()
	i := slices.Index(s, declarative.SectionSettingsUpdates)
	want := []string{declarative.SectionSoftwareSources, declarative.SectionSoftwareCatalog, declarative.SectionSoftwareAssignments}
	if !slices.Equal(s[i+1:i+4], want) {
		t.Fatalf("Sections = %v, want the software sections after settings.updates", s)
	}
	if !slices.Contains(declarative.RolloutSections(), declarative.SectionSoftwareAssignments) ||
		slices.Contains(declarative.RolloutSections(), declarative.SectionSoftwareSources) ||
		slices.Contains(declarative.RolloutSections(), declarative.SectionSoftwareCatalog) {
		t.Fatalf("RolloutSections = %v, want software_assignments only", declarative.RolloutSections())
	}
}

func TestSoftwareAssignmentKeys(t *testing.T) {
	want := []string{
		`[null,"Browser","organization",null]`,
		`["laptops","Browser","device_group",null]`,
		`[null,"Browser","user","ada@example.com"]`,
		`[null,"Browser","user_group","devs"]`,
	}
	for i, a := range *softwareDoc().SoftwareAssignments {
		if got := a.Key().String(); got != want[i] {
			t.Errorf("key of %+v = %s, want %s", a.Target, got, want[i])
		}
	}
	if got := (declarative.SoftwareSource{Slug: "vendor"}).Key().String(); got != `["vendor"]` {
		t.Errorf("source key = %s", got)
	}
	if got := (declarative.SoftwareCatalogEntry{Name: "Browser"}).Key().String(); got != `["Browser"]` {
		t.Errorf("entry key = %s", got)
	}
}

func TestDiffSoftwareSections(t *testing.T) {
	cur, want := softwareDoc(), softwareDoc()
	if p := declarative.Diff(cur, want); len(p.Changes) != 0 || p.RequiresStepUp != nil {
		t.Fatalf("same document: %+v", p)
	}
	(*want.SoftwareCatalog)[0].Description = "A browser"
	(*want.SoftwareAssignments)[0].Intent = "hold"
	*want.SoftwareAssignments = (*want.SoftwareAssignments)[:3]
	plan := declarative.Diff(cur, want)
	got := []string{}
	for _, c := range plan.Changes {
		got = append(got, c.Action+" "+c.Section+" "+c.Key)
	}
	wantChanges := []string{
		`delete software_assignments [null,"Browser","user_group","devs"]`,
		`update software_catalog ["Browser"]`,
		`update software_assignments [null,"Browser","organization",null]`,
	}
	if !slices.Equal(got, wantChanges) {
		t.Fatalf("changes = %q, want %q", got, wantChanges)
	}
	if plan.RequiresStepUp != nil {
		t.Fatalf("requires_step_up without a source change: %v", plan.RequiresStepUp)
	}
	// A plan field is a string, number, boolean, list of strings or null, so the plan hash stays deterministic.
	for _, c := range declarative.Diff(declarative.Document{}, softwareDoc()).Changes {
		for _, f := range c.Fields {
			switch f.After.(type) {
			case string, bool, int, []string, nil:
			default:
				t.Errorf("%s.%s is %T", c.Section, f.Name, f.After)
			}
		}
	}
}

func TestDiffSourceChangeRequiresStepUp(t *testing.T) {
	cur, want := softwareDoc(), softwareDoc()
	(*want.SoftwareSources)[0].Name = "Vendor repository"
	plan := declarative.Diff(cur, want)
	if !slices.Equal(plan.RequiresStepUp, []string{declarative.SectionSoftwareSources}) {
		t.Fatalf("requires_step_up = %v", plan.RequiresStepUp)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"requires_step_up":["software_sources"]`) {
		t.Fatalf("plan JSON %s", raw)
	}
	// The source's key shows as its hash, like a file's content.
	(*want.SoftwareSources)[0].SigningKey = "OTHER"
	for _, c := range declarative.Diff(cur, want).Changes {
		for _, f := range c.Fields {
			if f.Name == "signing_key" && f.After != declarative.ContentSummary("OTHER") {
				t.Fatalf("signing_key shown as %v", f.After)
			}
		}
	}
}

func TestPlanWithoutStepUpOmitsTheField(t *testing.T) {
	raw, err := json.Marshal(declarative.Diff(softwareDoc(), softwareDoc()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "requires_step_up") {
		t.Fatalf("plan JSON %s", raw)
	}
}

func TestDecodeSoftwareDefaults(t *testing.T) {
	raw := `{"api_version":"paddock/v1","kind":"OrganizationConfig",
	"software_sources":[{"slug":"vendor","name":"Vendor","uris":["https://apt.example.com"],"signing_key":"K","fingerprint":"F"}],
	"software_catalog":[{"name":"Browser","packages":[{"distribution":"ubuntu","release":"*","architecture":"*","package":"browser"}]}],
	"software_assignments":[{"entry":"Browser","target":{"type":"organization"},"intent":"required"}]}`
	if err := declarative.ValidateJSON([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	d, err := declarative.Decode([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	s := (*d.SoftwareSources)[0]
	if s.Kind != "apt" || s.Suites == nil || s.Components == nil || s.Architectures == nil {
		t.Fatalf("source defaults: %+v", s)
	}
	if e := (*d.SoftwareCatalog)[0]; e.Source != nil || e.Description != "" {
		t.Fatalf("entry defaults: %+v", e)
	}
}

func TestValidateSoftwareSections(t *testing.T) {
	for name, doc := range map[string]string{
		"assignment without target": `"software_assignments":[{"entry":"Browser","intent":"required"}]`,
		"target of two kinds":       `"software_assignments":[{"entry":"B","target":{"type":"user","slug":"x"},"intent":"required"}]`,
		"unknown intent":            `"software_assignments":[{"entry":"B","target":{"type":"organization"},"intent":"maybe"}]`,
		"source without key":        `"software_sources":[{"slug":"vendor","name":"V","uris":["https://a"],"fingerprint":"F"}]`,
		"entry without packages":    `"software_catalog":[{"name":"B","packages":[]}]`,
	} {
		raw := `{"api_version":"paddock/v1","kind":"OrganizationConfig",` + doc + `}`
		if err := declarative.ValidateJSON([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRevertSoftwareSections(t *testing.T) {
	cur, want := softwareDoc(), softwareDoc()
	(*want.SoftwareAssignments)[1].Intent = "uninstall"
	*want.SoftwareSources = append(*want.SoftwareSources, declarative.SoftwareSource{Slug: "other", Kind: "apt", Name: "Other"})
	plan := declarative.Diff(cur, want)
	items := declarative.BeforeItems(cur, plan)
	before := map[string]map[string]json.RawMessage{}
	for section, keys := range items {
		before[section] = map[string]json.RawMessage{}
		for k, v := range keys {
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			before[section][k] = raw
		}
	}
	got, err := declarative.Revert(want, plan, before)
	if err != nil {
		t.Fatal(err)
	}
	if p := declarative.Diff(got, cur); len(p.Changes) != 0 {
		t.Fatalf("revert left changes: %+v", p.Changes)
	}
}
