package mcpgen

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

const fixture = "testdata/admin.yaml"

func fixtureTools(t *testing.T) map[string]Tool {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	list, err := Build(doc)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Tool{}
	for _, tl := range list {
		byName[tl.Name] = tl
	}
	return byName
}

func schemaOf(t *testing.T, tl Tool) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(tl.InputSchema, &m); err != nil {
		t.Fatalf("%s: input schema is not JSON: %v", tl.Name, err)
	}
	return m
}

// TestGolden: the generated file for the fixture contract is byte-identical to testdata/catalog.golden. Regenerate
// after an intended change with `go run ../../cmd/mcpgen -spec testdata/admin.yaml -out testdata/catalog.golden`.
func TestGolden(t *testing.T) {
	got, err := Generate(fixture)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/catalog.golden")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("generated catalog differs from testdata/catalog.golden")
	}
	if !strings.HasPrefix(string(got), header+"\n") {
		t.Errorf("generated file does not start with %q", header)
	}
}

func TestDeterministic(t *testing.T) {
	first, err := Generate(fixture)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		again, err := Generate(fixture)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatal("two runs over the same contract differ")
		}
	}
}

func TestSelectionAndOrder(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	list, err := Build(doc)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range list {
		names = append(names, tl.Name)
		if tl.Pattern != tl.Method+" "+tl.Path {
			t.Errorf("%s: pattern %q is not %q", tl.Name, tl.Pattern, tl.Method+" "+tl.Path)
		}
	}
	if !slices.IsSorted(names) {
		t.Errorf("tools are not sorted by name: %v", names)
	}
	if slices.Contains(names, "login") {
		t.Error("an operation of tag auth is in the catalog")
	}
	if len(names) != 13 {
		t.Errorf("got %d tools, want the 13 non-auth operations of the fixture", len(names))
	}
}

func TestClassification(t *testing.T) {
	tools := fixtureTools(t)
	cases := []struct {
		name                                   string
		class, scope                           string
		destructive, idempotent, expose, stepU bool
	}{
		{"listThings", "read", "organization", false, true, true, false},
		{"createThing", "write", "organization", false, false, true, false},
		{"replaceThing", "write", "organization", false, true, true, false},
		{"deleteThing", "write", "organization", true, true, true, false},
		{"lockThing", "write", "organization", true, false, false, true},
		{"approveThing", "write", "organization", false, false, true, false},
		{"suspendThingLogins", "write", "organization", true, false, true, false},
		{"exportThing", "read", "organization", false, true, false, false},
		{"uploadBlob", "write", "platform", false, true, false, false},
		{"getMe", "read", "any", false, true, true, false},
		{"updateMe", "write", "any", false, false, false, false},
		{"getMySettings", "read", "any", false, true, true, false},
		{"getMcpCatalog", "read", "any", false, true, false, false},
	}
	for _, c := range cases {
		tl, ok := tools[c.name]
		if !ok {
			t.Errorf("%s missing", c.name)
			continue
		}
		if tl.Class != c.class || tl.Scope != c.scope || tl.Destructive != c.destructive ||
			tl.Idempotent != c.idempotent || tl.Expose != c.expose || tl.StepUp != c.stepU {
			t.Errorf("%s: got class %s scope %s destructive %t idempotent %t expose %t stepUp %t", c.name,
				tl.Class, tl.Scope, tl.Destructive, tl.Idempotent, tl.Expose, tl.StepUp)
		}
	}
	if !tools["getMe"].Bootstrap || !tools["getMcpCatalog"].Bootstrap || tools["listThings"].Bootstrap {
		t.Error("bootstrap flags do not follow x-paddock-mcp")
	}
	if tools["createThing"].AuditCode != "thing.created" || tools["createThing"].Tag != "things" {
		t.Errorf("createThing: audit code %q tag %q", tools["createThing"].AuditCode, tools["createThing"].Tag)
	}
}

func TestDescription(t *testing.T) {
	tools := fixtureTools(t)
	want := "List things\n\nRoles: everyone. Lists the things of the organization.\n\nRead-only. Paged: page, " +
		"page_size (10/25/50/100), sort (allow list: name, created_at), q (search over: name)."
	if got := tools["listThings"].Description; got != want {
		t.Errorf("listThings description:\n got %q\nwant %q", got, want)
	}
	if got := tools["createThing"].Description; got != "Create a thing\n\nChanges data; needs your MCP write access." {
		t.Errorf("createThing description %q", got)
	}
	if got := tools["deleteThing"].Description; got != "Changes data; needs your MCP write access." {
		t.Errorf("deleteThing description %q", got)
	}
}

func TestInputSchema(t *testing.T) {
	tools := fixtureTools(t)
	for _, tl := range tools {
		s := string(tl.InputSchema)
		for _, banned := range []string{`"$ref"`, `"nullable"`, `"readOnly"`, `X-Paddock-CSRF`} {
			if strings.Contains(s, banned) {
				t.Errorf("%s: input schema contains %s: %s", tl.Name, banned, s)
			}
		}
	}

	list := schemaOf(t, tools["listThings"])
	props := list["properties"].(map[string]any)
	if _, ok := props["page"]; !ok {
		t.Error("listThings lacks the query parameter page")
	}
	state := props["state"].(map[string]any)
	if state["description"] != "Repeatable state filter." || state["type"] != "array" {
		t.Errorf("listThings state: %v", state)
	}
	if _, ok := list["required"]; ok {
		t.Errorf("listThings has required arguments: %v", list["required"])
	}

	create := schemaOf(t, tools["createThing"])
	if req := create["required"].([]any); !slices.Equal(req, []any{"body"}) {
		t.Errorf("createThing required %v, want [body]", req)
	}
	body := create["properties"].(map[string]any)["body"].(map[string]any)
	bodyProps := body["properties"].(map[string]any)
	if _, ok := bodyProps["id"]; ok {
		t.Error("readOnly property id was not dropped")
	}
	if req := body["required"].([]any); !slices.Equal(req, []any{"name"}) {
		t.Errorf("body required %v, want [name] after dropping the readOnly id", req)
	}
	if note := bodyProps["note"].(map[string]any); !slices.Equal(note["type"].([]any), []any{"string", "null"}) {
		t.Errorf("nullable note: %v", note)
	}
	level := bodyProps["level"].(map[string]any)
	if !slices.Equal(level["enum"].([]any), []any{"low", "high", nil}) {
		t.Errorf("nullable enum level: %v", level)
	}
	mode := bodyProps["mode"].(map[string]any)
	anyOf, ok := mode["anyOf"].([]any)
	if !ok || len(anyOf) != 2 || anyOf[1].(map[string]any)["type"] != "null" {
		t.Errorf("nullable allOf mode is not an anyOf with null: %v", mode)
	}
	if items := bodyProps["tags"].(map[string]any)["items"].(map[string]any); items["description"] != "The mode." {
		t.Errorf("referenced item schema was not inlined: %v", items)
	}
	if body["additionalProperties"] != false {
		t.Errorf("additionalProperties lost: %v", body["additionalProperties"])
	}

	replace := schemaOf(t, tools["replaceThing"])
	if req := replace["required"].([]any); !slices.Equal(req, []any{"id"}) {
		t.Errorf("replaceThing required %v, want only the path parameter id (optional body)", req)
	}
	upload := schemaOf(t, tools["uploadBlob"])
	if _, ok := upload["properties"].(map[string]any)["body"]; ok {
		t.Error("a non-JSON request body became a body argument")
	}
}

func TestVersionIsHashOfTable(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	list, err := Build(doc)
	if err != nil {
		t.Fatal(err)
	}
	v, err := version(list)
	if err != nil {
		t.Fatal(err)
	}
	src, err := render(list)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 64 || !strings.Contains(string(src), `const Version = "`+v+`"`) {
		t.Errorf("version %q not rendered", v)
	}
	list[0].Description += "."
	if changed, _ := version(list); changed == v {
		t.Error("version did not change with the table")
	}
}

func TestRejectsBadAnnotations(t *testing.T) {
	cases := map[string]map[string]any{
		"unknown key":     {"x-paddock-mcp": map[string]any{"exposed": false}},
		"non-bool value":  {"x-paddock-mcp": map[string]any{"expose": "no"}},
		"not an object":   {"x-paddock-mcp": false},
		"step-up string":  {"x-paddock-step-up": "true"},
		"audit not text":  {"x-paddock-audit": 1},
		"list sort shape": {"x-paddock-list": map[string]any{"sort": "name"}},
	}
	for name, ext := range cases {
		op := openapi3.NewOperation()
		op.OperationID = "op"
		op.Extensions = ext
		if _, err := buildTool("GET", "/api/v1/x", &openapi3.PathItem{}, op); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRejectsRecursiveSchema(t *testing.T) {
	node := &openapi3.Schema{Type: &openapi3.Types{"object"}}
	node.Properties = openapi3.Schemas{"child": &openapi3.SchemaRef{Ref: "#/components/schemas/Node", Value: node}}
	if _, err := convert(&openapi3.SchemaRef{Value: node}, map[*openapi3.Schema]bool{}); err == nil {
		t.Error("a recursive schema was inlined")
	}
}

func jsonBody() *openapi3.MediaType {
	return &openapi3.MediaType{Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"object"}}}}
}

func okResponses() *openapi3.Responses {
	return openapi3.NewResponses(openapi3.WithStatus(204, &openapi3.ResponseRef{Value: openapi3.NewResponse()}))
}

func TestRequestContentMustBeExactlyJSON(t *testing.T) {
	cases := map[string]struct {
		content openapi3.Content
		expose  bool
	}{
		"json only":         {openapi3.Content{"application/json": jsonBody()}, true},
		"wildcard":          {openapi3.Content{"*/*": jsonBody()}, false},
		"json and wildcard": {openapi3.Content{"application/json": jsonBody(), "*/*": jsonBody()}, false},
		"json and binary":   {openapi3.Content{"application/json": jsonBody(), "application/octet-stream": jsonBody()}, false},
		"no content":        {openapi3.Content{}, false},
	}
	for name, c := range cases {
		op := openapi3.NewOperation()
		op.OperationID = "op"
		op.RequestBody = &openapi3.RequestBodyRef{Value: &openapi3.RequestBody{Content: c.content}}
		op.Responses = okResponses()
		tl, err := buildTool("POST", "/api/v1/x", &openapi3.PathItem{}, op)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if tl.Expose != c.expose {
			t.Errorf("%s: expose %t, want %t", name, tl.Expose, c.expose)
		}
	}
	op := openapi3.NewOperation()
	op.RequestBody = &openapi3.RequestBodyRef{Value: &openapi3.RequestBody{Content: openapi3.Content{"*/*": jsonBody()}}}
	schema, err := inputSchema(&openapi3.PathItem{}, op)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(schema), `"body"`) {
		t.Errorf("a */* request body became a body argument: %s", schema)
	}
}

func TestSuccessContentMustBeExactlyJSON(t *testing.T) {
	response := func(content openapi3.Content) *openapi3.ResponseRef {
		return &openapi3.ResponseRef{Value: openapi3.NewResponse().WithContent(content)}
	}
	cases := map[string]struct {
		responses map[int]openapi3.Content
		expose    bool
	}{
		"json only":            {map[int]openapi3.Content{200: {"application/json": jsonBody()}}, true},
		"no content":           {map[int]openapi3.Content{204: nil}, true},
		"json and no content":  {map[int]openapi3.Content{200: {"application/json": jsonBody()}, 204: nil}, true},
		"json and binary":      {map[int]openapi3.Content{200: {"application/json": jsonBody(), "application/octet-stream": jsonBody()}}, false},
		"wildcard":             {map[int]openapi3.Content{200: {"*/*": jsonBody()}}, false},
		"json then binary 206": {map[int]openapi3.Content{200: {"application/json": jsonBody()}, 206: {"application/octet-stream": jsonBody()}}, false},
		"binary then json 201": {map[int]openapi3.Content{200: {"application/yaml": jsonBody()}, 201: {"application/json": jsonBody()}}, false},
		"no success response":  {map[int]openapi3.Content{}, false},
	}
	for name, c := range cases {
		op := openapi3.NewOperation()
		op.OperationID = "op"
		op.Responses = openapi3.NewResponses()
		op.Responses.Delete("default")
		for code, content := range c.responses {
			op.Responses.Set(strconv.Itoa(code), response(content))
		}
		tl, err := buildTool("GET", "/api/v1/x", &openapi3.PathItem{}, op)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if tl.Expose != c.expose {
			t.Errorf("%s: expose %t, want %t", name, tl.Expose, c.expose)
		}
	}
}

func TestRequiredHeaderOrCookieHidesTool(t *testing.T) {
	param := func(in, name string, required bool) *openapi3.ParameterRef {
		return &openapi3.ParameterRef{Value: &openapi3.Parameter{In: in, Name: name, Required: required,
			Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}}}}
	}
	cases := map[string]struct {
		item, op openapi3.Parameters
		expose   bool
	}{
		"csrf only":                 {nil, openapi3.Parameters{param("header", "X-Paddock-CSRF", true)}, true},
		"optional header":           {nil, openapi3.Parameters{param("header", "X-Trace", false)}, true},
		"required header":           {nil, openapi3.Parameters{param("header", "X-Paddock-Minisig", true)}, false},
		"required cookie":           {nil, openapi3.Parameters{param("cookie", "paddock_flow", true)}, false},
		"required path-item header": {openapi3.Parameters{param("header", "X-Paddock-Minisig", true)}, nil, false},
	}
	for name, c := range cases {
		op := openapi3.NewOperation()
		op.OperationID = "op"
		op.Parameters = c.op
		op.Responses = okResponses()
		tl, err := buildTool("POST", "/api/v1/x", &openapi3.PathItem{Parameters: c.item}, op)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if tl.Expose != c.expose {
			t.Errorf("%s: expose %t, want %t", name, tl.Expose, c.expose)
		}
	}
}

func TestRejectsPathItemAnnotations(t *testing.T) {
	op := openapi3.NewOperation()
	op.OperationID = "op"
	op.Responses = okResponses()
	item := &openapi3.PathItem{Get: op, Extensions: map[string]any{"x-paddock-mcp": map[string]any{"expose": false}}}
	doc := &openapi3.T{Paths: openapi3.NewPaths(openapi3.WithPath("/api/v1/x", item))}
	if _, err := Build(doc); err == nil || !strings.Contains(err.Error(), "x-paddock-mcp") {
		t.Errorf("a path-item x-paddock-mcp was accepted (err %v)", err)
	}
	item.Extensions = map[string]any{"x-other": true}
	if _, err := Build(doc); err != nil {
		t.Errorf("a foreign path-item extension was refused: %v", err)
	}
}

// TestSkillGolden: the skill reference for the fixture contract is byte-identical to testdata/tools.golden.md.
// Regenerate after an intended change with
// `go run ../../cmd/mcpgen -spec testdata/admin.yaml -skill testdata/tools.golden.md`.
func TestSkillGolden(t *testing.T) {
	got, err := Skill(fixture)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/tools.golden.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("generated skill reference differs from testdata/tools.golden.md")
	}
}

// TestSkillSections: exposed tools sit in their tag's table, step-up operations only in the hand-over list, the other
// unexposed operations only in the last list, and the BFF tag auth nowhere.
func TestSkillSections(t *testing.T) {
	got, err := Skill(fixture)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(got)
	tags, stepUp, ok1 := strings.Cut(doc, "## Step-up operations")
	stepUp, hidden, ok2 := strings.Cut(stepUp, "## Other operations")
	if !ok1 || !ok2 {
		t.Fatalf("sections missing:\n%s", doc)
	}
	for _, c := range []struct {
		section, name string
		want          bool
	}{
		{tags, "## things", true},
		{tags, "| `listThings` | read | no | List things |", true},
		{tags, "| `deleteThing` | write | yes |", true},
		{tags, "`lockThing`", false},
		{tags, "`updateMe`", false},
		{stepUp, "| `lockThing` | things |", true},
		{stepUp, "`updateMe`", false},
		{hidden, "| `updateMe` | me |", true},
		{hidden, "| `exportThing` | things |", true},
		{hidden, "`lockThing`", false},
		{doc, "`login`", false},
	} {
		if strings.Contains(c.section, c.name) != c.want {
			t.Errorf("contains %q = %v, want %v", c.name, !c.want, c.want)
		}
	}
}

func TestSkillSummary(t *testing.T) {
	for _, c := range []struct{ desc, want string }{
		{"List things\n\nRead-only.", "List things"},
		{"Roles: org_admin. Adds a user. More text.\n\nChanges data; needs your MCP write access.", "Adds a user."},
		{"Roles: org_admin, org_operator.\n\nRead-only.", "GET /api/v1/x"},
		{"Roles: org_admin. confirm_hostname must match.\n\nChanges data; needs your MCP write access.", "GET /api/v1/x"},
		{"Read-only.", "GET /api/v1/x"},
	} {
		if got := skillSummary(Tool{Method: "GET", Path: "/api/v1/x", Description: c.desc}); got != c.want {
			t.Errorf("skillSummary(%q) = %q, want %q", c.desc, got, c.want)
		}
	}
	if got := cell("a | b"); got != `a \| b` {
		t.Errorf("cell = %q", got)
	}
}

func TestDestructiveSegments(t *testing.T) {
	cases := []struct {
		method, path string
		want         bool
	}{
		{"POST", "/api/v1/change-sets/{id}/revert", true},
		{"POST", "/api/v1/config-rollouts/{id}/complete", true},
		{"POST", "/api/v1/config-rollouts/{id}/halt", true},
		{"POST", "/api/v1/config-rollouts/{id}/resume", false},
		{"DELETE", "/api/v1/things/{id}", true},
		{"POST", "/api/v1/things/{id}/approve", false},
	}
	for _, c := range cases {
		if got := destructive(c.method, c.path); got != c.want {
			t.Errorf("destructive(%s %s) = %t, want %t", c.method, c.path, got, c.want)
		}
	}
}
