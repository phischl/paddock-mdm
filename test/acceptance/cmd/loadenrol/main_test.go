package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

type call struct {
	method, path string
	body         map[string]any
}

type fakeAPI struct {
	calls   []call
	answers []env.Response
}

func (f *fakeAPI) Do(_ context.Context, method, path string, body any) (env.Response, error) {
	c := call{method: method, path: path}
	if b, ok := body.(map[string]any); ok {
		c.body = b
	}
	f.calls = append(f.calls, c)
	r := f.answers[0]
	if len(f.answers) > 1 {
		f.answers = f.answers[1:]
	}
	return r, nil
}

func created(cfg string) env.Response {
	return env.Response{Status: http.StatusCreated, Body: []byte(`{"token":{"id":"x"},"enrollment_config":` + cfg + `}`)}
}

func TestValidate(t *testing.T) {
	for _, c := range []struct {
		org          string
		tokens, uses int
		ok           bool
	}{
		{"load-enrol", 10, 1000, true},
		{"Load", 10, 1000, false},
		{"load-enrol", 0, 1000, false},
		{"load-enrol", 1, 1001, false},
		{"load-enrol", 1, 0, false},
	} {
		if err := validate(c.org, c.tokens, c.uses); (err == nil) != c.ok {
			t.Errorf("validate(%q,%d,%d) = %v", c.org, c.tokens, c.uses, err)
		}
	}
}

func TestEnsureOrg(t *testing.T) {
	taken := env.Response{Status: http.StatusConflict, Body: []byte(`{"code":"slug_taken"}`), Header: http.Header{}}
	for name, res := range map[string]env.Response{
		"created": {Status: http.StatusCreated}, "exists": taken,
	} {
		if err := ensureOrg(context.Background(), &fakeAPI{answers: []env.Response{res}}, "load-enrol", &bytes.Buffer{}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	err := ensureOrg(context.Background(), &fakeAPI{answers: []env.Response{{Status: http.StatusForbidden, Body: []byte("no")}}}, "load-enrol", &bytes.Buffer{})
	if err == nil {
		t.Error("forbidden must fail")
	}
}

func TestCreateTokensAndWrite(t *testing.T) {
	f := &fakeAPI{answers: []env.Response{created(`{"token":"s1"}`), created(`{"token":"s2"}`)}}
	cfgs, err := createTokens(context.Background(), f, "load-enrol", 2, 500)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if c.method != http.MethodPost || c.path != tokensPath || c.body["auto_approve"] != true || c.body["max_uses"] != 500 {
			t.Errorf("unexpected call %+v", c)
		}
	}
	dir := filepath.Join(t.TempDir(), "load")
	if err := writeConfigs(dir, cfgs); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "token-2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(b, &got); err != nil || got["token"] != "s2" {
		t.Fatalf("token-2.json = %s (%v)", b, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("want only the two token files, got %d entries", len(entries))
	}
}

func TestCreateTokensFailureLeaksNothing(t *testing.T) {
	secret := "SUPER-SECRET-VALUE"
	f := &fakeAPI{answers: []env.Response{{Status: http.StatusBadRequest, Body: []byte(secret), Header: http.Header{}}}}
	_, err := createTokens(context.Background(), f, "load-enrol", 1, 10)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error must exist and not echo the body: %v", err)
	}
	f = &fakeAPI{answers: []env.Response{{Status: http.StatusCreated, Body: []byte(`{"secret":"` + secret + `"}`)}}}
	_, err = createTokens(context.Background(), f, "load-enrol", 1, 10)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("missing configuration must fail without echoing the body: %v", err)
	}
}

func TestRunRejectsInvalidArgumentsBeforeAnyLogin(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--org", "Bad Slug"}, &out); err == nil || out.Len() != 0 {
		t.Fatalf("invalid org must fail without output: %v %q", err, out.String())
	}
}

func TestWriteConfigsReplacesAnEarlierRun(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"token-1.json", "token-2.json", "token-3.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"token":"old"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeConfigs(dir, []json.RawMessage{json.RawMessage(`{"token":"new"}`)}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("want only token-1.json after a smaller run, got %d entries", len(entries))
	}
	info, err := os.Stat(filepath.Join(dir, "token-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("token-1.json mode %v, want 0600", info.Mode().Perm())
	}
}
