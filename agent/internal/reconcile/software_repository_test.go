package reconcile_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const (
	repoSecret  = "s3cr3t-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	repoSecret2 = "r0tat3d-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

// repositoryResource is a section with the organization's Paddock repository as its source and its credential.
func repositoryResource(t *testing.T, secret string) bundle.Resource {
	t.Helper()
	src := vendorSource(t)
	src.Slug, src.URIs, src.Suites, src.Components = "paddock", []string{"https://bundles.example.com/apt/acme/"}, []string{"paddock"}, []string{"main"}
	s := bundle.SoftwareSpec{Sources: []bundle.SoftwareSource{src}, Packages: []bundle.SoftwarePackage{required("acme-tool", "paddock")}}
	if secret != "" {
		s.Repository = &bundle.SoftwareRepositoryAuth{Host: "bundles.example.com/apt/acme/", Username: "paddock", Password: secret}
	}
	if err := bundle.ValidateSoftware(s); err != nil {
		t.Fatal(err)
	}
	r, err := bundle.SoftwareResource(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestSoftwareRepositoryCredential (plan M13c decision 15): the credential of the Paddock repository is written to
// apt's auth.conf.d as root-only before the source's first update, restored with a tamper event when it is changed or
// loosened outside Paddock, replaced without one when the bundle rotates it, removed with the repository, and its
// secret never reaches an event, the status, a result, the plan or the log.
func TestSoftwareRepositoryCredential(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	sys, s, events, _ := softwareFixture(t)
	var emitted []string
	emit := s.Events.Emit
	s.Events.Emit = func(typ string, data any) {
		b, _ := json.Marshal(data)
		emitted = append(emitted, string(b))
		emit(typ, data)
	}
	ctx := context.Background()
	r := repositoryResource(t, repoSecret)
	var results []string
	note := func(res reconcile.Result) { results = append(results, res.Message) }

	plan, err := s.Plan(ctx, r)
	if err != nil || !slices.Contains(plan, "file "+reconcile.SoftwareAuthFile) {
		t.Fatalf("plan %q, %v", plan, err)
	}
	results = append(results, plan...)
	note(s.Apply(ctx, r))
	want := "machine bundles.example.com/apt/acme/ login paddock password " + repoSecret + "\n"
	f := sys.Files[reconcile.SoftwareAuthFile]
	if f == nil || string(f.Data) != want || f.Mode != 0o600 || f.UID != 0 || f.GID != 0 {
		t.Fatalf("credential file %+v", f)
	}
	if !slices.ContainsFunc(sys.Calls, func(c string) bool { return strings.Contains(c, "paddock-paddock.sources") }) {
		t.Fatalf("no scoped update of the Paddock source: %v", sys.Calls)
	}

	for name, tamper := range map[string]func(){
		"content": func() {
			sys.Files[reconcile.SoftwareAuthFile].Data = []byte("machine evil.example.com login x password y\n")
		},
		"mode":    func() { sys.Files[reconcile.SoftwareAuthFile].Mode = 0o644 },
		"removed": func() { delete(sys.Files, reconcile.SoftwareAuthFile) },
	} {
		*events = nil
		tamper()
		note(s.Apply(ctx, r))
		if f := sys.Files[reconcile.SoftwareAuthFile]; f == nil || string(f.Data) != want || f.Mode != 0o600 {
			t.Fatalf("%s: not restored: %+v", name, f)
		}
		wantEvent := event{protocol.EventTamperProtectedFileChanged, `{"file":"` + reconcile.SoftwareAuthFile + `"}`}
		if !slices.Contains(*events, wantEvent) {
			t.Fatalf("%s: events %+v", name, *events)
		}
	}

	*events = nil
	sys.TakeCalls()
	rotated := repositoryResource(t, repoSecret2)
	note(s.Apply(ctx, rotated))
	if got := fileContent(t, sys, reconcile.SoftwareAuthFile); !strings.Contains(got, repoSecret2) || strings.Contains(got, repoSecret) {
		t.Fatalf("rotated credential not written: %q", got)
	}
	if slices.ContainsFunc(*events, func(e event) bool { return e.typ == protocol.EventTamperProtectedFileChanged }) {
		t.Fatalf("a rotation is no tamper: %+v", *events)
	}
	if !slices.Contains(sys.Calls, "apt-get update") {
		t.Fatalf("no update of the Paddock source after the rotation: %v", sys.Calls)
	}
	if !s.Residue() {
		t.Fatal("the credential file is residue")
	}

	*events = nil
	note(s.Apply(ctx, softwareResource(t, nil, required("nano", ""))))
	if sys.Files[reconcile.SoftwareAuthFile] != nil || slices.ContainsFunc(*events, func(e event) bool { return e.typ == protocol.EventTamperProtectedFileChanged }) {
		t.Fatalf("credential without repository: %+v, events %+v", sys.Files[reconcile.SoftwareAuthFile], *events)
	}

	status, _ := json.Marshal(s.Status())
	all := strings.Join(results, "\n") + string(status) + logs.String() + strings.Join(emitted, "\n")
	for _, secret := range []string{repoSecret, repoSecret2} {
		if strings.Contains(all, secret) {
			t.Fatalf("the secret leaked into a plan, result, status, event or log")
		}
	}
}

// TestSoftwareRepositoryCredentialEmptySection: a bundle without the software section removes the credential file
// (its name is Paddock's) and nothing else of apt's auth.conf.d.
func TestSoftwareRepositoryCredentialEmptySection(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	sys.Files[reconcile.SoftwareAuthFile] = &fakesys.File{Data: []byte("machine x login paddock password y\n"), Mode: 0o600}
	vendorAuth := "/etc/apt/auth.conf.d/vendor.conf"
	sys.Files[vendorAuth] = &fakesys.File{Data: []byte("machine vendor login a password b\n"), Mode: 0o600}
	if !s.Residue() {
		t.Fatal("the credential file is residue")
	}
	s.Apply(context.Background(), bundle.Resource{ID: "software", Type: bundle.TypeSoftware, Spec: []byte(`{"sources":[],"packages":[]}`)})
	if sys.Files[reconcile.SoftwareAuthFile] != nil || sys.Files[vendorAuth] == nil {
		t.Fatalf("files after the empty section: credential %v, vendor %v", sys.Files[reconcile.SoftwareAuthFile] != nil, sys.Files[vendorAuth] != nil)
	}
}
