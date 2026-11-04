package app_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// Fingerprints of the key fixtures of the domain package, as gpg --show-keys prints them.
const (
	sourceEd25519FP = "8A367815ED9674ED9013609A8F03DFF0EB10E2E4"
	sourceRSA3072FP = "5D47E8B7736A9129C4FDA19E1F2C82BB297A4093"
	sourceRSA2048FP = "EBBD1779E3508C777B3E01D3B378F1FA6890CA25"
	sourceDSAFP     = "26EB16479113C792A40357F4F0FC57026622ACAD"
)

func sourceKey(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "domain", "software", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestSoftwareSources (plan M13a decisions 1, 2 and 4, ticket PDK-408): only an organization administrator with a
// fresh step-up changes sources, every attempt is audited once, the stored name is trimmed, the key policy comes
// before the fingerprint comparison, and an update is validated on the merged state.
func TestSoftwareSources(t *testing.T) {
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	sources := app.NewSoftwareSources(h.runner, pool)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	operator := h.account(t, principal.RoleOrgOperator, true)
	auditor := h.account(t, principal.RoleOrgAuditor, false)
	token := h.create(t, steppedUp, "ci", principal.RoleOrgAdmin)
	tp, _, err := h.tokens.Authenticate(context.Background(), token.Secret, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }
	vendor := software.SourceInput{
		Slug: "vendor", Name: "  Vendor  ", URIs: []string{"https://apt.vendor.example/"}, Suites: []string{"stable"},
		Components: []string{"main"}, SigningKey: sourceKey(t, "ed25519.asc"),
		Fingerprint: strings.ToLower(sourceEd25519FP[:20]) + " " + strings.ToLower(sourceEd25519FP[20:]),
	}
	with := func(f func(in *software.SourceInput)) software.SourceInput {
		in := vendor
		f(&in)
		return in
	}

	got := h.during(t, func() {
		for name, c := range map[string]struct {
			p    principal.Principal
			in   software.SourceInput
			want *problem.Error
		}{
			"operator":           {operator, vendor, problem.Forbidden},
			"admin without step": {admin, vendor, problem.StepUpRequired},
			"api token":          {tp, vendor, problem.StepUpRequired},
			"http uri":           {steppedUp, with(func(in *software.SourceInput) { in.URIs = []string{"http://apt.vendor.example/"} }), problem.InvalidRequest},
			"wrong fingerprint":  {steppedUp, with(func(in *software.SourceInput) { in.Fingerprint = sourceRSA3072FP }), problem.FingerprintMismatch},
			"dsa, wrong fingerprint": {steppedUp, with(func(in *software.SourceInput) {
				in.SigningKey, in.Fingerprint = sourceKey(t, "dsa.asc"), sourceRSA3072FP
			}), problem.InvalidRequest},
			"flat suite with component": {steppedUp, with(func(in *software.SourceInput) { in.Suites = []string{"./"} }), problem.InvalidRequest},
		} {
			if _, err := sources.Create(ctx(c.p), c.in); !errors.Is(err, c.want) {
				t.Errorf("%s = %v, want %s", name, err, c.want.Code)
			}
		}
	})
	if n := len(got); n != 7 {
		t.Fatalf("actions %v", got)
	}
	if _, err := sources.Create(ctx(steppedUp), with(func(in *software.SourceInput) { in.URIs = []string{"http://a.example/"} })); problem.From(err).Detail != "uris must use https" {
		t.Fatalf("http detail = %v", err)
	}
	_, err = sources.Create(ctx(steppedUp), with(func(in *software.SourceInput) { in.Fingerprint = sourceRSA3072FP }))
	if d := problem.From(err).Detail; !strings.Contains(d, sourceEd25519FP) || !strings.Contains(d, sourceRSA3072FP) {
		t.Fatalf("mismatch detail = %q", d)
	}
	if ev := h.lastEvent(t); ev.Params["fingerprint"] != sourceRSA3072FP {
		t.Fatalf("failure event %+v", ev)
	}

	created, err := sources.Create(ctx(steppedUp), vendor)
	if err != nil {
		t.Fatal(err)
	}
	if created.Name != "Vendor" || created.Fingerprint != sourceEd25519FP || created.WeakKey || created.Architectures == nil {
		t.Fatalf("created %+v", created)
	}
	ev := h.lastEvent(t)
	if !ev.Actor.StepUp || ev.Params["name"] != "Vendor" || ev.Params["slug"] != "vendor" || ev.Params["fingerprint"] != sourceEd25519FP ||
		ev.Params["weak_key"] != false || !slices.Equal(anyStrings(ev.Params["uris"]), vendor.URIs) ||
		!slices.Equal(anyStrings(ev.Params["components"]), []string{"main"}) || ev.Target.Display != "Vendor" {
		t.Fatalf("created event %+v", ev)
	}
	for name, in := range map[string]software.SourceInput{
		"slug": with(func(in *software.SourceInput) { in.Name = "Other" }),
		"name": with(func(in *software.SourceInput) { in.Slug = "other"; in.Name = "Vendor " }),
	} {
		if _, err := sources.Create(ctx(steppedUp), in); !errors.Is(err, problem.AlreadyExists) {
			t.Errorf("duplicate %s = %v", name, err)
		}
	}

	if _, err := sources.Update(ctx(steppedUp), created.ID, app.SourceUpdate{Slug: new("other")}); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("slug change = %v", err)
	}
	rsa2048 := sourceKey(t, "rsa2048.asc")
	if _, err := sources.Update(ctx(steppedUp), created.ID, app.SourceUpdate{SigningKey: &rsa2048}); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("key without fingerprint = %v", err)
	}
	flat := []string{"./"}
	if _, err := sources.Update(ctx(steppedUp), created.ID, app.SourceUpdate{Suites: &flat}); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("flat suite on a source with components = %v", err)
	}
	if _, err := sources.Update(ctx(admin), created.ID, app.SourceUpdate{Name: new("X")}); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("update without step-up = %v", err)
	}
	updated, err := sources.Update(ctx(steppedUp), created.ID, app.SourceUpdate{SigningKey: &rsa2048, Fingerprint: new(sourceRSA2048FP)})
	if err != nil || updated.Fingerprint != sourceRSA2048FP || !updated.WeakKey || updated.Name != "Vendor" {
		t.Fatalf("key change = %+v, %v", updated, err)
	}
	ev = h.lastEvent(t)
	if ev.Params["fingerprint"] != sourceRSA2048FP || ev.Params["old_fingerprint"] != sourceEd25519FP || ev.Params["weak_key"] != true ||
		!slices.Equal(anyStrings(ev.Params["fields"]), []string{"signing_key"}) {
		t.Fatalf("updated event %+v", ev)
	}

	page, err := sources.List(ctx(auditor), app.ListPage{Sort: "name", Limit: 25, QPattern: new("%vend%")})
	if err != nil || page.Count != 1 || page.Items[0].ID != created.ID {
		t.Fatalf("list = %+v, %v", page, err)
	}
	if _, err := sources.Get(ctx(auditor), created.ID); err != nil {
		t.Fatal(err)
	}
	if err := sources.Delete(ctx(operator), created.ID); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator delete = %v", err)
	}
	if err := sources.Delete(ctx(steppedUp), created.ID); err != nil {
		t.Fatal(err)
	}
	if ev = h.lastEvent(t); ev.Params["fingerprint"] != sourceRSA2048FP || ev.Params["slug"] != "vendor" || ev.Params["weak_key"] != true {
		t.Fatalf("deleted event %+v", ev)
	}
	if _, err := sources.Get(ctx(auditor), created.ID); !errors.Is(err, problem.NotFound) {
		t.Fatalf("get after delete = %v", err)
	}
	if err := sources.Delete(ctx(steppedUp), created.ID); !errors.Is(err, problem.NotFound) {
		t.Fatalf("second delete = %v", err)
	}

	// External Review 1 L2: armor header values are not stored or served.
	header := with(func(in *software.SourceInput) {
		in.Slug, in.Name = "headers", "Headers"
		in.SigningKey = strings.Replace(in.SigningKey, "-----\n", "-----\nComment: \u202Eevil\x1b[31m\n", 1)
	})
	stored, err := sources.Create(ctx(steppedUp), header)
	if err != nil || strings.Contains(stored.SigningKey, "Comment") || strings.ContainsRune(stored.SigningKey, 0x1b) {
		t.Fatalf("stored key %q, %v", stored.SigningKey, err)
	}
	unchanged, err := sources.Update(ctx(steppedUp), stored.ID, app.SourceUpdate{SigningKey: &header.SigningKey, Fingerprint: new(sourceEd25519FP)})
	if err != nil || unchanged.SigningKey != stored.SigningKey || len(anyStrings(h.lastEvent(t).Params["fields"])) != 0 {
		t.Fatalf("same key with other armor = %v, fields %v", err, h.lastEvent(t).Params["fields"])
	}

	// Review 1 of Fix Round 1: a refused key change names signing_key in its failure event.
	rsa3072 := sourceKey(t, "rsa3072.asc")
	dsa := sourceKey(t, "dsa.asc")
	for name, c := range map[string]struct {
		key, fp string
		want    *problem.Error
	}{
		"fingerprint mismatch": {rsa3072, sourceEd25519FP, problem.FingerprintMismatch},
		"key policy":           {dsa, sourceDSAFP, problem.InvalidRequest},
	} {
		if _, err := sources.Update(ctx(steppedUp), stored.ID, app.SourceUpdate{SigningKey: &c.key, Fingerprint: &c.fp}); !errors.Is(err, c.want) {
			t.Fatalf("%s = %v", name, err)
		}
		if ev := h.lastEvent(t); ev.Outcome != "failure" || !slices.Equal(anyStrings(ev.Params["fields"]), []string{"signing_key"}) {
			t.Fatalf("%s: event %+v", name, ev)
		}
	}
}

// TestSoftwareSourceAuditParamsBounded (External Review 1 M1): a refused attempt records exactly one event whose
// request-derived params are cut to the documented limits and carry no invisible runes, whatever the body held.
func TestSoftwareSourceAuditParamsBounded(t *testing.T) {
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	sources := app.NewSoftwareSources(h.runner, pool)
	auditor := h.account(t, principal.RoleOrgAuditor, false)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	ctx := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }
	huge := strings.Repeat("\u202Ea", 100_000)
	many := make([]string, 1000)
	for i := range many {
		many[i] = "https://a.example/" + strings.Repeat("p", 2000)
	}
	in := software.SourceInput{
		Slug: huge, Name: huge, URIs: many, Suites: many, Components: many, SigningKey: huge, Fingerprint: huge,
	}
	check := func(name string) {
		t.Helper()
		ev := h.lastEvent(t)
		for k, v := range ev.Params {
			switch v := v.(type) {
			case string:
				if utf8.RuneCountInString(v) > 101 || strings.ContainsRune(v, 0x202E) {
					t.Errorf("%s: param %s of %d runes", name, k, utf8.RuneCountInString(v))
				}
			case []any:
				if len(v) > 9 {
					t.Errorf("%s: param %s of %d items", name, k, len(v))
				}
				for _, item := range anyStrings(v) {
					if utf8.RuneCountInString(item) > 513 || strings.ContainsRune(item, 0x202E) {
						t.Errorf("%s: item of %s of %d runes", name, k, utf8.RuneCountInString(item))
					}
				}
			}
		}
		if _, ok := ev.Params["signing_key"]; ok {
			t.Errorf("%s: the signing key is in the params", name)
		}
	}
	got := h.during(t, func() {
		if _, err := sources.Create(ctx(auditor), in); !errors.Is(err, problem.Forbidden) {
			t.Fatalf("denied create = %v", err)
		}
	})
	if len(got) != 1 || got[0] != "software_source.created:denied:forbidden" {
		t.Fatalf("actions %v", got)
	}
	check("denied create")
	if _, err := sources.Create(ctx(steppedUp), in); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("failed create = %v", err)
	}
	check("failed create")

	created, err := sources.Create(ctx(steppedUp), software.SourceInput{
		Slug: "bounded", Name: "Bounded", URIs: []string{"https://a.example/"}, Suites: []string{"stable"},
		Components: []string{"main"}, SigningKey: sourceKey(t, "ed25519.asc"), Fingerprint: sourceEd25519FP,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sources.Update(ctx(steppedUp), created.ID, app.SourceUpdate{Name: &huge, Fingerprint: &huge, SigningKey: &huge}); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("failed update = %v", err)
	}
	check("failed update")
}
