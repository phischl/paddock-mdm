package admin_test

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// integrityFixture is what seedIntegrity stored for acme: two sealed days and two runs covering the second day, the
// later one failed (plan M8b gate V4).
type integrityFixture struct {
	day1, day2       time.Time
	sum1, sum2       []byte
	okRun, failedRun uuid.UUID
	okEnd, failedEnd time.Time
}

func seedIntegrity(t *testing.T, e *env) integrityFixture {
	t.Helper()
	day2 := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	f := integrityFixture{
		day1: day2.AddDate(0, 0, -1), day2: day2, sum1: []byte{0x01, 0xab}, sum2: []byte{0x02, 0xcd},
		okRun: uuid.Must(uuid.NewV7()), failedRun: uuid.Must(uuid.NewV7()),
	}
	started := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	f.okEnd, f.failedEnd = started.Add(time.Minute), started.Add(11*time.Minute)
	err := e.writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		for _, m := range []auditstore.InsertAuditManifestParams{
			{OrganizationID: e.acme, Day: f.day1, Sha256: f.sum1, Signature: "vault:v1:x", KeyVersion: 1, ObjectKey: "org/" + e.acme.String() + "/manifests/1.json"},
			{OrganizationID: e.acme, Day: f.day2, Sha256: f.sum2, PrevSha256: f.sum1, Signature: "vault:v1:y", KeyVersion: 2, ObjectKey: "org/" + e.acme.String() + "/manifests/2.json"},
			{OrganizationID: e.globex, Day: f.day2, Sha256: f.sum2, Signature: "vault:v1:z", KeyVersion: 1, ObjectKey: "org/" + e.globex.String() + "/manifests/2.json"},
		} {
			if err := q.InsertAuditManifest(ctx, m); err != nil {
				return err
			}
		}
		for _, r := range []auditstore.InsertAuditVerificationRunParams{
			{ID: f.okRun, OrganizationID: e.acme, Trigger: "cli", FromDay: f.day2, ToDay: f.day2, StartedAt: started,
				FinishedAt: f.okEnd, Days: 1, Objects: 3, Ok: true, Problems: []byte(`[]`), EventID: uuid.Must(uuid.NewV7())},
			{ID: f.failedRun, OrganizationID: e.acme, Trigger: "nightly", FromDay: f.day2, ToDay: f.day2.AddDate(0, 0, 1),
				StartedAt: started.Add(10 * time.Minute), FinishedAt: f.failedEnd, Days: 2, Objects: 3, Ok: false,
				Problems: []byte(`["2026-01-02: no manifest (chain broken)"]`), EventID: uuid.Must(uuid.NewV7())},
			{ID: uuid.Must(uuid.NewV7()), OrganizationID: e.globex, Trigger: "cli", FromDay: f.day2, ToDay: f.day2,
				StartedAt: started.Add(20 * time.Minute), FinishedAt: started.Add(21 * time.Minute), Days: 1, Objects: 1, Ok: true,
				Problems: []byte(`["globex problem"]`), EventID: uuid.Must(uuid.NewV7())},
		} {
			if err := q.InsertAuditVerificationRun(ctx, r); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestAuditIntegritySummary(t *testing.T) {
	e := newEnv(t)
	auditor := e.session(e.acme, principal.RoleOrgAuditor)

	r := e.do(call{method: "GET", path: "/api/v1/audit/integrity", cookie: auditor})
	var empty adminapi.AuditIntegrity
	r.decode(t, &empty)
	if r.status != http.StatusOK || empty.SealedThrough != nil || empty.Manifests != 0 || empty.VerificationWindowDays != 7 ||
		empty.LastRun != nil || empty.LastSuccessAt != nil || empty.LastFailureAt != nil {
		t.Fatalf("before the first seal: %d %s", r.status, r.body)
	}
	for _, key := range []string{`"sealed_through":null`, `"last_run":null`, `"last_success_at":null`, `"last_failure_at":null`} {
		if !strings.Contains(string(r.body), key) {
			t.Fatalf("missing %s: %s", key, r.body)
		}
	}

	f := seedIntegrity(t, e)
	r = e.do(call{method: "GET", path: "/api/v1/audit/integrity", cookie: e.session(e.acme, principal.RoleOrgAdmin)})
	var s adminapi.AuditIntegrity
	r.decode(t, &s)
	if r.status != http.StatusOK || s.SealedThrough == nil || !s.SealedThrough.Equal(f.day2) || s.Manifests != 2 {
		t.Fatalf("summary: %d %s", r.status, r.body)
	}
	if s.LastRun == nil || s.LastRun.Id != f.failedRun || s.LastRun.Ok || s.LastRun.Trigger != adminapi.Nightly ||
		len(s.LastRun.Problems) != 1 || !s.LastRun.ToDay.Equal(f.day2.AddDate(0, 0, 1)) {
		t.Fatalf("last run: %s", r.body)
	}
	if s.LastSuccessAt == nil || !s.LastSuccessAt.Equal(f.okEnd) || s.LastFailureAt == nil || !s.LastFailureAt.Equal(f.failedEnd) {
		t.Fatalf("last success/failure: %s", r.body)
	}
}

func TestAuditIntegrityRoles(t *testing.T) {
	e := newEnv(t)
	operator := e.session(e.acme, principal.RoleOrgOperator)
	root := e.platformSession()
	for _, path := range []string{"/api/v1/audit/integrity", "/api/v1/audit/verification-runs", "/api/v1/audit/manifests"} {
		if r := e.do(call{method: "GET", path: path, cookie: operator}); r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
			t.Fatalf("operator %s: %d %s", path, r.status, r.body)
		}
		if r := e.do(call{method: "GET", path: path, cookie: root}); r.status != http.StatusForbidden {
			t.Fatalf("platform admin %s: %d %s", path, r.status, r.body)
		}
		if r := e.do(call{method: "GET", path: path}); r.status != http.StatusUnauthorized {
			t.Fatalf("anonymous %s: %d %s", path, r.status, r.body)
		}
	}
}

func TestAuditVerificationRuns(t *testing.T) {
	e := newEnv(t)
	auditor := e.session(e.acme, principal.RoleOrgAuditor)
	f := seedIntegrity(t, e)
	list := func(query string) adminapi.AuditVerificationRunPage {
		t.Helper()
		r := e.do(call{method: "GET", path: "/api/v1/audit/verification-runs" + query, cookie: auditor})
		var p adminapi.AuditVerificationRunPage
		r.decode(t, &p)
		if r.status != http.StatusOK {
			t.Fatalf("%s: %d %s", query, r.status, r.body)
		}
		return p
	}
	ids := func(p adminapi.AuditVerificationRunPage) []uuid.UUID {
		out := make([]uuid.UUID, len(p.Items))
		for i, it := range p.Items {
			out[i] = it.Id
		}
		return out
	}
	p := list("")
	if p.Total != 2 || p.Sort != "-started_at" || len(p.Items) != 2 || p.Items[0].Id != f.failedRun {
		t.Fatalf("default page (globex hidden, newest first): %+v", p)
	}
	if got := ids(list("?sort=started_at")); got[0] != f.okRun || got[1] != f.failedRun {
		t.Fatalf("sort=started_at: %v", got)
	}
	if got := ids(list("?sort=ok")); got[0] != f.failedRun {
		t.Fatalf("sort=ok puts false first: %v", got)
	}
	if got := ids(list("?ok=true")); len(got) != 1 || got[0] != f.okRun {
		t.Fatalf("ok=true: %v", got)
	}
	if got := ids(list("?trigger=nightly&trigger=sample")); len(got) != 1 || got[0] != f.failedRun {
		t.Fatalf("trigger: %v", got)
	}
	if got := ids(list("?q=no+manifest")); len(got) != 1 || got[0] != f.failedRun {
		t.Fatalf("q over problems: %v", got)
	}
	if p := list("?q=globex"); p.Total != 0 {
		t.Fatalf("globex run visible to acme: %+v", p)
	}
	if p := list("?ok=true"); len(p.Items[0].Problems) != 0 || p.Items[0].Problems == nil {
		t.Fatalf("problems of an ok run: %+v", p.Items[0])
	}
	for _, bad := range []string{"?sort=id", "?trigger=manual", "?page_size=7"} {
		e.expectRejected(auditor, "/api/v1/audit/verification-runs"+bad, "invalid_request")
	}
}

func TestAuditManifests(t *testing.T) {
	e := newEnv(t)
	auditor := e.session(e.acme, principal.RoleOrgAuditor)
	f := seedIntegrity(t, e)
	list := func(query string) adminapi.AuditManifestPage {
		t.Helper()
		r := e.do(call{method: "GET", path: "/api/v1/audit/manifests" + query, cookie: auditor})
		var p adminapi.AuditManifestPage
		r.decode(t, &p)
		if r.status != http.StatusOK {
			t.Fatalf("%s: %d %s", query, r.status, r.body)
		}
		return p
	}
	p := list("")
	if p.Total != 2 || p.Sort != "-day" || !p.Items[0].Day.Equal(f.day2) || !p.Items[1].Day.Equal(f.day1) {
		t.Fatalf("default page (globex hidden, newest first): %+v", p)
	}
	newest, first := p.Items[0], p.Items[1]
	// The failed run started after the successful one and covers the day too: it decides (gate V4).
	if newest.Sha256 != hex.EncodeToString(f.sum2) || newest.PrevSha256 == nil || *newest.PrevSha256 != hex.EncodeToString(f.sum1) ||
		newest.KeyVersion != 2 || newest.LastVerifiedOk == nil || *newest.LastVerifiedOk || newest.LastVerifiedAt == nil ||
		!newest.LastVerifiedAt.Equal(f.failedEnd) {
		t.Fatalf("newest day: %+v", newest)
	}
	if first.PrevSha256 != nil || first.LastVerifiedOk != nil || first.LastVerifiedAt != nil {
		t.Fatalf("first day, never verified: %+v", first)
	}
	if p := list("?sort=day"); !p.Items[0].Day.Equal(f.day1) {
		t.Fatalf("sort=day: %+v", p)
	}
	day1, day2 := f.day1.Format(time.DateOnly), f.day2.Format(time.DateOnly)
	if p := list("?from=" + day2 + "&to=" + day2); p.Total != 1 || !p.Items[0].Day.Equal(f.day2) {
		t.Fatalf("from/to inclusive: %+v", p)
	}
	if p := list("?to=" + day1); p.Total != 1 || !p.Items[0].Day.Equal(f.day1) {
		t.Fatalf("to: %+v", p)
	}
	if p := list("?verified=true"); p.Total != 1 || !p.Items[0].Day.Equal(f.day2) {
		t.Fatalf("verified=true (an ok run covers day 2): %+v", p)
	}
	if p := list("?verified=false"); p.Total != 1 || !p.Items[0].Day.Equal(f.day1) {
		t.Fatalf("verified=false: %+v", p)
	}
	if p := list("?q=2.json"); p.Total != 1 || !p.Items[0].Day.Equal(f.day2) {
		t.Fatalf("q over object_key: %+v", p)
	}
	if p := list("?q=" + e.globex.String()); p.Total != 0 {
		t.Fatalf("globex manifest visible to acme: %+v", p)
	}
	for _, bad := range []string{"?sort=sha256", "?from=yesterday"} {
		e.expectRejected(auditor, "/api/v1/audit/manifests"+bad, "invalid_request")
	}
}
