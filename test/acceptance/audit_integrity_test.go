package acceptance

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

var runLine = regexp.MustCompile(`(?m)^run ([0-9a-f-]{36})$`)

// TestAuditIntegrity covers gates V1–V5 of plan M8b §9: `paddock-server audit verify` records its run with trigger
// cli as an audit event of the verified organization, prints the run ID, and the writer's /metrics counts the run;
// the organization's auditor reads the sealed day, the runs and their results through the API (V4), an operator and
// the platform administrator may not (V5), and no other organization sees any of it. The portal step V6 is the
// Playwright spec auditIntegrity.spec.ts.
//
// Like TestAuditChain it uses a fresh organization so the development-only `audit seal --day --org` can seal today
// without sealing other organizations' days early.
func TestAuditIntegrity(t *testing.T) {
	ctx := testContext(t, 10*time.Minute)
	root := login(t, env.PlatformAdmin)
	body := newOrg()
	res := call(t, root, http.MethodPost, "/api/platform/v1/organizations", body)
	expectStatus(t, res, http.StatusCreated, "")
	org := responseID(t, res)
	user, pw := tempUser(t, "integrity", env.RoleGroup(body["slug"], "admins"))
	admin, err := loginAs(t, user, pw)
	if err != nil {
		t.Fatalf("login as the new organization's admin: %v", err)
	}
	createGroup(t, admin)
	waitForEvents(t, admin, 2) // admin.login + device_group.created
	auditorName, auditorPW := tempUser(t, "integrity-auditor", env.RoleGroup(body["slug"], "auditors"))
	auditor, err := loginAs(t, auditorName, auditorPW)
	if err != nil {
		t.Fatalf("login as the new organization's auditor: %v", err)
	}

	okBefore := verifyRuns(t, ctx, "ok")
	failedBefore := verifyRuns(t, ctx, "failed")
	today := time.Now().UTC().Format(time.DateOnly)
	tomorrow := time.Now().UTC().AddDate(0, 0, 1).Format(time.DateOnly)
	if code, out, err := stack.PaddockServer(ctx, "audit", "seal", "--day", today, "--org", org.String()); err != nil || code != 0 {
		t.Fatalf("audit seal: exit %d, %v\n%s", code, err, out)
	}
	idx := auditIndex(t)

	// V1: an intact day verifies, the run is printed and recorded as audit.chain_verified with trigger cli.
	code, out, err := stack.PaddockServer(ctx, "audit", "verify", "--org", org.String(), "--from", today, "--to", today)
	if err != nil || code != 0 || !strings.Contains(out, "OK "+org.String()) {
		t.Fatalf("V1 audit verify: exit %d, %v\n%s", code, err, out)
	}
	okRun := printedRun(t, out)
	ev := runEvent(t, idx, org, okRun)
	if ev.Code != "audit.chain_verified" || ev.Outcome != "success" || ev.ActorDisplay != "audit-writer" ||
		ev.Params["trigger"] != "cli" || ev.Params["days"] != float64(1) ||
		ev.Params["from_day"] != today || ev.Params["to_day"] != today {
		t.Fatalf("V1 event: %+v", ev)
	}

	// V4 (first half): the auditor sees today sealed and verified by the cli run, at the run's end.
	runs := integrityRuns(t, auditor, "?sort=started_at&trigger=cli")
	if len(runs.Items) != 1 || runs.Items[0].ID != okRun || !runs.Items[0].OK {
		t.Fatalf("V4 runs after V1: %+v", runs)
	}
	m := integrityManifest(t, auditor, today)
	if m.LastVerifiedOK == nil || !*m.LastVerifiedOK || m.LastVerifiedAt == nil || !m.LastVerifiedAt.Equal(runs.Items[0].FinishedAt) ||
		len(m.SHA256) != 64 || m.KeyVersion < 1 || !strings.Contains(m.ObjectKey, org.String()) {
		t.Fatalf("V4 manifest of %s after V1: %+v", today, m)
	}

	// V2: a range with a day without manifest fails, exits 1 and is recorded as audit.chain_verification_failed.
	code, out, _ = stack.PaddockServer(ctx, "audit", "verify", "--org", org.String(), "--from", today, "--to", tomorrow)
	if code != 1 || !strings.Contains(out, "FAIL ") || !strings.Contains(out, "no manifest") {
		t.Fatalf("V2 audit verify with a missing day: exit %d, want 1\n%s", code, out)
	}
	failedRun := printedRun(t, out)
	if failedRun == okRun {
		t.Fatalf("V2 printed the run ID of V1: %s", failedRun)
	}
	ev = runEvent(t, idx, org, failedRun)
	count, _ := ev.Params["problem_count"].(float64)
	problems, _ := ev.Params["problems"].([]any)
	if ev.Code != "audit.chain_verification_failed" || ev.Outcome != "failure" || ev.Params["trigger"] != "cli" ||
		count < 1 || len(problems) < 1 || !anyContains(problems, "no manifest") {
		t.Fatalf("V2 event: %+v", ev)
	}
	t.Logf("V1 run %s, V2 run %s", okRun, failedRun)

	// V4 (second half): the failed run is the newest one covering today, so it decides the day's result.
	var sum struct {
		SealedThrough          *string          `json:"sealed_through"`
		Manifests              int              `json:"manifests"`
		VerificationWindowDays int              `json:"verification_window_days"`
		LastRun                *integrityRunDTO `json:"last_run"`
		LastSuccessAt          *time.Time       `json:"last_success_at"`
		LastFailureAt          *time.Time       `json:"last_failure_at"`
	}
	res = call(t, auditor, http.MethodGet, "/api/v1/audit/integrity", nil)
	expectStatus(t, res, http.StatusOK, "")
	if err := res.JSON(&sum); err != nil {
		t.Fatal(err)
	}
	if sum.SealedThrough == nil || *sum.SealedThrough != today || sum.Manifests != 1 || sum.VerificationWindowDays != 7 ||
		sum.LastRun == nil || sum.LastRun.ID != failedRun || sum.LastRun.OK || sum.LastSuccessAt == nil || sum.LastFailureAt == nil {
		t.Fatalf("V4 integrity: %s", res.Body)
	}
	runs = integrityRuns(t, auditor, "?sort=started_at&trigger=cli")
	if len(runs.Items) != 2 || runs.Items[0].ID != okRun || runs.Items[1].ID != failedRun || runs.Items[1].OK ||
		!anyContains(toAny(runs.Items[1].Problems), "no manifest") {
		t.Fatalf("V4 runs sorted by started_at: %+v", runs)
	}
	if m := integrityManifest(t, auditor, today); m.LastVerifiedOK == nil || *m.LastVerifiedOK {
		t.Fatalf("V4 manifest of %s after V2: %+v", today, m)
	}

	// List contract of the manifests (ADR 0018) on data that exists: TestListContract walks acme's list, which holds
	// no sealed day on a fresh stack.
	manifestTotal := func(query string) int {
		t.Helper()
		res := call(t, auditor, http.MethodGet, "/api/v1/audit/manifests"+query, nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Items    []integrityManifestDTO `json:"items"`
			Total    int                    `json:"total"`
			Page     int                    `json:"page"`
			PageSize int                    `json:"page_size"`
			Sort     string                 `json:"sort"`
		}
		if err := res.JSON(&page); err != nil {
			t.Fatal(err)
		}
		if len(page.Items) > 0 && page.Items[0].Day != today {
			t.Fatalf("manifests%s: %s", query, res.Body)
		}
		return page.Total
	}
	for query, want := range map[string]int{
		"?sort=day": 1, "?sort=-day&page_size=10": 1, "?q=" + org.String(): 1, "?q=manifests%2F" + today: 1,
		"?q=no-such-object-key": 0, "?verified=true": 1, "?verified=false": 0, "?from=" + tomorrow: 0,
	} {
		if got := manifestTotal(query); got != want {
			t.Fatalf("manifests%s: total %d, want %d", query, got, want)
		}
	}
	res = call(t, auditor, http.MethodGet, "/api/v1/audit/manifests?page=2&page_size=10", nil)
	expectStatus(t, res, http.StatusOK, "")
	if strings.Contains(string(res.Body), today) {
		t.Fatalf("page 2 of one manifest: %s", res.Body)
	}
	expectStatus(t, call(t, auditor, http.MethodGet, "/api/v1/audit/manifests?sort=sha256", nil), http.StatusBadRequest, "invalid_request")
	expectStatus(t, call(t, auditor, http.MethodGet, "/api/v1/audit/manifests?page_size=7", nil), http.StatusBadRequest, "invalid_request")
	expectStatus(t, call(t, auditor, http.MethodGet, "/api/v1/audit/manifests?page=401&page_size=25", nil), http.StatusBadRequest, "page_out_of_range")
	if got := len(integrityRuns(t, auditor, "?q=no+manifest&trigger=cli").Items); got != 1 {
		t.Fatalf("runs q over problems: %d, want 1 (the V2 run)", got)
	}

	// V5: an operator of the organization and the platform administrator may not read the evidence integrity, an
	// anonymous caller is not signed in.
	operatorName, operatorPW := tempUser(t, "integrity-operator", env.RoleGroup(body["slug"], "operators"))
	operator, err := loginAs(t, operatorName, operatorPW)
	if err != nil {
		t.Fatalf("login as the new organization's operator: %v", err)
	}
	anonymous := anonymousPortal(t)
	for _, path := range integrityRoutes {
		expectStatus(t, call(t, operator, http.MethodGet, path, nil), http.StatusForbidden, "forbidden")
		if res := call(t, root, http.MethodGet, path, nil); res.Status != http.StatusForbidden {
			t.Fatalf("V5 %s as platform administrator: HTTP %d %s", path, res.Status, res.Body)
		}
		expectStatus(t, call(t, anonymous, http.MethodGet, path, nil), http.StatusUnauthorized, "unauthenticated")
	}

	// Isolation (plan M8b §8): another organization's admin sees none of the runs or the manifest of this one.
	for _, other := range []*env.Portal{login(t, env.Carol), login(t, env.Alice)} {
		for _, path := range []string{"/api/v1/audit/verification-runs?page_size=100", "/api/v1/audit/verification-runs?q=no+manifest&page_size=100"} {
			res := call(t, other, http.MethodGet, path, nil)
			expectStatus(t, res, http.StatusOK, "")
			for _, id := range []uuid.UUID{okRun, failedRun} {
				if strings.Contains(string(res.Body), id.String()) {
					t.Fatalf("%s as %s lists run %s of %s", path, other.User, id, org)
				}
			}
		}
		res := call(t, other, http.MethodGet, "/api/v1/audit/manifests?q="+org.String(), nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Total int `json:"total"`
		}
		if err := res.JSON(&page); err != nil || page.Total != 0 {
			t.Fatalf("manifests of %s as %s: %v %s", org, other.User, err, res.Body)
		}
		res = call(t, other, http.MethodGet, "/api/v1/audit/integrity", nil)
		expectStatus(t, res, http.StatusOK, "")
		for _, id := range []string{okRun.String(), failedRun.String(), org.String()} {
			if strings.Contains(string(res.Body), id) {
				t.Fatalf("integrity as %s contains %s", other.User, id)
			}
		}
	}

	// V3: the writer's /metrics (scraped by Prometheus) counts both CLI runs and exports the last-run gauge.
	waitForVerifyRuns(t, ctx, "ok", okBefore+1)
	waitForVerifyRuns(t, ctx, "failed", failedBefore+1)
	var last promQuery
	if err := prometheusGet(ctx, "/api/v1/query?query="+url.QueryEscape(`paddock_audit_verify_last_run_timestamp_seconds{role="paddock-audit-writer"}`), &last); err != nil {
		t.Fatal(err)
	}
	if len(last.Data.Result) == 0 {
		t.Fatal("V3: paddock_audit_verify_last_run_timestamp_seconds is not exported by the audit writer")
	}
}

func printedRun(t *testing.T, out string) uuid.UUID {
	t.Helper()
	m := runLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no `run <uuid>` line in the output:\n%s", out)
	}
	return uuid.MustParse(m[1])
}

// runEvent is the single index event of the run (correlation verify-<run id>) in org's audit log.
func runEvent(t *testing.T, idx *env.AuditIndex, org, run uuid.UUID) env.IndexEvent {
	t.Helper()
	events, err := idx.Events(testContext(t, time.Minute), org, "correlation_id = $1", "verify-"+run.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("%d events of run %s in the index of %s, want 1", len(events), run, org)
	}
	return events[0]
}

func anyContains(items []any, sub string) bool {
	for _, it := range items {
		if s, ok := it.(string); ok && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

type promQuery struct {
	Data struct {
		Result []struct {
			Metric map[string]string `json:"metric"`
			Value  [2]any            `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

// verifyRuns is paddock_audit_verify_runs_total{trigger="cli",result} of the audit writer as Prometheus last
// scraped it; 0 while no series exists.
func verifyRuns(t *testing.T, ctx context.Context, result string) float64 {
	t.Helper()
	q := fmt.Sprintf(`sum(paddock_audit_verify_runs_total{role="paddock-audit-writer",trigger="cli",result=%q})`, result)
	var res promQuery
	if err := prometheusGet(ctx, "/api/v1/query?query="+url.QueryEscape(q), &res); err != nil {
		t.Fatalf("Prometheus API (profile observability running?): %v", err)
	}
	if len(res.Data.Result) == 0 {
		return 0
	}
	s, _ := res.Data.Result[0].Value[1].(string)
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		t.Fatalf("value of %s: %v", q, err)
	}
	return v
}

func waitForVerifyRuns(t *testing.T, ctx context.Context, result string, want float64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		got := verifyRuns(t, ctx, result)
		if got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf(`V3: paddock_audit_verify_runs_total{trigger="cli",result=%q} = %v after 2 minutes, want ≥ %v`, result, got, want)
		}
		time.Sleep(5 * time.Second)
	}
}

// integrityRoutes are the evidence integrity routes of plan M8b decision 30.
var integrityRoutes = []string{"/api/v1/audit/integrity", "/api/v1/audit/verification-runs", "/api/v1/audit/manifests"}

type integrityRunDTO struct {
	ID         uuid.UUID `json:"id"`
	Trigger    string    `json:"trigger"`
	FinishedAt time.Time `json:"finished_at"`
	OK         bool      `json:"ok"`
	Problems   []string  `json:"problems"`
}

type integrityRunPage struct {
	Items []integrityRunDTO `json:"items"`
	Total int               `json:"total"`
}

func integrityRuns(t *testing.T, p *env.Portal, query string) integrityRunPage {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/audit/verification-runs"+query, nil)
	expectStatus(t, res, http.StatusOK, "")
	var page integrityRunPage
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	return page
}

type integrityManifestDTO struct {
	Day            string     `json:"day"`
	SHA256         string     `json:"sha256"`
	KeyVersion     int        `json:"key_version"`
	ObjectKey      string     `json:"object_key"`
	LastVerifiedAt *time.Time `json:"last_verified_at"`
	LastVerifiedOK *bool      `json:"last_verified_ok"`
}

// integrityManifest is the manifest of day as the caller lists it (from and to are inclusive).
func integrityManifest(t *testing.T, p *env.Portal, day string) integrityManifestDTO {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/audit/manifests?from="+day+"&to="+day, nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []integrityManifestDTO `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Day != day {
		t.Fatalf("manifests of %s: %s", day, res.Body)
	}
	return page.Items[0]
}

// anonymousPortal is a client without a session.
func anonymousPortal(t *testing.T) *env.Portal {
	t.Helper()
	client, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	return &env.Portal{User: "anonymous", Client: client}
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}
