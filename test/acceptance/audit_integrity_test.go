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

// TestAuditIntegrity covers gates V1–V3 of plan M8b §9: `paddock-server audit verify` records its run with trigger
// cli as an audit event of the verified organization, prints the run ID, and the writer's /metrics counts the run.
// The API and portal steps V4–V6 belong to PDK-110.
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
