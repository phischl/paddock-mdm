// Package acceptance holds the acceptance gates of the milestone plans; they run against the development stack.
// A gate must not depend on state that accumulates across runs (docs/operations/local-dev.md, "Acceptance gates on
// a long-lived stack").
package acceptance

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// Polling bounds of the audit checks (plan M0 §8, A3).
const (
	// auditPollTimeout covers the worst-case lag from a request to its event in the audit view on a loaded host
	// (PDK-551): relay wake-up (≤ 1 s) + the writer batch already in flight (≤ 5 s processing) + the event's own batch
	// wait (auditwriter.MaxBatchWait, 5 s) + its own transaction with the WORM put (≤ 5 s) ≈ 16 s, and one requeue
	// after a failed batch (auditwriter.RetryPause, 5 s) on top still fits. 10 s failed at load ~46 although the
	// event was recorded after 4.5 s and 5.0 s.
	auditPollTimeout = 30 * time.Second
	// auditSettleDelay is how long an exactly-once check waits for a late duplicate: one writer batch cycle at the
	// normal lag. When the event itself took longer than auditNormalLag, the pipeline is loaded and the check waits
	// auditLoadedSettleDelay, one batch wait plus the processing allowance of auditPollTimeout (PDK-551).
	auditSettleDelay       = 5 * time.Second
	auditLoadedSettleDelay = 10 * time.Second
	// auditLookback bounds the audit list expectOneEvent pages through. Unbounded, one poll pages through every event
	// of the last 7 days (about 90 pages on a busy stack) and takes most of a 10 s window, so an event indexed just
	// after the first poll began is never seen (PDK-445). It is far longer than any case waits between its request and
	// the check, so the request's event is always inside it.
	auditLookback = 15 * time.Minute
)

// parallelCases returns a semaphore that bounds the parallel cases of a gate: PADDOCK_ACCEPTANCE_PARALLEL, default 8
// (plan M3b decision 2). go test caps parallel subtests as well (-parallel, default GOMAXPROCS), so the effective limit
// is min(semaphore, -parallel); make acceptance passes -parallel only with ACCEPTANCE_GO_PARALLEL (PDK-556).
func parallelCases(t *testing.T) chan struct{} {
	t.Helper()
	return make(chan struct{}, parallelism(t))
}

// parallelism is the semaphore size for a gate's parallel cases (PADDOCK_ACCEPTANCE_PARALLEL, default 8), an upper
// bound: go test's -parallel may hold fewer at a time (see parallelCases).
func parallelism(t *testing.T) int {
	t.Helper()
	n := 8
	if v := os.Getenv("PADDOCK_ACCEPTANCE_PARALLEL"); v != "" {
		var err error
		if n, err = strconv.Atoi(v); err != nil || n < 1 {
			t.Fatalf("PADDOCK_ACCEPTANCE_PARALLEL=%q: want a positive integer", v)
		}
	}
	return n
}

func testContext(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func login(t *testing.T, user string) *env.Portal {
	t.Helper()
	p, err := env.Login(testContext(t, time.Minute), user, "")
	if err != nil {
		t.Fatalf("login %s: %v (run `make dev-seed` first)", user, err)
	}
	return p
}

func call(t *testing.T, p *env.Portal, method, path string, body any) env.Response {
	t.Helper()
	res, err := p.Do(testContext(t, time.Minute), method, path, body)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	if res.RequestID == "" {
		t.Fatalf("%s %s: response without X-Request-Id", method, path)
	}
	return res
}

func expectStatus(t *testing.T, res env.Response, status int, code string) {
	t.Helper()
	if res.Status != status || (code != "" && res.ProblemCode() != code) {
		t.Fatalf("got HTTP %d %s, want %d %s: %s", res.Status, res.ProblemCode(), status, code, res.Body)
	}
}

// auditSettle returns the settle delay of an exactly-once check whose event became visible after waited.
func auditSettle(waited time.Duration) time.Duration {
	if waited > auditNormalLag {
		return auditLoadedSettleDelay
	}
	return auditSettleDelay
}

// expectOneEvent polls the audit log visible to viewer (max auditPollTimeout) for the request's correlation ID and
// requires exactly one event with code and outcome — also after the settle delay (auditSettle).
func expectOneEvent(t *testing.T, viewer *env.Portal, requestID, code, outcome string) env.AuditEvent {
	t.Helper()
	ctx := testContext(t, 2*time.Minute)
	from := time.Now().Add(-auditLookback)
	var found []env.AuditEvent
	start := time.Now()
	deadline := start.Add(auditPollTimeout)
	for {
		// The deadline is checked against the poll's start: on a loaded host one poll pages for seconds, and a
		// snapshot taken before the deadline must not end the wait (PDK-551).
		polled := time.Now()
		events, err := viewer.AuditEventsSince(ctx, "", from)
		if err != nil {
			t.Fatal(err)
		}
		found = env.EventsFor(events, requestID)
		if len(found) > 0 || polled.After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	waited := time.Since(start)
	check := func(when string) {
		if len(found) != 1 {
			t.Fatalf("%s: %d audit events for request %s, want exactly 1 (%s/%s): %+v", when, len(found), requestID, code, outcome, found)
		}
		if found[0].Code != code || found[0].Outcome != outcome {
			t.Fatalf("%s: event %s/%s, want %s/%s", when, found[0].Code, found[0].Outcome, code, outcome)
		}
	}
	check(fmt.Sprintf("after polling %s", waited.Round(time.Second)))
	settle := auditSettle(waited)
	time.Sleep(settle)
	events, err := viewer.AuditEventsSince(ctx, "", from)
	if err != nil {
		t.Fatal(err)
	}
	found = env.EventsFor(events, requestID)
	check(fmt.Sprintf("%s later", settle))
	return found[0]
}

func auditIndex(t *testing.T) *env.AuditIndex {
	t.Helper()
	idx, err := env.NewAuditIndex(testContext(t, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idx.Close)
	return idx
}

// expectOneIndexEvent is expectOneEvent for events no portal session can read (platform scope): it queries the
// audit index of org directly.
func expectOneIndexEvent(t *testing.T, idx *env.AuditIndex, org uuid.UUID, where string, arg any, code, outcome string, timeout time.Duration) env.IndexEvent {
	t.Helper()
	ctx := testContext(t, timeout+auditLoadedSettleDelay+time.Minute)
	var found []env.IndexEvent
	start := time.Now()
	deadline := start.Add(timeout)
	for {
		polled := time.Now()
		var err error
		found, err = idx.Events(ctx, org, where, arg)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) > 0 || polled.After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	waited := time.Since(start)
	check := func(when string) {
		if len(found) != 1 || found[0].Code != code || found[0].Outcome != outcome {
			t.Fatalf("%s: index events of %s where %s=%v: %+v, want exactly one %s/%s", when, org, where, arg, found, code, outcome)
		}
	}
	check(fmt.Sprintf("after polling %s", waited.Round(time.Second)))
	settle := auditSettle(waited)
	time.Sleep(settle)
	var err error
	if found, err = idx.Events(ctx, org, where, arg); err != nil {
		t.Fatal(err)
	}
	check(fmt.Sprintf("%s later", settle))
	return found[0]
}

// Catch-up check of the audit pipeline (PDK-028). The normal lag is the audit writer's batch wait (5 s) plus margin;
// the consecutive probes span about half a minute, so a pipeline that is slow only now and then does not pass.
const (
	auditNormalLag      = 7 * time.Second
	auditCatchUpProbes  = 5
	auditCatchUpTimeout = 5 * time.Minute
	auditProbeTimeout   = time.Minute
)

// waitAuditCaughtUp blocks until the outbox → audit-writer pipeline is back to its normal lag: auditCatchUpProbes
// probe events in a row are in the index within auditNormalLag of their request, with recorded_at - occurred_at
// within that bound too. A probe is an audited validation failure of the platform administrator without side
// effects. A gate that stops or recreates services calls it before it returns, so the audit polls of the next gate
// do not run into the recovery.
func waitAuditCaughtUp(t *testing.T, root *env.Portal, idx *env.AuditIndex) {
	t.Helper()
	ctx := testContext(t, auditCatchUpTimeout+auditProbeTimeout)
	start := time.Now()
	for good, n := 0, 1; good < auditCatchUpProbes; n++ {
		if time.Since(start) > auditCatchUpTimeout {
			t.Fatalf("audit pipeline not back to its normal lag (%s) after %s", auditNormalLag, auditCatchUpTimeout)
		}
		res := call(t, root, http.MethodPost, "/api/platform/v1/organizations", map[string]string{"slug": "Not A Slug", "name": "x"})
		expectStatus(t, res, http.StatusBadRequest, "invalid_request")
		sent := time.Now()
		var lag time.Duration
		found := false
		for !found && time.Since(sent) < auditProbeTimeout {
			time.Sleep(250 * time.Millisecond)
			var err error
			// uuid.Nil is the platform pseudo-organization (platformOrg lives in a _test.go file, which this file
			// cannot reference outside test builds).
			if lag, found, err = idx.RecordingLag(ctx, uuid.Nil, res.RequestID); err != nil {
				t.Fatal(err)
			}
		}
		visible := time.Since(sent)
		if found && visible <= auditNormalLag && lag <= auditNormalLag {
			good++
		} else {
			good = 0
		}
		t.Logf("audit probe %d: visible after %s (found %t), recorded_at lag %s; %d of %d in a row within %s",
			n, visible.Round(10*time.Millisecond), found, lag.Round(10*time.Millisecond), good, auditCatchUpProbes, auditNormalLag)
	}
	t.Logf("audit pipeline caught up after %s", time.Since(start).Round(time.Second))
}

// waitAuditPast blocks until a marker event triggered now (the probe of waitAuditCaughtUp) is visible in the audit
// index and then for the settle delay of its lag (auditSettle). An absence check that follows covers every event
// the stack committed before the call, however slow the pipeline is (PDK-569).
func waitAuditPast(t *testing.T, root *env.Portal, idx *env.AuditIndex) {
	t.Helper()
	ctx := testContext(t, auditPollTimeout+time.Minute)
	res := call(t, root, http.MethodPost, "/api/platform/v1/organizations", map[string]string{"slug": "Not A Slug", "name": "x"})
	expectStatus(t, res, http.StatusBadRequest, "invalid_request")
	start := time.Now()
	deadline := start.Add(auditPollTimeout)
	for {
		polled := time.Now()
		_, found, err := idx.RecordingLag(ctx, uuid.Nil, res.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		if found {
			break
		}
		if polled.After(deadline) {
			t.Fatalf("audit marker %s not visible within %s", res.RequestID, auditPollTimeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
	// The relay publishes the outbox in id order to the single serial audit writer, so an earlier event is recorded
	// no later than the marker; the settle covers a requeued batch or a second relay replica reordering them.
	waited := time.Since(start)
	settle := auditSettle(waited)
	t.Logf("audit marker visible after %s, settling %s", waited.Round(10*time.Millisecond), settle)
	time.Sleep(settle)
}

// tempUser creates an Authentik user in groups and deletes it when the test ends.
func tempUser(t *testing.T, prefix string, groups ...string) (string, string) {
	t.Helper()
	ctx := testContext(t, time.Minute)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	username := prefix + "-" + hex.EncodeToString(b) + "@acceptance.test"
	password := "pw-" + uuid.NewString()
	pk, err := ak.CreateUser(ctx, username, password, groups...)
	t.Cleanup(func() {
		if pk != 0 {
			_ = ak.DeleteUser(context.Background(), pk)
		}
	})
	if err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	return username, password
}

func loginAs(t *testing.T, username, password string) (*env.Portal, error) {
	t.Helper()
	return env.Login(testContext(t, time.Minute), username, password)
}

type me struct {
	ID           string `json:"id"`
	Role         string `json:"role"`
	Organization *struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	} `json:"organization"`
}

func whoami(t *testing.T, p *env.Portal) me {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/me", nil)
	expectStatus(t, res, http.StatusOK, "")
	var m me
	if err := res.JSON(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func orgOf(t *testing.T, p *env.Portal) uuid.UUID {
	t.Helper()
	m := whoami(t, p)
	if m.Organization == nil {
		t.Fatal("session has no organization")
	}
	return uuid.MustParse(m.Organization.ID)
}

func loadSpec(t *testing.T) *openapi3.T {
	t.Helper()
	root, err := stack.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromFile(filepath.Join(root, "api", "openapi", "admin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func uniqueName(prefix string) string { return prefix + " " + uuid.NewString()[:8] }

func uniqueSuffix() string { return strings.ReplaceAll(uniqueName("")[1:], "-", "") }

// responseID is the id of a created resource.
func responseID(t *testing.T, res env.Response) uuid.UUID {
	t.Helper()
	var body struct {
		ID string `json:"id"`
	}
	if err := res.JSON(&body); err != nil {
		t.Fatal(err)
	}
	return uuid.MustParse(body.ID)
}

// rootS3 is the audit object store with root credentials (reading objects for checks).
func rootS3(t *testing.T) *s3.Client {
	t.Helper()
	return s3Client(t, mustSecret(t, "rustfs_audit_root_user"), mustSecret(t, "rustfs_audit_root_password"))
}

// objectEvents downloads one WORM object and decodes its JSON lines.
func objectEvents(t *testing.T, client *s3.Client, key string) []map[string]any {
	t.Helper()
	bucket := stack.AuditBucket()
	out, err := client.GetObject(testContext(t, time.Minute), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	defer func() { _ = out.Body.Close() }()
	compressed, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	raw, err := dec.DecodeAll(compressed, nil)
	if err != nil {
		t.Fatalf("decompress %s: %v", key, err)
	}
	var events []map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	for d.More() {
		var ev map[string]any
		if err := d.Decode(&ev); err != nil {
			t.Fatal(err)
		}
		events = append(events, ev)
	}
	return events
}

func containsAny(body []byte, ids []string) string {
	for _, id := range ids {
		if id != "" && strings.Contains(string(body), id) {
			return id
		}
	}
	return ""
}

func s3Client(t *testing.T, accessKey, secretKey string) *s3.Client {
	t.Helper()
	return s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(stack.AuditS3Endpoint()),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
	})
}

func mustSecret(t *testing.T, name string) string {
	t.Helper()
	v, err := stack.Secret(name)
	if err != nil {
		t.Fatalf("read secret %s (run `make dev-secrets up audit-bootstrap` first): %v", name, err)
	}
	return v
}

func expectError(t *testing.T, op string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s succeeded; the WORM guarantee is broken", op)
	}
	t.Logf("%s rejected as expected: %v", op, err)
}

// stepUp runs a step-up of p as user and fails the test unless the outcome matches ok.
func stepUp(t *testing.T, p *env.Portal, user string, ok bool) {
	t.Helper()
	// A user's TOTP generator hands out one code per 30 s step (Authentik refuses a reused code), so the parallel cases
	// of a gate that step up as the same user queue for it: up to one step per parallel case before the flow starts.
	final, err := p.StepUp(testContext(t, 3*time.Minute+time.Duration(parallelism(t))*30*time.Second), user, "/settings")
	if err != nil {
		t.Fatalf("step-up as %s: %v", user, err)
	}
	if failed := strings.Contains(final, "stepup=failed"); failed == ok {
		t.Fatalf("step-up as %s returned to %s", user, final)
	}
}

// operatorRootsMu serializes every read-modify-write of operator roots in this run: the list is replaced as a whole,
// so two writers must never interleave (ensureOperatorRoots, the audit case of the setting, the isolation fixture).
var operatorRootsMu sync.Mutex
