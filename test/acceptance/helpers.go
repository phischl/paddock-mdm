// Package acceptance holds the acceptance gates of the milestone plans; they run against the development stack.
package acceptance

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	auditPollTimeout = 10 * time.Second
	auditSettleDelay = 5 * time.Second
)

// parallelCases returns a semaphore that bounds the parallel cases of a gate: PADDOCK_ACCEPTANCE_PARALLEL, default 8
// (plan M3b decision 2).
func parallelCases(t *testing.T) chan struct{} {
	t.Helper()
	return make(chan struct{}, parallelism(t))
}

// parallelism is the number of parallel cases of a gate (PADDOCK_ACCEPTANCE_PARALLEL, default 8).
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

// expectOneEvent polls the audit log visible to viewer (max 10 s) for the request's correlation ID and requires
// exactly one event with code and outcome — also after another 5 s.
func expectOneEvent(t *testing.T, viewer *env.Portal, requestID, code, outcome string) env.AuditEvent {
	t.Helper()
	ctx := testContext(t, 2*time.Minute)
	var found []env.AuditEvent
	deadline := time.Now().Add(auditPollTimeout)
	for {
		events, err := viewer.AuditEvents(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		found = env.EventsFor(events, requestID)
		if len(found) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	check := func(when string) {
		if len(found) != 1 {
			t.Fatalf("%s: %d audit events for request %s, want exactly 1 (%s/%s): %+v", when, len(found), requestID, code, outcome, found)
		}
		if found[0].Code != code || found[0].Outcome != outcome {
			t.Fatalf("%s: event %s/%s, want %s/%s", when, found[0].Code, found[0].Outcome, code, outcome)
		}
	}
	check("after polling")
	time.Sleep(auditSettleDelay)
	events, err := viewer.AuditEvents(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	found = env.EventsFor(events, requestID)
	check("5 s later")
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
	ctx := testContext(t, timeout+time.Minute)
	var found []env.IndexEvent
	deadline := time.Now().Add(timeout)
	for {
		var err error
		found, err = idx.Events(ctx, org, where, arg)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	check := func(when string) {
		if len(found) != 1 || found[0].Code != code || found[0].Outcome != outcome {
			t.Fatalf("%s: index events of %s where %s=%v: %+v, want exactly one %s/%s", when, org, where, arg, found, code, outcome)
		}
	}
	check("after polling")
	time.Sleep(auditSettleDelay)
	var err error
	if found, err = idx.Events(ctx, org, where, arg); err != nil {
		t.Fatal(err)
	}
	check("5 s later")
	return found[0]
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
