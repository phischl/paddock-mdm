package acceptance

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// Paths of the backup API (plan M15 §6.2) that the backup gates use beside backupKeyPath, backupTargets and restorePlans.
const (
	backupOverviewPath = "/api/platform/v1/backup"
	backupRunPath      = "/api/platform/v1/backup/run"
	backupRunsPath     = "/api/platform/v1/backup/runs"
)

// The development targets that `make dev-seed BACKUP=1` creates (test/acceptance/cmd/devseed/backup.go).
const (
	devS3Target    = "dev-s3"
	devLocalTarget = "dev-local"
	devS3Bucket    = "paddock-backup"
)

// requireBackupStack skips the gate on a stack started without BACKUP=1 (no paddock-backup container at all: CI's stack)
// and fails it when the backup role exists but does not run, so a crashed role never passes as a skip.
func requireBackupStack(t *testing.T) {
	t.Helper()
	ctx := testContext(t, time.Minute)
	filter := []string{"--filter", "label=com.docker.compose.project=" + stack.Project(),
		"--filter", "label=com.docker.compose.service=paddock-backup", "--filter", "label=com.docker.compose.oneoff=False"}
	all, err := stack.Docker(ctx, nil, append([]string{"ps", "-a", "-q"}, filter...)...)
	if err != nil {
		t.Fatalf("looking for the backup role: %v", err)
	}
	if strings.TrimSpace(all) == "" {
		t.Skip("needs the backup role: start the stack with `make up BACKUP=1` and run `make dev-seed BACKUP=1`")
	}
	running, err := stack.Docker(ctx, nil, append([]string{"ps", "-q", "--filter", "status=running"}, filter...)...)
	if err != nil {
		t.Fatalf("looking for the backup role: %v", err)
	}
	if strings.TrimSpace(running) == "" {
		t.Fatal("the stack has a paddock-backup container, but it does not run")
	}
}

// productionStepUpWindow is the step-up window of a production stack; backupAdmin falls back to it when the stack
// does not report its own.
const productionStepUpWindow = 5 * time.Minute

// backupAdmin is the platform administrator of the backup gates with a step-up that fresh renews before it leaves the
// stack's step-up window (the gates wait minutes for the backup role between writes; the dev stacks run 30 s).
type backupAdmin struct {
	*env.Portal
	steppedUp time.Time
	window    time.Duration
}

func newBackupAdmin(t *testing.T) *backupAdmin {
	t.Helper()
	a := &backupAdmin{Portal: login(t, env.PlatformAdmin)}
	a.window = stackStepUpWindow(t, a.Portal)
	a.fresh(t)
	return a
}

// stackStepUpWindow reads the step-up window the API reports on GET /api/v1/me (development stacks only, it is the
// value the API enforces) and falls back to the production window when it is not reported.
func stackStepUpWindow(t *testing.T, p *env.Portal) time.Duration {
	t.Helper()
	var me struct {
		StepUp *struct {
			WindowSeconds int `json:"window_seconds"`
		} `json:"step_up"`
	}
	res := call(t, p, http.MethodGet, "/api/v1/me", nil)
	if res.Status != http.StatusOK || res.JSON(&me) != nil || me.StepUp == nil || me.StepUp.WindowSeconds <= 0 {
		t.Logf("step-up window not reported (HTTP %d), assuming %s", res.Status, productionStepUpWindow)
		return productionStepUpWindow
	}
	return time.Duration(me.StepUp.WindowSeconds) * time.Second
}

// stepUpDue reports whether a step-up taken age ago must be renewed before the next call: when less than a third of
// the window (at most a minute) is left, so the call that follows still lands inside it.
func stepUpDue(age, window time.Duration) bool {
	return age > window-min(window/3, time.Minute)
}

// fresh steps up again when the last step-up is about to leave the stack's window.
func (a *backupAdmin) fresh(t *testing.T) *env.Portal {
	t.Helper()
	if a.steppedUp.IsZero() || stepUpDue(time.Since(a.steppedUp), a.window) {
		stepUp(t, a.Portal, env.PlatformAdmin, true)
		a.steppedUp = time.Now()
	}
	return a.Portal
}

// backupKey is BackupKey of the admin API.
type backupKey struct {
	KeyID       string     `json:"key_id"`
	Fingerprint string     `json:"fingerprint"`
	State       string     `json:"state"`
	ConfirmedAt *time.Time `json:"confirmed_at"`
	RetiredAt   *time.Time `json:"retired_at"`
	Attempts    int        `json:"attempts"`
	Legacy      bool       `json:"legacy"`
	Positions   []int      `json:"positions"`
}

type backupKeyStatus struct {
	Active  *backupKey  `json:"active"`
	Pending *backupKey  `json:"pending"`
	Retired []backupKey `json:"retired"`
}

type generatedBackupKey struct {
	KeyID        string `json:"key_id"`
	Key          string `json:"key"`
	Fingerprint  string `json:"fingerprint"`
	Positions    []int  `json:"positions"`
	DownloadName string `json:"download_name"`
}

// backupSecrets are the key texts and target credentials the gates of this run handed to the stack; the log checks
// look for every one of them.
var backupSecrets struct {
	sync.Mutex
	values []string
}

func rememberBackupSecret(v string) {
	backupSecrets.Lock()
	defer backupSecrets.Unlock()
	if v != "" && !slices.Contains(backupSecrets.values, v) {
		backupSecrets.values = append(backupSecrets.values, v)
	}
}

func knownBackupSecrets() []string {
	backupSecrets.Lock()
	defer backupSecrets.Unlock()
	return slices.Clone(backupSecrets.values)
}

func getBackupKeyStatus(t *testing.T, p *env.Portal) (backupKeyStatus, env.Response) {
	t.Helper()
	res := call(t, p, http.MethodGet, backupKeyPath, nil)
	expectStatus(t, res, http.StatusOK, "")
	var s backupKeyStatus
	if err := res.JSON(&s); err != nil {
		t.Fatalf("backup key status %s: %v", res.Body, err)
	}
	return s, res
}

// challengeAnswer is the answer to a key's challenge: the characters of text at the 1-based positions, in order.
func challengeAnswer(t *testing.T, text string, positions []int) string {
	t.Helper()
	var b strings.Builder
	for _, p := range positions {
		if p < 1 || p > len(text) {
			t.Fatalf("challenge position %d outside the key text of %d characters", p, len(text))
		}
		b.WriteByte(text[p-1])
	}
	return b.String()
}

// wrongAnswer is six characters that differ from the right answer in every position.
func wrongAnswer(right string) string {
	b := []byte(right)
	for i := range b {
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
	}
	return string(b)
}

// keyFingerprint is backupset.Fingerprint of a key text: the first 16 hex characters of the SHA-256 of its 32 bytes.
func keyFingerprint(t *testing.T, text string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != 32 {
		t.Fatalf("key text is not 32 bytes in standard base64 (%d bytes, %v)", len(raw), err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

func generateBackupKey(t *testing.T, a *backupAdmin) (generatedBackupKey, env.Response) {
	t.Helper()
	res := call(t, a.fresh(t), http.MethodPost, backupKeyPath, nil)
	expectStatus(t, res, http.StatusCreated, "")
	var g generatedBackupKey
	if err := res.JSON(&g); err != nil {
		t.Fatalf("generated key: %v", err)
	}
	rememberBackupSecret(g.Key)
	return g, res
}

func confirmBackupKey(t *testing.T, a *backupAdmin, keyID, answer string) env.Response {
	t.Helper()
	return call(t, a.fresh(t), http.MethodPost, backupKeyPath+"/"+keyID+"/confirm", map[string]string{"answer": answer})
}

// ensureActiveBackupKey returns the active key and generates and confirms one when there is none; a pending key is
// discarded first (a gate interrupted between generating and confirming leaves one behind).
func ensureActiveBackupKey(t *testing.T, a *backupAdmin) backupKey {
	t.Helper()
	s, _ := getBackupKeyStatus(t, a.Portal)
	if s.Active != nil {
		return *s.Active
	}
	if s.Pending != nil {
		expectStatus(t, call(t, a.fresh(t), http.MethodPost, backupKeyPath+"/"+s.Pending.KeyID+"/discard", nil), http.StatusOK, "")
	}
	g, _ := generateBackupKey(t, a)
	res := confirmBackupKey(t, a, g.KeyID, challengeAnswer(t, g.Key, g.Positions))
	expectStatus(t, res, http.StatusOK, "")
	var k backupKey
	if err := res.JSON(&k); err != nil || k.State != "confirmed" {
		t.Fatalf("confirmed key %s: %v", res.Body, err)
	}
	return k
}

// backupTarget is BackupTarget of the admin API.
type backupTarget struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Enabled        bool   `json:"enabled"`
	HostState      string `json:"host_state"`
	HostRevision   int    `json:"host_revision"`
	HasCredentials bool   `json:"has_credentials"`
	Settings       struct {
		S3 *struct {
			Prefix string `json:"prefix"`
		} `json:"s3"`
	} `json:"settings"`
	TestRequestedAt *time.Time `json:"test_requested_at"`
	LastTestAt      *time.Time `json:"last_test_at"`
	LastTestOK      *bool      `json:"last_test_ok"`
	LastTestError   *string    `json:"last_test_error"`
	Status          []struct {
		Kind          string     `json:"kind"`
		LastSuccessAt *time.Time `json:"last_success_at"`
		LastError     *string    `json:"last_error"`
	} `json:"status"`
}

// lastSuccess returns the target's last success of kind.
func (b backupTarget) lastSuccess(kind string) time.Time {
	for _, s := range b.Status {
		if s.Kind == kind && s.LastSuccessAt != nil {
			return *s.LastSuccessAt
		}
	}
	return time.Time{}
}

type backupTargetPage struct {
	Items []backupTarget `json:"items"`
	Total int            `json:"total"`
	Sort  string         `json:"sort"`
}

func listBackupTargets(t *testing.T, p *env.Portal, query url.Values) backupTargetPage {
	t.Helper()
	if query.Get("page_size") == "" {
		query.Set("page_size", "100")
	}
	res := call(t, p, http.MethodGet, backupTargets+"?"+query.Encode(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page backupTargetPage
	if err := res.JSON(&page); err != nil {
		t.Fatalf("backup targets %s: %v", res.Body, err)
	}
	return page
}

func getBackupTarget(t *testing.T, p *env.Portal, id string) (backupTarget, env.Response) {
	t.Helper()
	res := call(t, p, http.MethodGet, backupTargets+"/"+id, nil)
	expectStatus(t, res, http.StatusOK, "")
	var target backupTarget
	if err := res.JSON(&target); err != nil {
		t.Fatalf("backup target %s: %v", res.Body, err)
	}
	return target, res
}

// devBackupTarget returns the development target name, which `make dev-seed BACKUP=1` creates.
func devBackupTarget(t *testing.T, p *env.Portal, name string) backupTarget {
	t.Helper()
	for _, it := range listBackupTargets(t, p, url.Values{"q": {name}}).Items {
		if it.Name == name {
			return it
		}
	}
	t.Fatalf("no backup target %s: run `make dev-seed BACKUP=1`", name)
	return backupTarget{}
}

// waitBackupTarget polls the target every second until cond holds.
func waitBackupTarget(t *testing.T, p *env.Portal, id string, timeout time.Duration, what string, cond func(backupTarget) bool) backupTarget {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		target, _ := getBackupTarget(t, p, id)
		if cond(target) {
			return target
		}
		if time.Now().After(deadline) {
			t.Fatalf("backup target %s: %s not reached within %s: %+v", target.Name, what, timeout, target)
		}
		time.Sleep(time.Second)
	}
}

// backupRun is BackupRun of the admin API.
type backupRun struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Label      string            `json:"label"`
	State      string            `json:"state"`
	Outcome    *string           `json:"outcome"`
	FinishedAt *time.Time        `json:"finished_at"`
	ErrorClass *string           `json:"error_class"`
	Targets    []backupRunTarget `json:"targets"`
}

// backupRunTarget is BackupRunTarget of the admin API: the mirror result of one run on one target.
type backupRunTarget struct {
	TargetID   string  `json:"target_id"`
	OK         bool    `json:"ok"`
	ErrorClass *string `json:"error_class"`
}

// requestBackupRuns sends POST /backup/run for kinds (nil: every kind) and returns the requested runs.
func requestBackupRuns(t *testing.T, a *backupAdmin, kinds []string, label string) ([]backupRun, env.Response) {
	t.Helper()
	res := call(t, a.fresh(t), http.MethodPost, backupRunPath, map[string]any{"kinds": kinds, "label": label})
	expectStatus(t, res, http.StatusAccepted, "")
	var runs []backupRun
	if err := res.JSON(&runs); err != nil {
		t.Fatalf("requested runs %s: %v", res.Body, err)
	}
	return runs, res
}

// waitBackupRuns polls the run history every second until every run of ids is finished and returns them by ID.
func waitBackupRuns(t *testing.T, p *env.Portal, ids []string, timeout time.Duration) map[string]backupRun {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		res := call(t, p, http.MethodGet, backupRunsPath+"?page_size=100&sort=-started_at", nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Items []backupRun `json:"items"`
		}
		if err := res.JSON(&page); err != nil {
			t.Fatal(err)
		}
		found := map[string]backupRun{}
		for _, r := range page.Items {
			if slices.Contains(ids, r.ID) && r.State == "finished" {
				found[r.ID] = r
			}
		}
		if len(found) == len(ids) {
			return found
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d backup runs finished within %s: %+v", len(found), len(ids), timeout, found)
		}
		time.Sleep(time.Second)
	}
}

// promValue returns the value of the single series of query in the development Prometheus (ok false without one).
func promValue(t *testing.T, query string) (float64, bool) {
	t.Helper()
	var out struct {
		Data struct {
			Result []struct {
				Value []any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := prometheusGet(testContext(t, time.Minute), "/api/v1/query?query="+url.QueryEscape(query), &out); err != nil {
		t.Fatalf("prometheus %s: %v", query, err)
	}
	if len(out.Data.Result) != 1 || len(out.Data.Result[0].Value) != 2 {
		return 0, false
	}
	s, _ := out.Data.Result[0].Value[1].(string)
	v, err := strconv.ParseFloat(s, 64)
	return v, err == nil
}

// waitKeyConfirmedMetric polls Prometheus every second until paddock_backup_key_confirmed has the value want: the
// backup role sets it each round (15 s on the development stack) and Prometheus scrapes it every 15 s.
func waitKeyConfirmedMetric(t *testing.T, want float64) {
	t.Helper()
	const timeout = 2 * time.Minute
	deadline := time.Now().Add(timeout)
	for {
		v, ok := promValue(t, `paddock_backup_key_confirmed{job="paddock-backup"}`)
		if ok && v == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("paddock_backup_key_confirmed = %v (series present: %t), want %v within %s", v, ok, want, timeout)
		}
		time.Sleep(time.Second)
	}
}

// expectSecretsNotLogged fails when any of secrets appears in the log of a container of the stack since the given time
// (plan M15 C7: no key, password or access key in any log). The values are exact, so a hit is never a false positive.
func expectSecretsNotLogged(t *testing.T, since time.Time, secrets ...string) {
	t.Helper()
	ctx := testContext(t, 5*time.Minute)
	ids, err := stack.Docker(ctx, nil, "ps", "-a", "-q", "--filter", "label=com.docker.compose.project="+stack.Project())
	if err != nil {
		t.Fatalf("listing the stack's containers: %v", err)
	}
	n := 0
	for _, id := range strings.Fields(ids) {
		cmd := exec.CommandContext(ctx, "docker", "logs", "--since", since.UTC().Format(time.RFC3339), id) //nolint:gosec // test orchestration
		out, err := cmd.CombinedOutput()
		if err != nil {
			// A one-off container removed between the listing and this call has no log any more.
			if strings.Contains(string(out), "No such container") {
				continue
			}
			t.Fatalf("docker logs %s: %v: %s", id, err, out)
		}
		n++
		for i, s := range secrets {
			if s != "" && strings.Contains(string(out), s) {
				t.Errorf("secret %d of %d appears in the log of container %s", i+1, len(secrets), id)
			}
		}
	}
	if n == 0 {
		t.Fatal("no container log was read")
	}
	t.Logf("%d secrets absent from the logs of %d containers since %s", len(secrets), n, since.Format(time.RFC3339))
}

// expectNoSecretIn fails when body contains one of secrets or a field of a write-only credential.
func expectNoSecretIn(t *testing.T, what string, body []byte, secrets ...string) {
	t.Helper()
	for _, field := range []string{`"secret_key"`, `"access_key"`, `"password"`} {
		if strings.Contains(string(body), field) {
			t.Errorf("%s holds the field %s: %s", what, field, body)
		}
	}
	for i, s := range secrets {
		if s != "" && strings.Contains(string(body), s) {
			t.Errorf("%s holds secret %d of %d", what, i+1, len(secrets))
		}
	}
}

// devTargetS3 is a client of the development S3 target's bucket on the audit host's RustFS, with the target's own
// credentials (compose.backup.dev.yaml; the host reaches audit-rustfs on its published port).
func devTargetS3(t *testing.T) *s3.Client {
	t.Helper()
	return s3Client(t, mustSecret(t, "backup_dev_target_access_key"), mustSecret(t, "backup_dev_target_secret_key"))
}

// backupManifest is the part of manifest.json (paddock.backup-set.v1, plan M15 §6.5) that the gates read.
type backupManifest struct {
	Schema      string    `json:"schema"`
	GeneratedAt time.Time `json:"generated_at"`
	KeyID       string    `json:"key_id"`
	Contents    struct {
		PgBackRest struct {
			Path    string `json:"path"`
			Stanzas []struct {
				Name       string    `json:"name"`
				LastFullAt time.Time `json:"last_full_at"`
			} `json:"stanzas"`
		} `json:"pgbackrest"`
		OpenBao []backupFile `json:"openbao"`
		Fleet   []backupFile `json:"fleet"`
		Escrow  []backupFile `json:"escrow"`
	} `json:"contents"`
}

type backupFile struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
}

// lastFull returns the stanza's last full backup time in the manifest.
func (m backupManifest) lastFull(stanza string) time.Time {
	for _, s := range m.Contents.PgBackRest.Stanzas {
		if s.Name == stanza {
			return s.LastFullAt
		}
	}
	return time.Time{}
}

// s3SetRoot is the set's prefix in a target bucket without a target prefix (backupset.SetRoot).
const s3SetRoot = "paddock-backup/"

// targetManifest reads manifest.json of the development S3 target; ok is false while the target holds none.
func targetManifest(t *testing.T, client *s3.Client) (backupManifest, bool) {
	t.Helper()
	bucket, key := devS3Bucket, s3SetRoot+"manifest.json"
	out, err := client.GetObject(testContext(t, time.Minute), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchKey") {
			return backupManifest{}, false
		}
		t.Fatalf("get %s/%s: %v", bucket, key, err)
	}
	defer func() { _ = out.Body.Close() }()
	raw, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	var m backupManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest.json of the S3 target: %v", err)
	}
	return m, true
}

// waitTargetManifest polls the S3 target's manifest every second until cond holds.
func waitTargetManifest(t *testing.T, client *s3.Client, timeout time.Duration, what string, cond func(backupManifest) bool) backupManifest {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		m, ok := targetManifest(t, client)
		if ok && cond(m) {
			return m
		}
		if time.Now().After(deadline) {
			t.Fatalf("the S3 target's manifest: %s not reached within %s (present %t, key %s, path %s, generated %s)",
				what, timeout, ok, m.KeyID, m.Contents.PgBackRest.Path, m.GeneratedAt)
		}
		time.Sleep(time.Second)
	}
}

// targetObjects counts the objects of the development S3 target below prefix (relative to the set root).
func targetObjects(t *testing.T, client *s3.Client, prefix string) int {
	t.Helper()
	bucket, p := devS3Bucket, s3SetRoot+prefix
	n := 0
	pages := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &p})
	for pages.HasMorePages() {
		page, err := pages.NextPage(testContext(t, time.Minute))
		if err != nil {
			t.Fatalf("list %s/%s: %v", bucket, p, err)
		}
		n += len(page.Contents)
	}
	return n
}

// ownerConn is a paddock_owner connection: the backup gates set up key states that no API reaches (no active key, an
// empty key table), as the gates that play a compromised database do.
func ownerConn(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn, err := stack.PaddockOwnerDSN()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(testContext(t, time.Minute), dsn)
	if err != nil {
		t.Fatalf("connect as paddock_owner: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// fmtTime formats t for a literal in an audit index query (generated here, never user input).
func fmtTime(t time.Time) string { return fmt.Sprintf("'%s'", t.UTC().Format(time.RFC3339Nano)) }
