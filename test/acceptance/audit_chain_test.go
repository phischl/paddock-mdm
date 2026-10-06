package acceptance

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

var objectKeyPattern = regexp.MustCompile(`^org/([0-9a-f-]{36})/(\d{4}/\d{2}/\d{2}/\d{2}-[0-9a-f-]{36}\.jsonl\.zst|manifests/\d{4}-\d{2}-\d{2}\.json)$`)

// TestAuditChain is gate A5 (plan M0 §8, AC5): the sealer writes a signed manifest chain that `paddock-server
// audit verify` accepts, every WORM object lives below org/<organization_id>/ and holds only that organization's
// events, and a missing manifest breaks the chain.
//
// A fresh organization is used so the gate can seal its current day (development-only `audit seal --day --org`)
// without sealing other organizations' days early: an organization created today has nothing to seal for yesterday.
func TestAuditChain(t *testing.T) {
	ctx := testContext(t, 10*time.Minute)
	root := login(t, env.PlatformAdmin)
	alice, carol := login(t, env.Alice), login(t, env.Carol)

	// A fresh organization with an admin and some activity.
	body := newOrg()
	res := call(t, root, http.MethodPost, "/api/platform/v1/organizations", body)
	expectStatus(t, res, http.StatusCreated, "")
	chain := responseID(t, res)
	user, pw := tempUser(t, "chain", env.RoleGroup(body["slug"], "admins"))
	admin, err := loginAs(t, user, pw)
	if err != nil {
		t.Fatalf("login as the new organization's admin: %v", err)
	}
	for i := 0; i < 2; i++ {
		createGroup(t, admin)
	}
	// Activity in acme and globex for the object checks.
	createGroup(t, alice)
	createGroup(t, carol)

	waitForEvents(t, admin, 3) // admin.login + 2 × device_group.created
	today := time.Now().UTC().Format(time.DateOnly)

	code, out, err := stack.PaddockServer(ctx, "audit", "seal", "--day", today, "--org", chain.String())
	if err != nil || code != 0 {
		t.Fatalf("audit seal: exit %d, %v\n%s", code, err, out)
	}
	code, out, err = stack.PaddockServer(ctx, "audit", "verify", "--org", chain.String(), "--from", today, "--to", today)
	if err != nil || code != 0 {
		t.Fatalf("audit verify: exit %d, %v\n%s", code, err, out)
	}
	if !strings.Contains(out, "OK "+chain.String()) {
		t.Fatalf("audit verify output: %s", out)
	}
	t.Logf("verify: %s", strings.TrimSpace(out))

	// A day without a manifest breaks the chain.
	tomorrow := time.Now().UTC().AddDate(0, 0, 1).Format(time.DateOnly)
	code, out, _ = stack.PaddockServer(ctx, "audit", "verify", "--org", chain.String(), "--from", today, "--to", tomorrow)
	if code != 1 || !strings.Contains(out, "no manifest") {
		t.Fatalf("audit verify with a missing day: exit %d, want 1\n%s", code, out)
	}

	// Objects of acme, globex and the new organization exist, and each holds only its organization's events.
	client := rootS3(t)
	for _, org := range []uuid.UUID{orgOf(t, alice), orgOf(t, carol), chain} {
		keys := listKeys(t, client, "org/"+org.String()+"/"+time.Now().UTC().Format("2006/01/02")+"/")
		if len(keys) == 0 {
			t.Fatalf("no WORM objects of %s today", org)
		}
		for _, key := range keys {
			m := objectKeyPattern.FindStringSubmatch(key)
			if m == nil || m[1] != org.String() {
				t.Fatalf("object key %s does not carry organization %s", key, org)
			}
			for _, ev := range objectEvents(t, client, key) {
				if ev["organization_id"] != org.String() {
					t.Fatalf("object %s holds an event of %v", key, ev["organization_id"])
				}
			}
		}
	}
	// Every object in the bucket below org/ follows the key scheme.
	for _, key := range listKeys(t, client, "org/") {
		if !objectKeyPattern.MatchString(key) {
			t.Fatalf("object key %s violates org/<organization_id>/…", key)
		}
	}
}

func waitForEvents(t *testing.T, p *env.Portal, n int) {
	t.Helper()
	ctx := testContext(t, time.Minute)
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(time.Second) {
		events, err := p.AuditEvents(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(events) >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d audit events after 30 s, want %d", len(events), n)
		}
	}
}

func listKeys(t *testing.T, client *s3.Client, prefix string) []string {
	t.Helper()
	bucket := stack.AuditBucket()
	var keys []string
	p := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &prefix})
	for p.HasMorePages() {
		page, err := p.NextPage(testContext(t, time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range page.Contents {
			keys = append(keys, *o.Key)
		}
	}
	return keys
}
