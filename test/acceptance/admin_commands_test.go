package acceptance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// runAdmin runs paddock-server admin in a one-off worker container, as the restore runbook does.
func runAdmin(t *testing.T, args ...string) string {
	t.Helper()
	out, err := stack.Compose(testContext(t, 5*time.Minute), nil, append([]string{"run", "--rm", "--no-deps", "paddock-worker", "admin"}, args...)...)
	if err != nil {
		t.Fatalf("paddock-server admin %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// valkeyCLI runs valkey-cli in the stack's Valkey container.
func valkeyCLI(t *testing.T, args string) string {
	t.Helper()
	out, err := stack.Compose(testContext(t, time.Minute), nil, "exec", "-T", "valkey", "sh", "-c",
		`REDISCLI_AUTH="$(cat /run/secrets/valkey_password)" valkey-cli --no-auth-warning `+args)
	if err != nil {
		t.Fatalf("valkey-cli %s: %v", args, err)
	}
	return strings.TrimSpace(out)
}

// expectIndexEventSince waits for exactly one event of code in org that occurred at or after since.
func expectIndexEventSince(t *testing.T, idx *env.AuditIndex, org uuid.UUID, code string, since time.Time) env.IndexEvent {
	t.Helper()
	return expectOneIndexEvent(t, idx, org, "code = '"+code+"' AND occurred_at >= $1", since, code, "success", 90*time.Second)
}

// TestAdminCommands is gate T4 of plan M6c: the restore commands of decision 21 bump every device's bundle sequence,
// request a forced recompile of every organization that publishes a new bundle version without a configuration
// change, and rebuild the gateway's cache; each records its audit event.
func TestAdminCommands(t *testing.T) {
	alice := login(t, env.Alice)
	acme := orgOf(t, alice)
	idx := auditIndex(t)
	dev := activeDevice(t, alice, "", "t4-"+uniqueSuffix())

	dsn, err := stack.PaddockOwnerDSN()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(testContext(t, time.Minute), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	seq := func() int64 {
		t.Helper()
		var v int64
		if err := conn.QueryRow(testContext(t, time.Minute), "SELECT bundle_seq FROM device WHERE id = $1", dev.DeviceID).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	// The device's first bundle is published before the bump (the compiler runs asynchronously).
	for deadline := time.Now().Add(90 * time.Second); seq() == 0; time.Sleep(time.Second) {
		if time.Now().After(deadline) {
			t.Fatal("the device got no bundle")
		}
	}

	since := time.Now().Add(-time.Second)
	before := seq()
	if out := runAdmin(t, "bump-bundle-seq", "--by", "5"); !strings.Contains(out, "bumped bundle_seq of ") || !strings.Contains(out, " by 5") {
		t.Fatalf("bump-bundle-seq printed %q", out)
	}
	bumped := seq()
	if bumped < before+5 {
		t.Fatalf("bundle_seq %d → %d, want at least +5", before, bumped)
	}
	if ev := expectIndexEventSince(t, idx, platformOrg, "platform.bundle_seq_bumped", since); ev.Params["by"] != float64(5) {
		t.Fatalf("platform.bundle_seq_bumped params %v", ev.Params)
	}

	since = time.Now().Add(-time.Second)
	if out := runAdmin(t, "recompile", "--all"); !strings.Contains(out, "recompile requested for ") {
		t.Fatalf("recompile printed %q", out)
	}
	expectIndexEventSince(t, idx, acme, "organization.recompile_requested", since)
	for deadline := time.Now().Add(90 * time.Second); seq() <= bumped; time.Sleep(time.Second) {
		if time.Now().After(deadline) {
			t.Fatalf("no new bundle version above %d within 90 s after recompile --all", bumped)
		}
	}

	key := "dk:" + dev.KeyID
	if got := valkeyCLI(t, "DEL "+key); got != "1" {
		t.Fatalf("DEL %s = %q", key, got)
	}
	since = time.Now().Add(-time.Second)
	if out := runAdmin(t, "rebuild-cache"); !strings.Contains(out, "cache rebuilt for ") {
		t.Fatalf("rebuild-cache printed %q", out)
	}
	if got := valkeyCLI(t, "EXISTS "+key); got != "1" {
		t.Fatalf("%s missing right after rebuild-cache (EXISTS = %q)", key, got)
	}
	expectIndexEventSince(t, idx, platformOrg, "platform.cache_rebuilt", since)
}
