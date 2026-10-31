package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/auditevidence"
	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/config"
)

// auditEnv is a complete audit-writer configuration whose database is unreachable.
func auditEnv(t *testing.T, extra map[string]string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	secret := func(name, value string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	env := map[string]string{
		"PADDOCK_AUDIT_DB_WRITER_URL_FILE": secret("dsn", "postgres://w:p@127.0.0.1:1/paddock_audit?connect_timeout=1"),
		"PADDOCK_OPENBAO_ADDR":             "http://127.0.0.1:1",
		"PADDOCK_OPENBAO_ROLE_ID_FILE":     secret("role", "r"),
		"PADDOCK_OPENBAO_SECRET_ID_FILE":   secret("secret", "s"),
		"PADDOCK_AUDIT_S3_ENDPOINT":        "http://127.0.0.1:1",
		"PADDOCK_AUDIT_S3_ACCESS_KEY_FILE": secret("ak", "a"),
		"PADDOCK_AUDIT_S3_SECRET_KEY_FILE": secret("sk", "s"),
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

// TestIndexRetentionBelowWORMRetentionIsInvalid: the index is never purged ahead of the WORM retention (plan M10
// decision 23); the loader names the variable.
func TestIndexRetentionBelowWORMRetentionIsInvalid(t *testing.T) {
	for _, tc := range []struct{ worm, index string }{{"400", "399"}, {"500", "450"}} {
		env := auditEnv(t, map[string]string{
			"PADDOCK_AUDIT_RETENTION_DAYS": tc.worm, "PADDOCK_AUDIT_INDEX_RETENTION_DAYS": tc.index,
		})
		_, err := loadAuditDeps(context.Background(), config.NewLoaderFrom(env))
		if err == nil || !strings.Contains(err.Error(), "PADDOCK_AUDIT_INDEX_RETENTION_DAYS") {
			t.Errorf("retention %s, index retention %s: err = %v, want it to name PADDOCK_AUDIT_INDEX_RETENTION_DAYS",
				tc.worm, tc.index, err)
		}
	}
}

// TestIndexRetentionDefaultsToWORMRetention: without the variable, and with a longer index retention, the loader
// accepts the configuration (it fails later, on the unreachable database).
func TestIndexRetentionDefaultsToWORMRetention(t *testing.T) {
	for _, extra := range []map[string]string{
		{"PADDOCK_AUDIT_RETENTION_DAYS": "500"},
		{"PADDOCK_AUDIT_RETENTION_DAYS": "400", "PADDOCK_AUDIT_INDEX_RETENTION_DAYS": "730"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		deps, err := loadAuditDeps(ctx, config.NewLoaderFrom(auditEnv(t, extra)))
		cancel()
		if deps != nil {
			deps.pool.Close()
		}
		if err != nil && strings.Contains(err.Error(), "RETENTION_DAYS") {
			t.Errorf("%v: err = %v", extra, err)
		}
	}
}

// TestAuditRetentionForWorker (ADR 0032 amendment 2026-10-18, PDK-180): the worker reads the index retention with the
// audit writer's default and validation, so its retention round keeps the rows as long as the index.
func TestAuditRetentionForWorker(t *testing.T) {
	for _, tc := range []struct {
		env        map[string]string
		index      int
		invalidVar string
	}{
		{env: map[string]string{}, index: auditwriter.MinRetentionDays},
		{env: map[string]string{"PADDOCK_AUDIT_RETENTION_DAYS": "500"}, index: 500},
		{env: map[string]string{"PADDOCK_AUDIT_RETENTION_DAYS": "400", "PADDOCK_AUDIT_INDEX_RETENTION_DAYS": "730"}, index: 730},
		{env: map[string]string{"PADDOCK_AUDIT_RETENTION_DAYS": "500", "PADDOCK_AUDIT_INDEX_RETENTION_DAYS": "450"},
			invalidVar: "PADDOCK_AUDIT_INDEX_RETENTION_DAYS"},
		{env: map[string]string{"PADDOCK_AUDIT_RETENTION_DAYS": "399"}, invalidVar: "PADDOCK_AUDIT_RETENTION_DAYS"},
	} {
		l := config.NewLoaderFrom(tc.env)
		_, index := auditRetention(l)
		err := l.Err()
		if tc.invalidVar != "" {
			if err == nil || !strings.Contains(err.Error(), tc.invalidVar) {
				t.Errorf("%v: err = %v, want it to name %s", tc.env, err, tc.invalidVar)
			}
			continue
		}
		if err != nil || index != tc.index {
			t.Errorf("%v: index %d (%v), want %d", tc.env, index, err, tc.index)
		}
	}
}

// TestPrintPurgeReport: due partitions print DROP, KEEP or FAIL; partitions not yet due print nothing.
func TestPrintPurgeReport(t *testing.T) {
	month := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		parts []auditwriter.PurgedPartition
		want  string
	}{
		{"none", nil, "nothing to purge\n"},
		{"only recent", []auditwriter.PurgedPartition{
			{Name: "audit_event_2026_10", Reason: auditwriter.PurgeReasonNotDue},
		}, "nothing to purge\n"},
		{"mixed", []auditwriter.PurgedPartition{
			{Name: "audit_event_2025_01", Month: month, Due: true, Dropped: true, Events: 12345, Reason: auditwriter.PurgeReasonDropped},
			{Name: "audit_event_2025_02", Due: true, Events: 3, Reason: auditwriter.PurgeReasonLateEvents},
			{Name: "audit_event_2025_03", Due: true, Reason: auditwriter.PurgeReasonLockTimeout},
			{Name: "audit_event_2025_04", Due: true, Failed: true, Reason: "boom"},
			{Name: "audit_event_default", Reason: auditwriter.PurgeReasonUnknownName},
			{Name: "audit_event_2026_10", Reason: auditwriter.PurgeReasonNotDue},
		}, "DROP audit_event_2025_01: 12345 events\n" +
			"KEEP audit_event_2025_02: late events still within retention\n" +
			"KEEP audit_event_2025_03: lock_timeout\n" +
			"FAIL audit_event_2025_04: boom\n" +
			"KEEP audit_event_default: not a monthly partition\n"},
	} {
		var out bytes.Buffer
		printPurgeReport(&out, auditwriter.PurgeReport{Partitions: tc.parts})
		if out.String() != tc.want {
			t.Errorf("%s: got\n%s\nwant\n%s", tc.name, out.String(), tc.want)
		}
	}
}

func TestPrintAuditKeys(t *testing.T) {
	var out bytes.Buffer
	printAuditKeys(&out, map[int][]byte{2: []byte("second"), 1: []byte("first")})
	want := "audit-chain v1 " + auditevidence.Fingerprint([]byte("first")) + "\n" +
		"audit-chain v2 " + auditevidence.Fingerprint([]byte("second")) + "\n"
	if out.String() != want {
		t.Fatalf("printAuditKeys = %q, want %q", out.String(), want)
	}
	out.Reset()
	printAuditKeys(&out, nil)
	if out.Len() != 0 {
		t.Fatalf("no keys printed %q", out.String())
	}
}

func TestAuditKeysRejectsArguments(t *testing.T) {
	if err := runAudit(context.Background(), config.NewLoaderFrom(nil), config.Common{}, []string{"keys", "extra"}); !errors.Is(err, errUsage) {
		t.Fatalf("audit keys extra = %v, want usage error", err)
	}
}
