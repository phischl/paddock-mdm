package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/backuprole"
	"github.com/phischl/paddock-mdm/server/internal/config"
)

// TestLoadBackupRole: the defaults of plan M15 decision 15, and the shortened full interval only on the development
// stack.
func TestLoadBackupRole(t *testing.T) {
	l := config.NewLoaderFrom(map[string]string{})
	cfg := loadBackupRole(l, config.Common{Env: "production"})
	if err := l.Err(); err != nil {
		t.Fatal(err)
	}
	if cfg.RepoDir != "/backup-repo" || cfg.RuntimeDir != "/run/paddock-backup" || cfg.TargetsDir != "/backup-targets" ||
		cfg.FleetDumpsDir != "/fleet-dumps" || cfg.RoundInterval != time.Minute || cfg.FullInterval != 0 {
		t.Errorf("defaults %+v", cfg)
	}
	l = config.NewLoaderFrom(map[string]string{"PADDOCK_BACKUP_FULL_INTERVAL_S": "120"})
	loadBackupRole(l, config.Common{Env: "production"})
	if err := l.Err(); err == nil || !strings.Contains(err.Error(), "PADDOCK_BACKUP_FULL_INTERVAL_S") {
		t.Errorf("production accepted the development interval: %v", err)
	}
	l = config.NewLoaderFrom(map[string]string{"PADDOCK_BACKUP_FULL_INTERVAL_S": "120"})
	if cfg := loadBackupRole(l, config.Common{Env: "development"}); l.Err() != nil || cfg.FullInterval != 2*time.Minute {
		t.Errorf("development: %v %v", cfg.FullInterval, l.Err())
	}
}

// TestPrintBackupStatus: the status table names the active key, the newest run per kind and each target's kinds.
func TestPrintBackupStatus(t *testing.T) {
	at := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	ok, class := "succeeded", "dial"
	target := uuid.New()
	var out bytes.Buffer
	err := printBackupStatus(&out,
		[]pgstore.ListBackupKeyStatesRow{{KeyID: "bk-20261104-7f3a9c1e", Fingerprint: "0123456789abcdef", State: "confirmed"}},
		[]pgstore.BackupRun{{Kind: "openbao", State: "finished", Outcome: &ok, FinishedAt: &at}},
		[]pgstore.AllBackupTargetsRow{{ID: target, Name: "nas", Type: "smb", Enabled: true, HostState: "unreachable"}},
		[]pgstore.BackupTargetStatus{{TargetID: target, Kind: "openbao", LastSuccessAt: &at, LastError: &class}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bk-20261104-7f3a9c1e (fingerprint 0123456789abcdef)", "openbao  finished  succeeded",
		"nas", "unreachable", "2026-11-04T10:00:00Z", "dial"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	if err := printBackupStatus(&out, nil, nil, nil, nil); err != nil || !strings.Contains(out.String(), "no backup runs") {
		t.Errorf("without a key: %s %v", out.String(), err)
	}
}

// TestPrintBackupStatusNamesUnknownPathTarget: a target whose mirror found a repository path no backup key names gets a
// note under the table that the path is kept, deletions go on, and the log names the path (decisions-alpha10 A10-25);
// a target without that error gets none.
func TestPrintBackupStatusNamesUnknownPathTarget(t *testing.T) {
	unknown, dial := backuprole.ClassUnknownPath, "dial"
	nas, s3 := uuid.New(), uuid.New()
	var out bytes.Buffer
	err := printBackupStatus(&out, nil, nil,
		[]pgstore.AllBackupTargetsRow{{ID: nas, Name: "nas", Type: "smb", Enabled: true, HostState: "mounted"},
			{ID: s3, Name: "offsite", Type: "s3", Enabled: true, HostState: "n/a"}},
		[]pgstore.BackupTargetStatus{{TargetID: s3, Kind: "postgres", LastError: &unknown},
			{TargetID: s3, Kind: "openbao", LastError: &unknown}, {TargetID: nas, Kind: "postgres", LastError: &dial}})
	if err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if n := strings.Count(got, "offsite holds a pgBackRest repository path no backup key names"); n != 1 {
		t.Errorf("%d notes for offsite, want 1:\n%s", n, got)
	}
	if strings.Contains(got, "nas holds") {
		t.Errorf("a note for a target without an unknown path:\n%s", got)
	}
	for _, want := range []string{"goes on deleting", "paddock-backup log names the path"} {
		if !strings.Contains(got, want) {
			t.Errorf("the note lacks %q:\n%s", want, got)
		}
	}
}
