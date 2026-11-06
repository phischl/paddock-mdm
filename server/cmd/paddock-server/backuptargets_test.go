package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/backuprole"
	"github.com/phischl/paddock-mdm/server/internal/config"
)

func TestBackupTargetsUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"render", "extra"}, {"render", "--bogus"}, {"revisions", "x"}, {"purge"},
		{"purge", "not-a-uuid"}, {"unknown"}} {
		if err := runBackupTargets(context.Background(), config.NewLoader(), args, &bytes.Buffer{}); !errors.Is(err, errUsage) {
			t.Errorf("%q: %v, want usage", args, err)
		}
	}
}

func TestBackupMarkMount(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PADDOCK_BACKUP_TARGETS_DIR", dir)
	a, missing := uuid.New(), uuid.New()
	if err := os.Mkdir(filepath.Join(dir, a.String()), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {a.String()}, {a.String(), "0"}, {"x", "1"}, {a.String(), "two"}} {
		if err := backupMarkMount(config.NewLoader(), args, &bytes.Buffer{}); !errors.Is(err, errUsage) {
			t.Errorf("%q: %v, want usage", args, err)
		}
	}
	var out bytes.Buffer
	err := backupMarkMount(config.NewLoader(), []string{a.String(), "3", missing.String(), "1"}, &out)
	if err == nil || !strings.Contains(err.Error(), missing.String()) {
		t.Errorf("a missing volume must fail naming it: %v", err)
	}
	if out.String() != "marked "+a.String()+" 3\n" {
		t.Errorf("output %q", out.String())
	}
	if got := backuprole.HostState(dir, backuprole.TargetRecord{ID: a, HostRevision: 3}); got != backuprole.HostMounted {
		t.Errorf("host state %s", got)
	}
}

// TestBackupResolveLocalRefuses: a device outside the configured root (the root changed after apply) and a device
// below it that does not resolve are refused; resolution itself is covered in backuprole.
func TestBackupResolveLocalRefuses(t *testing.T) {
	for _, args := range [][]string{nil, {"--root", "/srv/paddock-backup"}} {
		if err := backupResolveLocal(args, &bytes.Buffer{}); !errors.Is(err, errUsage) {
			t.Errorf("%q: %v, want usage", args, err)
		}
	}
	root := filepath.Join(t.TempDir(), "root")
	for name, args := range map[string][]string{
		"outside the root":    {"--root", root, "/srv/paddock-backup/x"},
		"prefix only":         {"--root", root, root + "x/y"},
		"missing below root":  {"--root", root, root + "/x"},
		"default root absent": {"/srv/paddock-backup-test-absent/x"},
	} {
		var out bytes.Buffer
		if err := backupResolveLocal(args, &out); !errors.Is(err, backuprole.ErrLocalPath) || out.Len() != 0 {
			t.Errorf("%s: %v %q", name, err, out.String())
		}
	}
}
