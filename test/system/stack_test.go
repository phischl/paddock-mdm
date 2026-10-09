package system

import (
	"slices"
	"testing"
)

// TestWithBackup (PDK-018): a restart keeps the backup overlay of a stack that runs with it, unless BACKUP is set
// explicitly.
func TestWithBackup(t *testing.T) {
	backup := []string{"/r/deploy/compose/compose.yaml", "/r/deploy/compose/compose.backup.yaml", "/r/deploy/compose/compose.backup.dev.yaml"}
	plain := []string{"/r/deploy/compose/compose.yaml", "/r/deploy/compose/compose.dev.yaml"}
	env := func(vars map[string]string) func(string) string { return func(k string) string { return vars[k] } }
	for _, tt := range []struct {
		name  string
		args  []string
		env   map[string]string
		files []string
		want  []string
	}{
		{"backup stack", []string{"up"}, nil, backup, []string{"up", "BACKUP=1"}},
		{"plain stack", []string{"down"}, nil, plain, []string{"down"}},
		{"not running", []string{"up"}, nil, nil, []string{"up"}},
		{"BACKUP in the environment", []string{"up"}, map[string]string{"BACKUP": "1"}, backup, []string{"up"}},
		{"BACKUP from make system-test", []string{"down"}, map[string]string{"MAKEFLAGS": "--no-print-directory -- BACKUP=1 VM=all"}, backup, []string{"down"}},
		{"BACKUP in the arguments", []string{"up", "BACKUP="}, nil, backup, []string{"up", "BACKUP="}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := withBackup(tt.args, env(tt.env), tt.files); !slices.Equal(got, tt.want) {
				t.Fatalf("withBackup(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
