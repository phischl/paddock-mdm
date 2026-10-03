package pgtest

import (
	"sync"
	"testing"
)

var (
	paddockOnce sync.Once
	paddockEnv  Paddock
	auditOnce   sync.Once
	auditEnv    Audit
)

// SharedPaddock starts one migrated paddock database per test binary; Ryuk removes the container at exit.
func SharedPaddock(t *testing.T) Paddock {
	t.Helper()
	paddockOnce.Do(func() { paddockEnv = StartPaddock(keepAlive{t}) })
	if paddockEnv.Super == "" {
		t.Fatal("pgtest: shared paddock database not available")
	}
	return paddockEnv
}

// SharedAudit starts one migrated paddock_audit database per test binary.
func SharedAudit(t *testing.T) Audit {
	t.Helper()
	auditOnce.Do(func() { auditEnv = StartAudit(keepAlive{t}) })
	if auditEnv.Super == "" {
		t.Fatal("pgtest: shared audit database not available")
	}
	return auditEnv
}

// keepAlive suppresses the per-test cleanup so the container outlives the test that started it.
type keepAlive struct{ *testing.T }

func (keepAlive) Cleanup(func()) {}
