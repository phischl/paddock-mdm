package db_test

import (
	"sync"
	"testing"

	"github.com/paddock-mdm/paddock/server/internal/testsupport/pgtest"
)

var (
	paddockOnce sync.Once
	paddockEnv  pgtest.Paddock
	auditOnce   sync.Once
	auditEnv    pgtest.Audit
)

// sharedPaddock starts one migrated paddock database per test binary. Containers are reaped by testcontainers.
func sharedPaddock(t *testing.T) pgtest.Paddock {
	t.Helper()
	paddockOnce.Do(func() { paddockEnv = pgtest.StartPaddock(&noCleanup{t}) })
	if paddockEnv.Super == "" {
		t.Fatal("paddock test database not available")
	}
	return paddockEnv
}

func sharedAudit(t *testing.T) pgtest.Audit {
	t.Helper()
	auditOnce.Do(func() { auditEnv = pgtest.StartAudit(&noCleanup{t}) })
	if auditEnv.Super == "" {
		t.Fatal("audit test database not available")
	}
	return auditEnv
}

// noCleanup keeps the container alive across tests of this package (Ryuk removes it when the binary exits).
type noCleanup struct{ *testing.T }

func (n *noCleanup) Cleanup(func()) {}
