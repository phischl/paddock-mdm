package db_test

import (
	"testing"

	"github.com/paddock-mdm/paddock/server/internal/testsupport/pgtest"
)

func sharedPaddock(t *testing.T) pgtest.Paddock { return pgtest.SharedPaddock(t) }

func sharedAudit(t *testing.T) pgtest.Audit { return pgtest.SharedAudit(t) }
