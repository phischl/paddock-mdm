package objectstore_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/s3test"
)

// TestDefaultRetention reads the Object Lock configuration `make prod-check ONLINE=1` checks (plan M6a decision 2).
func TestDefaultRetention(t *testing.T) {
	ctx := context.Background()
	locked := s3test.Start(t, "paddock-audit")
	enabled, mode, days, err := objectstore.New(locked.Endpoint, s3test.RootUser, s3test.RootPassword, locked.Bucket).DefaultRetention(ctx)
	if err != nil || !enabled || mode != types.ObjectLockRetentionModeCompliance || days != 400 {
		t.Fatalf("locked bucket: enabled=%v mode=%q days=%d err=%v", enabled, mode, days, err)
	}

	plain := s3test.StartPlain(t, "paddock-plain")
	enabled, _, _, err = objectstore.New(plain.Endpoint, s3test.RootUser, s3test.RootPassword, plain.Bucket).DefaultRetention(ctx)
	if err == nil && enabled {
		t.Fatal("a bucket without Object Lock must not report it enabled")
	}
}
