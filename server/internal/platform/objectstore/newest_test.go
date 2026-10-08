package objectstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/s3test"
)

// TestNewest finds the newest object below a prefix, which the worker exports as the age of a backup (plan M6a
// decision 9).
func TestNewest(t *testing.T) {
	ctx := context.Background()
	r := s3test.StartPlain(t, "paddock-backup")
	store := objectstore.New(r.Endpoint, s3test.RootUser, s3test.RootPassword, r.Bucket)
	if _, found, err := store.Newest(ctx, "openbao/"); err != nil || found {
		t.Fatalf("empty prefix: found=%v err=%v", found, err)
	}
	before := time.Now().Add(-time.Minute)
	for _, key := range []string{"openbao/1.snap.enc", "openbao/2.snap.enc", "fleet/1.sql.gz.enc"} {
		if err := store.Put(ctx, key, "application/octet-stream", "no-store", []byte(key)); err != nil {
			t.Fatal(err)
		}
	}
	newest, found, err := store.Newest(ctx, "openbao/")
	if err != nil || !found || newest.Before(before) || newest.After(time.Now().Add(time.Minute)) {
		t.Fatalf("newest=%v found=%v err=%v", newest, found, err)
	}
	if _, found, _ := store.Newest(ctx, "pgbackrest/backup/paddock/backup.info"); found {
		t.Fatal("missing key must not be found")
	}
}
