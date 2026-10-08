package objectstore_test

import (
	"context"
	"strings"
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

// TestListPage lists one page with delimiter and StartAfter, which the worker uses for the WAL archive age without a
// full listing (PDK-015).
func TestListPage(t *testing.T) {
	ctx := context.Background()
	r := s3test.StartPlain(t, "paddock-backup")
	store := objectstore.New(r.Endpoint, s3test.RootUser, s3test.RootPassword, r.Bucket)
	root := "pgbackrest/archive/paddock/16-1/"
	for _, key := range []string{root + "0000000100000000/a.gz", root + "0000000100000001/b.gz", root + "0000000100000001/c.gz",
		root + "0000000200000001/d.gz", root + "00000002.history"} {
		if err := store.Put(ctx, key, "application/octet-stream", "no-store", []byte(key)); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.ListPage(ctx, objectstore.ListQuery{Prefix: root, Delimiter: "/", StartAfter: root + "0000000100000001"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(page.Prefixes, ","); got != root+"0000000100000001/,"+root+"0000000200000001/" || page.Next != "" {
		t.Fatalf("prefixes %q next %q", got, page.Next)
	}
	if len(page.Objects) != 1 || page.Objects[0].Key != root+"00000002.history" || page.Objects[0].LastModified.IsZero() {
		t.Fatalf("objects %+v", page.Objects)
	}
	page, err = store.ListPage(ctx, objectstore.ListQuery{Prefix: root + "0000000100000001/"})
	if err != nil || len(page.Objects) != 2 || len(page.Prefixes) != 0 {
		t.Fatalf("segments %+v, %v", page, err)
	}
}
