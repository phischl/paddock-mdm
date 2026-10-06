package objectstore_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/s3test"
)

// TestDeleteAllVersions: every version of every object below the prefix is gone, objects outside it stay (plan M4c
// decision 9).
func TestDeleteAllVersions(t *testing.T) {
	ctx := context.Background()
	r := s3test.StartVersioned(t, "paddock-escrow")
	store := objectstore.New(r.Endpoint, s3test.RootUser, s3test.RootPassword, r.Bucket)
	prefix := "org/o/devices/d/luks-header/"
	for _, key := range []string{prefix + "1.bin", prefix + "1.bin", prefix + "2.bin", "org/o/devices/other/luks-header/1.bin"} {
		if err := store.Put(ctx, key, "application/octet-stream", "no-store", []byte(key)); err != nil {
			t.Fatal(err)
		}
	}
	n, err := store.DeleteAllVersions(ctx, prefix)
	if err != nil || n != 3 {
		t.Fatalf("deleted %d, %v", n, err)
	}
	versions, err := r.Root.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &r.Bucket})
	if err != nil {
		t.Fatal(err)
	}
	if len(versions.Versions) != 1 || *versions.Versions[0].Key != "org/o/devices/other/luks-header/1.bin" || len(versions.DeleteMarkers) != 0 {
		t.Fatalf("left %d versions, %d delete markers", len(versions.Versions), len(versions.DeleteMarkers))
	}
	if n, err := store.DeleteAllVersions(ctx, prefix); err != nil || n != 0 {
		t.Fatalf("second run: %d, %v", n, err)
	}
}
