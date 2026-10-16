package objectstore_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/s3test"
)

// TestSizeAndDelete: Size reports a stored object's length and a missing key as not found; Delete removes the
// current version so that the previous one is current again, and a missing key is not an error (plan M8s decision 30).
func TestSizeAndDelete(t *testing.T) {
	ctx := context.Background()
	r := s3test.StartVersioned(t, "paddock-escrow")
	store := objectstore.New(r.Endpoint, s3test.RootUser, s3test.RootPassword, r.Bucket)
	key := "org/o/devices/d/luks-header/1.bin"
	if _, found, err := store.Size(ctx, key); err != nil || found {
		t.Fatalf("missing key: found %v, %v", found, err)
	}
	for _, body := range []string{"first", "second version"} {
		if err := store.Put(ctx, key, "application/octet-stream", "no-store", []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if size, found, err := store.Size(ctx, key); err != nil || !found || size != int64(len("second version")) {
		t.Fatalf("size %d found %v, %v", size, found, err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if size, found, err := store.Size(ctx, key); err != nil || !found || size != int64(len("first")) {
		t.Fatalf("after delete: size %d found %v, %v", size, found, err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.Size(ctx, key); err != nil || found {
		t.Fatalf("after the second delete: found %v, %v", found, err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("missing key: %v", err)
	}
}

// TestPresignedPutBindsTheSize: the object store refuses a presigned PUT whose body differs from the signed size and
// accepts exactly the signed size (plan M8s decision 29).
func TestPresignedPutBindsTheSize(t *testing.T) {
	ctx := context.Background()
	r := s3test.StartVersioned(t, "paddock-escrow")
	store := objectstore.New(r.Endpoint, s3test.RootUser, s3test.RootPassword, r.Bucket)
	p := objectstore.NewPresigner(r.Endpoint, s3test.RootUser, s3test.RootPassword, r.Bucket)
	put := func(key string, size int64, body []byte) int {
		t.Helper()
		u, err := p.PresignPut(ctx, key, size, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}
	if code := put("larger.bin", 10, bytes.Repeat([]byte{1}, 11)); code < 400 {
		t.Errorf("11 bytes for a signed size of 10: HTTP %d", code)
	}
	if _, found, err := store.Size(ctx, "larger.bin"); err != nil || found {
		t.Errorf("larger body stored: found %v, %v", found, err)
	}
	if code := put("exact.bin", 10, bytes.Repeat([]byte{1}, 10)); code != http.StatusOK {
		t.Errorf("10 bytes for a signed size of 10: HTTP %d", code)
	}
	if size, found, err := store.Size(ctx, "exact.bin"); err != nil || !found || size != 10 {
		t.Errorf("exact body: size %d found %v, %v", size, found, err)
	}
}
