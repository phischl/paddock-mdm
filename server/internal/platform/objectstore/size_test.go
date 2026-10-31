package objectstore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/s3test"
)

// TestSize: Size reports the length of the current version and a missing key as not found (plan M8s decision 30).
func TestSize(t *testing.T) {
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

// TestSHA256 hashes the current version of an object while it streams and reports a missing key as not found
// (PDK-496).
func TestSHA256(t *testing.T) {
	ctx := context.Background()
	r := s3test.StartVersioned(t, "paddock-agent-artifacts")
	store := objectstore.New(r.Endpoint, s3test.RootUser, s3test.RootPassword, r.Bucket)
	key := "releases/1.0.0/amd64/paddockd"
	if _, found, err := store.SHA256(ctx, key); err != nil || found {
		t.Fatalf("missing key: found %v, %v", found, err)
	}
	if err := store.Put(ctx, key, "application/octet-stream", "no-store", []byte("paddockd")); err != nil {
		t.Fatal(err)
	}
	sum, found, err := store.SHA256(ctx, key)
	if err != nil || !found || sum != sha256Hex("paddockd") {
		t.Fatalf("sum %q found %v, %v", sum, found, err)
	}
}

// TestPutRejected marks a write the store answered with a client error on its only attempt, and only that, as
// rejected (PDK-496): not a 4xx after a retried 5xx, whose first write may still complete.
func TestPutRejected(t *testing.T) {
	ctx := context.Background()
	r := s3test.StartVersioned(t, "paddock-agent-artifacts")
	missing := objectstore.New(r.Endpoint, s3test.RootUser, s3test.RootPassword, "no-such-bucket")
	if err := missing.Put(ctx, "k", "application/octet-stream", "no-store", []byte("x")); !errors.Is(err, objectstore.ErrRejected) {
		t.Fatalf("write into a missing bucket: %v, want rejected", err)
	}
	var calls atomic.Int32
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>denied</Message></Error>`)
	}))
	t.Cleanup(flaky.Close)
	retried := objectstore.New(flaky.URL, "k", "s", "paddock-agent-artifacts")
	if err := retried.Put(ctx, "k", "application/octet-stream", "no-store", []byte("x")); err == nil || errors.Is(err, objectstore.ErrRejected) || calls.Load() < 2 {
		t.Fatalf("4xx after a retried 5xx (%d attempts): %v, want an error that is not rejected", calls.Load(), err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	store := objectstore.New(r.Endpoint, s3test.RootUser, s3test.RootPassword, r.Bucket)
	if err := store.Put(cancelled, "k", "application/octet-stream", "no-store", []byte("x")); err == nil || errors.Is(err, objectstore.ErrRejected) {
		t.Fatalf("interrupted write: %v, want an error that is not rejected", err)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
