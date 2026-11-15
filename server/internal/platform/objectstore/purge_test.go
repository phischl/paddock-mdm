package objectstore_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/s3test"
)

// fakeVersionedStore answers ListObjectVersions with versions, two per page, and refuses DeleteObject of every key in
// refuse with status and the S3 error code and message; every other delete succeeds.
type fakeVersionedStore struct {
	mu       sync.Mutex
	versions []string
	refuse   map[string]bool
	status   int
	code     string
	message  string
	deleted  []string
	lists    int
}

func (f *fakeVersionedStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.TrimPrefix(r.URL.Path, "/b/")
	switch {
	case r.Method == http.MethodGet && r.URL.Query().Has("versions"):
		f.lists++
		start := 0
		if m := r.URL.Query().Get("key-marker"); m != "" {
			start = slices.Index(f.versions, m) + 1
		}
		end := min(start+2, len(f.versions))
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListVersionsResult><Name>b</Name>`)
		for _, k := range f.versions[start:end] {
			fmt.Fprintf(&b, `<Version><Key>%s</Key><VersionId>v-%s</VersionId><IsLatest>true</IsLatest></Version>`, k, k)
		}
		if end < len(f.versions) {
			fmt.Fprintf(&b, `<IsTruncated>true</IsTruncated><NextKeyMarker>%s</NextKeyMarker><NextVersionIdMarker>v-%s</NextVersionIdMarker>`,
				f.versions[end-1], f.versions[end-1])
		} else {
			b.WriteString(`<IsTruncated>false</IsTruncated>`)
		}
		b.WriteString(`</ListVersionsResult>`)
		_, _ = w.Write([]byte(b.String()))
	case r.Method == http.MethodDelete && f.refuse[key]:
		w.WriteHeader(f.status)
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, f.code, f.message)
	case r.Method == http.MethodDelete:
		f.deleted = append(f.deleted, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

// TestPurgeVersionsRecordsObjectLockRefusals: a version Object Lock keeps never makes the purge report success. It is
// recorded as retained, the error wraps ErrRetained, the purge still deletes every other version, and it ends instead
// of listing the kept version again (plan M17 amendment k; main's binding point 1 for PDK-1054).
func TestPurgeVersionsRecordsObjectLockRefusals(t *testing.T) {
	refusals := []struct {
		name, code, message string
		status              int
	}{
		{"AWS retention", "AccessDenied", "Access Denied because object protected by object lock.", http.StatusForbidden},
		{"lock code", "ObjectLocked", "Object is WORM protected and cannot be overwritten", http.StatusBadRequest},
		{"legal hold", "InvalidRequest", "Object is under legal hold", http.StatusBadRequest},
	}
	for _, rf := range refusals {
		t.Run(rf.name, func(t *testing.T) {
			f := &fakeVersionedStore{
				versions: []string{"org/o/devices/d/luks-header/1", "org/o/devices/d/luks-header/2", "org/o/devices/d/luks-header/3",
					"org/o/devices/d/luks-header/4", "org/o/devices/d/luks-header/5"},
				refuse: map[string]bool{"org/o/devices/d/luks-header/2": true, "org/o/devices/d/luks-header/4": true},
				status: rf.status, code: rf.code, message: rf.message,
			}
			srv := httptest.NewServer(f)
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			p, err := objectstore.New(srv.URL, "k", "s", "b").PurgeVersions(ctx, "org/o/")
			if !errors.Is(err, objectstore.ErrRetained) {
				t.Fatalf("err = %v, want ErrRetained", err)
			}
			if p.Deleted != 3 || !slices.Equal(p.Retained, []string{"org/o/devices/d/luks-header/2", "org/o/devices/d/luks-header/4"}) {
				t.Fatalf("purge = %+v, want 3 deleted and versions 2 and 4 retained", p)
			}
			if f.lists != 3 {
				t.Fatalf("listed %d pages, want 3", f.lists)
			}
		})
	}
}

// TestPurgeVersionsStopsOnOtherErrors: an AccessDenied of a missing grant is no Object Lock refusal; the purge stops
// with it and does not report it as retained.
func TestPurgeVersionsStopsOnOtherErrors(t *testing.T) {
	f := &fakeVersionedStore{
		versions: []string{"org/o/a", "org/o/b"},
		refuse:   map[string]bool{"org/o/a": true},
		status:   http.StatusForbidden, code: "AccessDenied", message: "Access Denied.",
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	p, err := objectstore.New(srv.URL, "k", "s", "b").PurgeVersions(context.Background(), "org/o/")
	if err == nil || errors.Is(err, objectstore.ErrRetained) || len(p.Retained) != 0 || len(f.deleted) != 0 {
		t.Fatalf("purge = %+v, err = %v, deleted %v: want a plain error before any delete", p, err, f.deleted)
	}
}

// TestPurgeVersionsRustFS: below the prefix every version and delete marker goes, outside it everything stays; a
// second run deletes nothing.
func TestPurgeVersionsRustFS(t *testing.T) {
	ctx := context.Background()
	r := s3test.StartVersioned(t, "paddock-escrow")
	store := objectstore.New(r.Endpoint, s3test.RootUser, s3test.RootPassword, r.Bucket)
	prefix := "org/o/"
	for _, key := range []string{prefix + "devices/d/luks-header/1", prefix + "devices/d/luks-header/1", prefix + "devices/d/diagnostics/z", "org/other/devices/d/luks-header/1"} {
		if err := store.Put(ctx, key, "application/octet-stream", "no-store", []byte(key)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Delete(ctx, prefix+"devices/d/diagnostics/z"); err != nil {
		t.Fatal(err)
	}
	p, err := store.PurgeVersions(ctx, prefix)
	if err != nil || p.Deleted != 4 || len(p.Retained) != 0 {
		t.Fatalf("purge = %+v, %v; want 4 deleted (two header versions, a diagnostics version and its delete marker)", p, err)
	}
	versions, err := r.Root.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &r.Bucket})
	if err != nil {
		t.Fatal(err)
	}
	if len(versions.Versions) != 1 || *versions.Versions[0].Key != "org/other/devices/d/luks-header/1" || len(versions.DeleteMarkers) != 0 {
		t.Fatalf("left %d versions, %d delete markers", len(versions.Versions), len(versions.DeleteMarkers))
	}
	if p, err := store.PurgeVersions(ctx, prefix); err != nil || p.Deleted != 0 {
		t.Fatalf("second run: %+v, %v", p, err)
	}
}

// TestPurgeVersionsRustFSRetention: on a bucket with Object Lock, RustFS refuses to delete a version under COMPLIANCE
// retention, and PurgeVersions reports exactly that version as retained.
func TestPurgeVersionsRustFSRetention(t *testing.T) {
	ctx := context.Background()
	r := s3test.Start(t, "paddock-locked")
	store := objectstore.New(r.Endpoint, s3test.RootUser, s3test.RootPassword, r.Bucket)
	key := "org/o/devices/d/luks-header/1"
	if err := store.PutLocked(ctx, key, "application/octet-stream", []byte("h"), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	p, err := store.PurgeVersions(ctx, "org/o/")
	if !errors.Is(err, objectstore.ErrRetained) || p.Deleted != 0 || !slices.Equal(p.Retained, []string{key}) {
		t.Fatalf("purge = %+v, err = %v; want the locked version retained", p, err)
	}
}

// TestPurgeObjectsRustFS: an unversioned bucket's objects below the prefix go, the others stay.
func TestPurgeObjectsRustFS(t *testing.T) {
	ctx := context.Background()
	r := s3test.StartPlain(t, "paddock-bundles")
	store := objectstore.New(r.Endpoint, s3test.RootUser, s3test.RootPassword, r.Bucket)
	for _, key := range []string{"org/o/a", "org/o/b/c", "org/other/a", "apt/o/x"} {
		if err := store.Put(ctx, key, "application/octet-stream", "no-store", []byte(key)); err != nil {
			t.Fatal(err)
		}
	}
	p, err := store.PurgeObjects(ctx, "org/o/")
	if err != nil || p.Deleted != 2 || len(p.Retained) != 0 {
		t.Fatalf("purge = %+v, %v", p, err)
	}
	left, err := store.List(ctx, "")
	if err != nil || !slices.Equal(left, []string{"apt/o/x", "org/other/a"}) {
		t.Fatalf("left %v, %v", left, err)
	}
}
