package objectstore_test

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/s3test"
)

// fakeVersionedStore answers ListObjectVersions with the versions not deleted yet, two per page, and DeleteObjects with
// a per-key error with code and message for every key in refuse; every other key is deleted. status, when set, refuses
// the whole DeleteObjects request with that status and code. A single DeleteObject of a refused key gets 403 with code
// and singleMessage.
type fakeVersionedStore struct {
	mu            sync.Mutex
	versions      []string // sorted
	refuse        map[string]bool
	status        int
	code          string
	message       string
	singleMessage string
	singleDelay   time.Duration
	pageSize      int // 0: 2
	gone          map[string]bool
	deleted       []string
	lists         int
	batches       int
	singles       int
}

type deleteRequest struct {
	Quiet   bool `xml:"Quiet"`
	Objects []struct {
		Key       string `xml:"Key"`
		VersionID string `xml:"VersionId"`
	} `xml:"Object"`
}

func (f *fakeVersionedStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Query().Has("versions"):
		f.lists++
		marker := r.URL.Query().Get("key-marker")
		var page []string
		truncated := false
		for _, k := range f.versions {
			if f.gone[k] || (marker != "" && k <= marker) {
				continue
			}
			if len(page) == max(f.pageSize, 2) {
				truncated = true
				break
			}
			page = append(page, k)
		}
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListVersionsResult><Name>b</Name>`)
		for _, k := range page {
			fmt.Fprintf(&b, `<Version><Key>%s</Key><VersionId>v-%s</VersionId><IsLatest>true</IsLatest></Version>`, k, k)
		}
		if truncated {
			last := page[len(page)-1]
			fmt.Fprintf(&b, `<IsTruncated>true</IsTruncated><NextKeyMarker>%s</NextKeyMarker><NextVersionIdMarker>v-%s</NextVersionIdMarker>`, last, last)
		} else {
			b.WriteString(`<IsTruncated>false</IsTruncated>`)
		}
		b.WriteString(`</ListVersionsResult>`)
		_, _ = w.Write([]byte(b.String()))
	case r.Method == http.MethodPost && r.URL.Query().Has("delete"):
		f.batches++
		if f.status != 0 {
			w.WriteHeader(f.status)
			fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, f.code, f.message)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req deleteRequest
		if err := xml.Unmarshal(body, &req); err != nil || !req.Quiet {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><DeleteResult>`)
		for _, o := range req.Objects {
			if o.VersionID != "v-"+o.Key {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if f.refuse[o.Key] {
				fmt.Fprintf(&b, `<Error><Key>%s</Key><VersionId>%s</VersionId><Code>%s</Code><Message>%s</Message></Error>`,
					o.Key, o.VersionID, f.code, f.message)
				continue
			}
			f.gone[o.Key] = true
			f.deleted = append(f.deleted, o.Key)
		}
		b.WriteString(`</DeleteResult>`)
		_, _ = w.Write([]byte(b.String()))
	case r.Method == http.MethodDelete:
		key := strings.TrimPrefix(r.URL.Path, "/b/")
		f.singles++
		time.Sleep(f.singleDelay)
		if f.refuse[key] {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, f.code, f.singleMessage)
			return
		}
		f.gone[key] = true
		f.deleted = append(f.deleted, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func newFakeVersioned(versions ...string) *fakeVersionedStore {
	return &fakeVersionedStore{versions: versions, refuse: map[string]bool{}, gone: map[string]bool{}}
}

// TestPurgeVersionsRecordsObjectLockRefusals (AC2 of PDK-1087): a version Object Lock keeps never makes the purge report
// success. Its per-key error of DeleteObjects is recorded as retained, the error wraps ErrRetained, the purge still
// deletes every other version, and it ends instead of listing the kept version again (plan M17 amendment k).
func TestPurgeVersionsRecordsObjectLockRefusals(t *testing.T) {
	refusals := []struct{ name, code, message string }{
		{"AWS retention", "AccessDenied", "Access Denied because object protected by object lock."},
		{"lock code", "ObjectLocked", "Object is WORM protected and cannot be overwritten"},
		{"legal hold", "InvalidRequest", "Object is under legal hold"},
	}
	for _, rf := range refusals {
		t.Run(rf.name, func(t *testing.T) {
			f := newFakeVersioned("org/o/devices/d/luks-header/1", "org/o/devices/d/luks-header/2", "org/o/devices/d/luks-header/3",
				"org/o/devices/d/luks-header/4", "org/o/devices/d/luks-header/5")
			f.refuse = map[string]bool{"org/o/devices/d/luks-header/2": true, "org/o/devices/d/luks-header/4": true}
			f.code, f.message = rf.code, rf.message
			srv := httptest.NewServer(f)
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			p, err := objectstore.New(srv.URL, "k", "s", "b").PurgeVersions(ctx, "org/o/", time.Time{})
			if !errors.Is(err, objectstore.ErrRetained) {
				t.Fatalf("err = %v, want ErrRetained", err)
			}
			if p.Deleted != 3 || !p.Done || !slices.Equal(p.Retained, []string{"org/o/devices/d/luks-header/2", "org/o/devices/d/luks-header/4"}) {
				t.Fatalf("purge = %+v, want 3 deleted, versions 2 and 4 retained and the listing done", p)
			}
			if f.lists != 3 || f.batches != 3 {
				t.Fatalf("listed %d pages with %d DeleteObjects, want 3 and 3", f.lists, f.batches)
			}
		})
	}
}

// TestPurgeVersionsRustFSAccessDenied: RustFS 1.0.4 answers a version under Object Lock in DeleteObjects with a plain
// AccessDenied; the purge asks the single delete, whose lock message records it as retained. A plain AccessDenied there
// too is a missing grant and stops the purge.
func TestPurgeVersionsRustFSAccessDenied(t *testing.T) {
	for _, tc := range []struct {
		name, single string
		retained     bool
	}{{"lock", "Object is WORM protected and cannot be overwritten", true}, {"missing grant", "Access Denied.", false}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeVersioned("org/o/a", "org/o/b")
			f.refuse["org/o/a"] = true
			f.code, f.message, f.singleMessage = "AccessDenied", "Access Denied.", tc.single
			srv := httptest.NewServer(f)
			defer srv.Close()
			p, err := objectstore.New(srv.URL, "k", "s", "b").PurgeVersions(context.Background(), "org/o/", time.Time{})
			if tc.retained != errors.Is(err, objectstore.ErrRetained) || (err == nil) || p.Deleted != 1 || f.singles != 1 {
				t.Fatalf("purge = %+v, err = %v, %d single deletes", p, err, f.singles)
			}
			if tc.retained != slices.Equal(p.Retained, []string{"org/o/a"}) {
				t.Fatalf("retained %v", p.Retained)
			}
		})
	}
}

// TestPurgeVersionsSingleDeleteTimeouts (PDK-1087 fix round 1): every single delete that classifies a per-key
// AccessDenied gets its own PurgeRequestTimeout, so a page of locked versions whose single deletes together take longer
// than one timeout still ends with every version retained, not with a deadline error. This test takes about 32 s.
func TestPurgeVersionsSingleDeleteTimeouts(t *testing.T) {
	keys := make([]string, 16)
	for i := range keys {
		keys[i] = fmt.Sprintf("org/o/devices/d/luks-header/%02d", i)
	}
	f := newFakeVersioned(keys...)
	for _, k := range keys {
		f.refuse[k] = true
	}
	f.code, f.message, f.singleMessage = "AccessDenied", "Access Denied.", "Object is WORM protected and cannot be overwritten"
	f.pageSize, f.singleDelay = len(keys), objectstore.PurgeRequestTimeout/time.Duration(len(keys))+time.Second/8
	srv := httptest.NewServer(f)
	defer srv.Close()
	p, err := objectstore.New(srv.URL, "k", "s", "b").PurgeVersions(context.Background(), "org/o/", time.Time{})
	if !errors.Is(err, objectstore.ErrRetained) || len(p.Retained) != len(keys) || !p.Done || f.singles != len(keys) {
		t.Fatalf("purge = %d retained, done %v, err = %v after %d single deletes; want all %d retained", len(p.Retained), p.Done,
			err, f.singles, len(keys))
	}
}

// TestPurgeVersionsStopsAtFirstDenied (PDK-1087 fix round 1): a plain AccessDenied that the single delete confirms
// ends the call at that key; the page's other refused keys are not probed.
func TestPurgeVersionsStopsAtFirstDenied(t *testing.T) {
	f := newFakeVersioned("org/o/a", "org/o/b", "org/o/c", "org/o/d")
	f.pageSize = 4
	for _, k := range f.versions {
		f.refuse[k] = true
	}
	f.code, f.message, f.singleMessage = "AccessDenied", "Access Denied.", "Access Denied."
	srv := httptest.NewServer(f)
	defer srv.Close()
	p, err := objectstore.New(srv.URL, "k", "s", "b").PurgeVersions(context.Background(), "org/o/", time.Time{})
	if err == nil || errors.Is(err, objectstore.ErrRetained) || len(p.Retained) != 0 || f.singles != 1 {
		t.Fatalf("purge = %+v, err = %v after %d single deletes; want the error after the first", p, err, f.singles)
	}
}

// TestPurgeVersionsStopsOnOtherErrors (AC2): an AccessDenied of a missing grant or an InternalError of one key is no
// Object Lock refusal: the purge stops with it after the page and does not report it as retained. A refusal of the
// whole request stops it too.
func TestPurgeVersionsStopsOnOtherErrors(t *testing.T) {
	for _, tc := range []struct {
		name, code, message string
		status              int
	}{
		{"missing grant", "AccessDenied", "Access Denied.", 0},
		{"internal error", "InternalError", "We encountered an internal error. Please try again.", 0},
		{"whole request", "AccessDenied", "Access Denied.", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeVersioned("org/o/a", "org/o/b", "org/o/c")
			f.refuse = map[string]bool{"org/o/a": true}
			f.code, f.message, f.status = tc.code, tc.message, tc.status
			srv := httptest.NewServer(f)
			defer srv.Close()
			p, err := objectstore.New(srv.URL, "k", "s", "b").PurgeVersions(context.Background(), "org/o/", time.Time{})
			if err == nil || errors.Is(err, objectstore.ErrRetained) || len(p.Retained) != 0 || p.Done || f.lists != 1 {
				t.Fatalf("purge = %+v, err = %v after %d lists: want a plain error at the first page", p, err, f.lists)
			}
			if want := map[bool]int{true: 0, false: 1}[tc.status != 0]; p.Deleted != want || len(f.deleted) != want {
				t.Fatalf("deleted %d (store %v), want %d: the request's other deletions are counted", p.Deleted, f.deleted, want)
			}
		})
	}
}

// TestPurgeVersionsYield (AC2): with until in the past, a call returns after the first page on which it deleted
// something, with Done false; a page holding only retained entries does not yield, so a call that meets only those
// lists to the end.
func TestPurgeVersionsYield(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	f := newFakeVersioned("org/o/1", "org/o/2", "org/o/3", "org/o/4", "org/o/5")
	f.refuse = map[string]bool{"org/o/1": true, "org/o/2": true}
	f.code, f.message = "ObjectLocked", "locked"
	srv := httptest.NewServer(f)
	defer srv.Close()
	store := objectstore.New(srv.URL, "k", "s", "b")
	p, err := store.PurgeVersions(context.Background(), "org/o/", past)
	if err != nil || p.Done || p.Deleted != 2 || f.lists != 2 {
		t.Fatalf("first call: %+v, %v after %d lists; want 2 deleted after the second page and Done false", p, err, f.lists)
	}
	p, err = store.PurgeVersions(context.Background(), "org/o/", past)
	if !errors.Is(err, objectstore.ErrRetained) || !p.Done || p.Deleted != 1 || len(p.Retained) != 2 {
		t.Fatalf("second call: %+v, %v; want the last version deleted and the listing done", p, err)
	}
	f.lists = 0
	p, err = store.PurgeVersions(context.Background(), "org/o/", past)
	if !errors.Is(err, objectstore.ErrRetained) || !p.Done || p.Deleted != 0 || f.lists != 1 {
		t.Fatalf("only retained entries: %+v, %v after %d lists; want the listing done", p, err, f.lists)
	}

	locked := make([]string, 0, 6)
	for i := range 6 {
		locked = append(locked, fmt.Sprintf("org/l/%d", i))
	}
	g := newFakeVersioned(locked...)
	for _, k := range locked {
		g.refuse[k] = true
	}
	g.code, g.message = "ObjectLocked", "locked"
	gsrv := httptest.NewServer(g)
	defer gsrv.Close()
	p, err = objectstore.New(gsrv.URL, "k", "s", "b").PurgeVersions(context.Background(), "org/l/", past)
	if !errors.Is(err, objectstore.ErrRetained) || !p.Done || len(p.Retained) != 6 || g.lists != 3 {
		t.Fatalf("pages of retained entries only: %+v, %v after %d lists; want every page listed in one call", p, err, g.lists)
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
	p, err := store.PurgeVersions(ctx, prefix, time.Time{})
	if err != nil || p.Deleted != 4 || len(p.Retained) != 0 || !p.Done {
		t.Fatalf("purge = %+v, %v; want 4 deleted (two header versions, a diagnostics version and its delete marker)", p, err)
	}
	versions, err := r.Root.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &r.Bucket})
	if err != nil {
		t.Fatal(err)
	}
	if len(versions.Versions) != 1 || *versions.Versions[0].Key != "org/other/devices/d/luks-header/1" || len(versions.DeleteMarkers) != 0 {
		t.Fatalf("left %d versions, %d delete markers", len(versions.Versions), len(versions.DeleteMarkers))
	}
	if p, err := store.PurgeVersions(ctx, prefix, time.Time{}); err != nil || p.Deleted != 0 || !p.Done {
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
	p, err := store.PurgeVersions(ctx, "org/o/", time.Time{})
	if !errors.Is(err, objectstore.ErrRetained) || p.Deleted != 0 || !slices.Equal(p.Retained, []string{key}) {
		t.Fatalf("purge = %+v, err = %v; want the locked version retained", p, err)
	}
}

// countingProxy forwards to target and counts the DeleteObjects requests (POST ?delete). The client signs the proxy's
// host, which the proxy keeps as the Host header, so RustFS accepts the signature.
func countingProxy(t *testing.T, target string) (string, *atomic.Int32) {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	var batches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Query().Has("delete") {
			batches.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &batches
}

// putMany writes keys with 16 writers.
func putMany(t *testing.T, store *objectstore.Store, keys []string) {
	t.Helper()
	ctx := context.Background()
	work := make(chan string)
	errs := make(chan error, len(keys))
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for k := range work {
				errs <- store.Put(ctx, k, "application/octet-stream", "no-store", []byte("x"))
			}
		})
	}
	for _, k := range keys {
		work <- k
	}
	close(work)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestPurgeObjectsRustFS (AC1 of PDK-1087): RustFS 1.0.4 purges 2 500 objects below a prefix with exactly 3
// DeleteObjects requests. With until in the past one call deletes exactly 1 000 and returns Done false, and the next
// calls finish with Done true and 2 500 in total. Objects outside the prefix stay.
func TestPurgeObjectsRustFS(t *testing.T) {
	ctx := context.Background()
	r := s3test.StartPlain(t, "paddock-bundles")
	endpoint, batches := countingProxy(t, r.Endpoint)
	store := objectstore.New(endpoint, s3test.RootUser, s3test.RootPassword, r.Bucket)
	keys := make([]string, 0, 2500)
	for i := range 2500 {
		keys = append(keys, fmt.Sprintf("org/o/devices/%04d/bundle", i))
	}
	putMany(t, store, append(slices.Clone(keys), "org/other/a", "apt/o/x", "org/o-other/a"))

	p, err := store.PurgeObjects(ctx, "org/o/", time.Time{})
	if err != nil || p.Deleted != 2500 || len(p.Retained) != 0 || !p.Done {
		t.Fatalf("purge = %+v, %v", p, err)
	}
	if n := batches.Load(); n != 3 {
		t.Fatalf("%d DeleteObjects requests for 2 500 objects, want 3", n)
	}
	left, err := store.List(ctx, "")
	if err != nil || !slices.Equal(left, []string{"apt/o/x", "org/o-other/a", "org/other/a"}) {
		t.Fatalf("left %v, %v", left, err)
	}

	putMany(t, store, keys)
	batches.Store(0)
	past := time.Now().Add(-time.Minute)
	p, err = store.PurgeObjects(ctx, "org/o/", past)
	if err != nil || p.Deleted != 1000 || p.Done {
		t.Fatalf("first bounded call: %+v, %v; want exactly 1 000 deleted and Done false", p, err)
	}
	total, calls := p.Deleted, 1
	for !p.Done {
		if calls++; calls > 5 {
			t.Fatal("the bounded purge does not finish")
		}
		if p, err = store.PurgeObjects(ctx, "org/o/", past); err != nil {
			t.Fatal(err)
		}
		total += p.Deleted
	}
	if total != 2500 || calls != 3 || batches.Load() != 3 {
		t.Fatalf("bounded purge: %d deleted in %d calls with %d DeleteObjects, want 2 500 in 3 calls with 3", total, calls, batches.Load())
	}
	if left, err := store.List(ctx, ""); err != nil || len(left) != 3 {
		t.Fatalf("left %v, %v", left, err)
	}
}
