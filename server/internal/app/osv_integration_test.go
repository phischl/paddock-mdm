package app_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/osv"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type osvHarness struct {
	osv    *app.OSV
	worker *db.OrgPool
	super  *pgx.Conn
}

func newOSVHarness(t *testing.T) osvHarness {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	worker, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	runner := app.NewActionRunner(worker, platform, httpx.RequestID)
	return osvHarness{osv: app.NewOSV(runner, worker, platform), worker: worker, super: super}
}

func (h osvHarness) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := h.super.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// osvZip is a zip of the real OSV records of server/internal/osv/testdata.
func osvZip(t *testing.T) []byte {
	t.Helper()
	files, err := filepath.Glob("../osv/testdata/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("osv testdata: %v", err)
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		fw, err := w.Create(filepath.Base(f))
		if err == nil {
			_, err = fw.Write(body)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func systemPlatform() context.Context {
	return principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem, Display: "worker"})
}

func readZip(data []byte) func(fn func(osv.Entry) error) (osv.Stats, error) {
	return func(fn func(osv.Entry) error) (osv.Stats, error) { return osv.Read(bytes.NewReader(data), fn) }
}

// TestOSVImport (plan M5c decision 1, AC2): an import replaces the data in one transaction and records the ETag; a
// failing or empty read leaves the previous data and state; 304 and failures are recorded.
func TestOSVImport(t *testing.T) {
	h := newOSVHarness(t)
	ctx := systemPlatform()
	before, err := h.osv.State(ctx)
	if err != nil {
		t.Fatal(err)
	}

	st, err := h.osv.Import(ctx, `"etag-1"`, readZip(osvZip(t)))
	if err != nil || st.Entries != 8 {
		t.Fatalf("import: %+v %v", st, err)
	}
	if n := h.count(t, "SELECT count(*) FROM osv_ubuntu"); n != 8 {
		t.Errorf("osv_ubuntu has %d rows, want 8", n)
	}
	if n := h.count(t, `SELECT count(*) FROM osv_ubuntu WHERE cve = 'CVE-2026-11386' AND release = '26.04'
		AND package = 'ubuntu-advantage-tools' AND priority = 'high' AND fixed_version = '37.2ubuntu0.1'
		AND cvss_vector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H'`); n != 1 {
		t.Error("CVE-2026-11386 in 26.04 missing")
	}
	if n := h.count(t, "SELECT count(*) FROM osv_ubuntu WHERE fixed_version IS NULL AND cve = 'CVE-2008-7320' AND priority = ''"); n != 1 {
		t.Error("CVE-2008-7320 without fix and priority missing")
	}
	// Binary packages of other names than their source package, per release: libcg and libcggl in both, six of
	// openssh in 24.04, four of ubuntu-advantage-tools in both.
	if n := h.count(t, "SELECT count(*) FROM osv_ubuntu_binary"); n != 2*2+6+2*4 {
		t.Errorf("osv_ubuntu_binary has %d rows, want 18", n)
	}
	if n := h.count(t, "SELECT count(*) FROM osv_ubuntu_binary WHERE release = '24.04' AND binary_name = 'openssh-client' AND package = 'openssh'"); n != 1 {
		t.Error("openssh-client → openssh missing")
	}
	after, err := h.osv.State(ctx)
	if err != nil || after.ETag != `"etag-1"` || after.DataVersion != before.DataVersion+1 || after.Entries != 8 ||
		after.LastSuccessAt == nil || after.LastError != "" {
		t.Fatalf("state %+v %v", after, err)
	}

	t.Run("failed read keeps the data", func(t *testing.T) {
		data := osvZip(t)
		if _, err := h.osv.Import(ctx, `"etag-2"`, readZip(data[:len(data)-200])); err == nil {
			t.Fatal("truncated zip imported")
		}
		if _, err := h.osv.Import(ctx, `"etag-3"`, func(func(osv.Entry) error) (osv.Stats, error) { return osv.Stats{}, nil }); err == nil {
			t.Fatal("empty import accepted")
		}
		if n := h.count(t, "SELECT count(*) FROM osv_ubuntu"); n != 8 {
			t.Errorf("osv_ubuntu has %d rows after failed imports", n)
		}
		if st, _ := h.osv.State(ctx); st.ETag != `"etag-1"` || st.DataVersion != after.DataVersion {
			t.Errorf("state changed by failed imports: %+v", st)
		}
	})

	t.Run("failure and 304", func(t *testing.T) {
		if err := h.osv.Failed(ctx, errors.New("osv: download: HTTP 503")); err != nil {
			t.Fatal(err)
		}
		st, _ := h.osv.State(ctx)
		if st.LastError != "osv: download: HTTP 503" || st.LastAttemptAt == nil || !st.LastSuccessAt.Equal(*after.LastSuccessAt) {
			t.Errorf("after failure %+v", st)
		}
		if err := h.osv.NotModified(ctx); err != nil {
			t.Fatal(err)
		}
		st, _ = h.osv.State(ctx)
		if st.LastError != "" || !st.LastSuccessAt.After(*after.LastSuccessAt) || st.DataVersion != after.DataVersion || st.ETag != `"etag-1"` {
			t.Errorf("after 304 %+v", st)
		}
	})

	t.Run("stale alert once", func(t *testing.T) {
		alerts := func() int { return h.count(t, "SELECT count(*) FROM action WHERE code = 'platform.osv_stale'") }
		start := alerts()
		if stale, err := h.osv.AlertIfStale(ctx, time.Now().Add(71*time.Hour)); err != nil || stale {
			t.Fatalf("after 71 h: stale %v %v", stale, err)
		}
		for range 2 {
			if stale, err := h.osv.AlertIfStale(ctx, time.Now().Add(73*time.Hour)); err != nil || !stale {
				t.Fatalf("after 73 h: stale %v %v", stale, err)
			}
		}
		if n := alerts() - start; n != 1 {
			t.Fatalf("%d platform.osv_stale events, want 1", n)
		}
		if n := h.count(t, `SELECT count(*) FROM action WHERE code = 'platform.osv_stale' AND outcome = 'success'
			AND organization_id = '00000000-0000-0000-0000-000000000000' AND params ? 'last_success_at'`); n < 1 {
			t.Error("platform.osv_stale not in the platform pseudo-organization with last_success_at")
		}
		// A success ends the stale period: the next one is alerted again.
		if err := h.osv.NotModified(ctx); err != nil {
			t.Fatal(err)
		}
		if st, _ := h.osv.State(ctx); st.StaleAlerted {
			t.Error("stale alert not cleared by a success")
		}
		if _, err := h.osv.AlertIfStale(ctx, time.Now().Add(73*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if n := alerts() - start; n != 2 {
			t.Errorf("%d platform.osv_stale events, want 2", n)
		}
	})
}
