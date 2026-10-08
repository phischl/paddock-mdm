package worker

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

func TestOSVDue(t *testing.T) {
	day := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	at := func(h, m int) *time.Time {
		v := day.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute)
		return &v
	}
	sec := func(v *time.Time) *time.Time { w := v.Add(time.Second); return &w }
	slot := 3*time.Hour + 17*time.Minute
	for _, c := range []struct {
		name    string
		started bool
		every   time.Duration
		now     time.Time
		st      app.OSVState
		want    bool
	}{
		{name: "start without data", now: *at(1, 0), want: true},
		{name: "start with data older than a day", now: *at(1, 0), st: app.OSVState{LastSuccessAt: at(-25, 0), LastAttemptAt: at(-25, 0)}, want: true},
		{name: "start with fresh data, before the slot", now: *at(1, 0), st: app.OSVState{LastSuccessAt: at(-20, 0), LastAttemptAt: at(-20, 0)}},
		{name: "slot reached", started: true, now: *at(3, 17), st: app.OSVState{LastSuccessAt: at(-20, 0), LastAttemptAt: at(-20, 0)}, want: true},
		{name: "slot done", started: true, now: *at(9, 0), st: app.OSVState{LastSuccessAt: at(3, 18), LastAttemptAt: at(3, 18)}},
		{name: "failed attempt at the slot waits for the next day", started: true, now: *at(23, 0), st: app.OSVState{LastSuccessAt: at(-20, 0), LastAttemptAt: at(3, 18)}},
		{name: "before today's slot, yesterday's done", started: true, now: *at(2, 0), st: app.OSVState{LastSuccessAt: at(-20, 0), LastAttemptAt: at(-20, 0)}},
		{name: "before today's slot, yesterday's missed", started: true, now: *at(2, 0), st: app.OSVState{LastSuccessAt: at(-30, 0), LastAttemptAt: at(-30, 0)}, want: true},
		{name: "interval elapsed", every: time.Minute, now: *at(1, 0), st: app.OSVState{LastAttemptAt: at(0, 59)}, want: true},
		{name: "interval not elapsed", every: time.Minute, now: *at(1, 0), st: app.OSVState{LastAttemptAt: sec(at(0, 59))}},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := &OSV{every: c.every, slot: slot, started: c.started}
			if got := o.due(c.now, c.st); got != c.want {
				t.Errorf("due %v, want %v", got, c.want)
			}
		})
	}
}

// fakeOSVSource answers like the OSV bucket: the zip with its ETag, 304 for that ETag, or an error.
type fakeOSVSource struct {
	zip       []byte
	etag      string
	err       error
	gotETags  []string
	downloads int
}

func (f *fakeOSVSource) Fetch(_ context.Context, etag string, read func(string, io.Reader) error) (bool, error) {
	f.gotETags = append(f.gotETags, etag)
	if f.err != nil {
		return false, f.err
	}
	if etag != "" && etag == f.etag {
		return true, nil
	}
	f.downloads++
	return false, read(f.etag, bytes.NewReader(f.zip))
}

// TestOSVRound (plan M5c decisions 1, 2 and 4, AC1, AC2): a round downloads, imports and enriches the findings, a
// later one sends the ETag and keeps the data on 304, a failing download keeps it and records the error.
func TestOSVRound(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	src := &fakeOSVSource{zip: osvFixtureZip(t), etag: `"round-1"`}
	uc := app.NewOSV(app.NewActionRunner(f.pool, platform, httpx.RequestID), f.pool, platform)
	o := NewOSV(uc, src, f.pool, platform, time.Nanosecond)
	rows := func() int {
		var n int
		if err := f.super.QueryRow(ctx, "SELECT count(*) FROM osv_ubuntu").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	state := func() app.OSVState {
		st, err := uc.State(principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"}))
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	dev := uuid.Must(uuid.NewV7())
	for _, sql := range []string{
		"INSERT INTO device (id, organization_id, hostname, state, hardware_uuid) VALUES ($1, $2, 'lt-osv', 'active', $3)",
		"INSERT INTO device_inventory_ref (device_id, organization_id, external_id, os_version) VALUES ($1, $2, $3, 'Ubuntu 24.04.3 LTS')",
		`INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version)
		 VALUES ($1, $2, 'CVE-2024-6387', 'openssh-server', '1:9.6p1-3ubuntu13')`,
	} {
		args := []any{dev, f.org}
		if strings.Count(sql, "$") == 3 {
			args = append(args, uuid.NewString())
		}
		if _, err := f.super.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}

	if err := o.Round(ctx); err != nil {
		t.Fatal(err)
	}
	var severity, fixed string
	if err := f.super.QueryRow(ctx, "SELECT severity, fixed_version FROM vulnerability_finding WHERE device_id = $1", dev).
		Scan(&severity, &fixed); err != nil || severity != "high" || fixed != "1:9.6p1-3ubuntu13.3" {
		t.Fatalf("finding after the import: %q %q %v", severity, fixed, err)
	}
	first := state()
	if src.downloads != 1 || rows() != 8 || first.ETag != `"round-1"` || first.LastError != "" {
		t.Fatalf("first round: downloads %d, rows %d, state %+v", src.downloads, rows(), first)
	}
	if err := o.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if st := state(); src.downloads != 1 || src.gotETags[1] != `"round-1"` || st.DataVersion != first.DataVersion ||
		!st.LastSuccessAt.After(*first.LastSuccessAt) {
		t.Fatalf("304 round: downloads %d, etags %v, state %+v", src.downloads, src.gotETags, st)
	}
	src.err = errors.New("osv: download: HTTP 500")
	if err := o.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if st := state(); rows() != 8 || st.LastError != "osv: download: HTTP 500" || st.DataVersion != first.DataVersion {
		t.Fatalf("failed round: rows %d, state %+v", rows(), st)
	}
}

// osvFixtureZip is a zip of the real OSV records of server/internal/osv/testdata.
func osvFixtureZip(t *testing.T) []byte {
	t.Helper()
	files, err := filepath.Glob("../osv/testdata/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("osv testdata: %v", err)
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range files {
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		fw, err := w.Create(filepath.Base(name))
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
