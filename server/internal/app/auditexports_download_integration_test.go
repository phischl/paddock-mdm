package app_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// storeExport inserts an export of organization org as the audit writer would leave it, with the given chunks, and
// returns its ID and the SHA-256 of the chunks.
func (h exportHarness) storeExport(t *testing.T, org uuid.UUID, status string, expires time.Time, chunks ...[]byte) (uuid.UUID, []byte) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, h.writerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	id := uuid.Must(uuid.NewV7())
	sum := sha256.New()
	var size int64
	for _, c := range chunks {
		sum.Write(c)
		size += int64(len(c))
	}
	day := exportDay(1)
	_, err = conn.Exec(ctx, `INSERT INTO audit_export (id, organization_id, status, from_day, to_day, purpose, requested_by,
		correlation_id, ready_at, expires_at, size, package_sha256, event_count, object_count, verify_ok)
		VALUES ($1, $2, $3, $4, $4, 'download test', '{}', 'c', now(), $5, $6, $7, 1, 1, true)`,
		id, org, status, day, expires, size, sum.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	for seq, c := range chunks {
		if _, err := conn.Exec(ctx, "INSERT INTO audit_export_chunk (export_id, organization_id, seq, data) VALUES ($1, $2, $3, $4)", id, org, seq, c); err != nil {
			t.Fatal(err)
		}
	}
	return id, sum.Sum(nil)
}

// download collects the package Download streams.
func download(ctx context.Context, h exportHarness, id uuid.UUID) (app.ExportPackage, []byte, error) {
	var pkg app.ExportPackage
	var body bytes.Buffer
	err := h.exports.Download(ctx, id, func(p app.ExportPackage) { pkg = p }, func(chunk []byte) error {
		body.Write(chunk)
		return nil
	})
	return pkg, body.Bytes(), err
}

func TestAuditExportDownloadSuccess(t *testing.T) {
	h := newExportHarness(t)
	id, sum := h.storeExport(t, h.org, "ready", time.Now().Add(time.Hour), []byte("first,"), []byte("second,"), []byte("third"))
	pkg, body, err := download(h.admin(principal.RoleOrgAuditor), h, id)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "first,second,third" || pkg.Export.ID != id {
		t.Fatalf("body %q, export %s", body, pkg.Export.ID)
	}
	var slug string
	if err := h.super.QueryRow(context.Background(), "SELECT slug FROM organization WHERE id = $1", h.org).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	want := "paddock-audit-export-" + slug + "-" + exportDay(1).Format(time.DateOnly) + "_" + exportDay(1).Format(time.DateOnly) +
		"-" + id.String()[:8] + ".tar"
	if pkg.Filename != want {
		t.Fatalf("filename %q, want %q", pkg.Filename, want)
	}
	ev := expectOne(t, h.harness, audit.OutcomeSuccess, "")
	if ev.Code != audit.CodeAuditExportDownloaded || ev.Params["export_id"] != id.String() ||
		ev.Params["from_day"] != exportDay(1).Format(time.DateOnly) || ev.Params["to_day"] != exportDay(1).Format(time.DateOnly) ||
		ev.Params["size"] != float64(len(body)) || ev.Params["package_sha256"] != hex.EncodeToString(sum) {
		t.Fatalf("event = %+v", ev)
	}
}

// TestAuditExportDownloadRefusals: every refusal is one recorded attempt; nothing is streamed.
func TestAuditExportDownloadRefusals(t *testing.T) {
	future, past := time.Now().Add(time.Hour), time.Now().Add(-time.Hour)
	for _, c := range []struct {
		name    string
		status  string
		expires time.Time
		role    principal.Role
		foreign bool
		want    *problem.Error
		outcome audit.Outcome
	}{
		{"pending", "pending", future, principal.RoleOrgAuditor, false, problem.ExportNotReady, audit.OutcomeFailure},
		{"running", "running", future, principal.RoleOrgAuditor, false, problem.ExportNotReady, audit.OutcomeFailure},
		{"failed", "failed", future, principal.RoleOrgAdmin, false, problem.ExportNotReady, audit.OutcomeFailure},
		{"expired", "expired", past, principal.RoleOrgAuditor, false, problem.ExportNotReady, audit.OutcomeFailure},
		{"ready but past expiry", "ready", past, principal.RoleOrgAuditor, false, problem.ExportNotReady, audit.OutcomeFailure},
		{"foreign organization", "ready", future, principal.RoleOrgAuditor, true, problem.NotFound, audit.OutcomeFailure},
		{"operator", "ready", future, principal.RoleOrgOperator, false, problem.Forbidden, audit.OutcomeDenied},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newExportHarness(t)
			org := h.org
			if c.foreign {
				org = uuid.Must(uuid.NewV7())
			}
			id, _ := h.storeExport(t, org, c.status, c.expires, []byte("secret package"))
			var begun bool
			err := h.exports.Download(h.admin(c.role), id, func(app.ExportPackage) { begun = true }, func([]byte) error {
				t.Error("a chunk was streamed")
				return nil
			})
			if !errors.Is(err, c.want) || begun {
				t.Fatalf("err = %v (begun %v), want %v", err, begun, c.want)
			}
			ev := expectOne(t, h.harness, c.outcome, c.want.Code)
			if ev.Code != audit.CodeAuditExportDownloaded {
				t.Fatalf("event code %s", ev.Code)
			}
			if _, ok := ev.Params["package_sha256"]; ok {
				t.Fatalf("a refused download records the package checksum: %+v", ev.Params)
			}
		})
	}
}

// TestAuditExportDownloadStreamsLargePackage: a package over 100 MiB flows through an io.Pipe chunk by chunk, so no
// more than one chunk is ever held by the use case, and the receiver sees the stored checksum.
func TestAuditExportDownloadStreamsLargePackage(t *testing.T) {
	h := newExportHarness(t)
	const chunkSize = 8 << 20
	chunk := bytes.Repeat([]byte("0123456789abcdef"), chunkSize/16)
	chunks := make([][]byte, 13)
	for i := range chunks {
		chunks[i] = chunk
	}
	id, sum := h.storeExport(t, h.org, "ready", time.Now().Add(time.Hour), chunks...)

	pr, pw := io.Pipe()
	var calls, largest int
	var wg sync.WaitGroup
	wg.Add(1)
	var downloadErr error
	go func() {
		defer wg.Done()
		downloadErr = h.exports.Download(h.admin(principal.RoleOrgAuditor), id, func(app.ExportPackage) {}, func(c []byte) error {
			calls++
			largest = max(largest, len(c))
			_, err := pw.Write(c)
			return err
		})
		pw.CloseWithError(downloadErr)
	}()
	got := sha256.New()
	n, err := io.Copy(got, pr)
	wg.Wait()
	if err != nil || downloadErr != nil {
		t.Fatalf("copy %v, download %v", err, downloadErr)
	}
	if n != int64(len(chunks))*chunkSize || n < 100<<20 || calls != len(chunks) || largest != chunkSize ||
		!bytes.Equal(got.Sum(nil), sum) {
		t.Fatalf("%d bytes in %d calls (largest %d)", n, calls, largest)
	}
	expectOne(t, h.harness, audit.OutcomeSuccess, "")
}

// TestAuditExportDownloadDetectsDamagedChunks: a package whose stored chunks do not add up to the recorded size and
// checksum is reported to the caller after the event was recorded.
func TestAuditExportDownloadDetectsDamagedChunks(t *testing.T) {
	h := newExportHarness(t)
	id, _ := h.storeExport(t, h.org, "ready", time.Now().Add(time.Hour), []byte("abc"))
	conn, err := pgx.Connect(context.Background(), h.writerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(), "DELETE FROM audit_export_chunk WHERE export_id = $1", id); err != nil {
		t.Fatal(err)
	}
	_, _, err = download(h.admin(principal.RoleOrgAuditor), h, id)
	if err == nil || !strings.Contains(err.Error(), "different checksum") {
		t.Fatalf("err = %v", err)
	}
	expectOne(t, h.harness, audit.OutcomeSuccess, "")
}
