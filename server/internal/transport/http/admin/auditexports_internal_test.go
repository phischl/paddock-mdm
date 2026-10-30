package admin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
)

// exportServer serves streamExport behind a real http.Server with the given write timeout, answering errors the way
// the generated strict handler does.
func exportServer(t *testing.T, writeTimeout, chunkDeadline time.Duration, download exportDownload) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := streamExport(r.Context(), uuid.New(), download, chunkDeadline)
		if err == nil {
			err = res.VisitDownloadAuditExportResponse(w)
		}
		if err != nil {
			httpx.WriteProblem(w, r, err)
		}
	}))
	srv.Config.WriteTimeout = writeTimeout
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func exportPackage(size int64) app.ExportPackage {
	return app.ExportPackage{Export: auditstore.AuditExport{Size: &size, PackageSha256: make([]byte, 32)}, Filename: "p.tar"}
}

func TestAuditExportDownloadOutlivesWriteTimeout(t *testing.T) {
	const chunks, chunkSize = 10, 32 << 10
	srv := exportServer(t, 300*time.Millisecond, 2*time.Second,
		func(_ context.Context, _ uuid.UUID, begin func(app.ExportPackage), stream func([]byte) error) error {
			begin(exportPackage(chunks * chunkSize))
			for range chunks {
				time.Sleep(100 * time.Millisecond)
				if err := stream(bytes.Repeat([]byte{'A'}, chunkSize)); err != nil {
					return err
				}
			}
			return nil
		})
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK || len(body) != chunks*chunkSize {
		t.Fatalf("download over the write timeout: status %d, %d bytes, %v", resp.StatusCode, len(body), err)
	}
}

func TestAuditExportDownloadStalledClient(t *testing.T) {
	done := make(chan error, 1)
	srv := exportServer(t, time.Minute, 200*time.Millisecond,
		func(_ context.Context, _ uuid.UUID, begin func(app.ExportPackage), stream func([]byte) error) error {
			begin(exportPackage(1 << 40))
			chunk := make([]byte, 256<<10)
			for {
				if err := stream(chunk); err != nil {
					done <- err
					return err
				}
			}
		})
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: paddock\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("stalled client ended the use case with %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("a client that stopped reading still holds the download well past the per-chunk bound")
	}
}

// expectTruncated asserts a 200 answer whose body stops after prefix without anything appended.
func expectTruncated(t *testing.T, srv *httptest.Server, prefix []byte) {
	t.Helper()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !errors.Is(err, io.ErrUnexpectedEOF) || !bytes.Equal(body, prefix) {
		t.Fatalf("broken download: status %d, err %v, body %q", resp.StatusCode, err, body)
	}
}

func TestAuditExportDownloadChunkFailureTruncates(t *testing.T) {
	first := bytes.Repeat([]byte{'A'}, 1024)
	srv := exportServer(t, time.Minute, time.Minute,
		func(_ context.Context, _ uuid.UUID, begin func(app.ExportPackage), stream func([]byte) error) error {
			begin(exportPackage(3 * 1024))
			if err := stream(first); err != nil {
				return err
			}
			return errors.New("read chunk 1: connection reset")
		})
	expectTruncated(t, srv, first)
}

func TestAuditExportDownloadPanic(t *testing.T) {
	t.Run("before the headers", func(t *testing.T) {
		srv := exportServer(t, time.Minute, time.Minute,
			func(context.Context, uuid.UUID, func(app.ExportPackage), func([]byte) error) error {
				panic("pgx exploded")
			})
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var p struct{ Code string }
		if err := json.NewDecoder(bufio.NewReader(resp.Body)).Decode(&p); err != nil || resp.StatusCode != http.StatusInternalServerError || p.Code != "internal" {
			t.Fatalf("panic before begin: status %d, code %q, %v", resp.StatusCode, p.Code, err)
		}
	})
	t.Run("while streaming", func(t *testing.T) {
		first := []byte(strings.Repeat("B", 512))
		srv := exportServer(t, time.Minute, time.Minute,
			func(_ context.Context, _ uuid.UUID, begin func(app.ExportPackage), stream func([]byte) error) error {
				begin(exportPackage(2048))
				if err := stream(first); err != nil {
					return err
				}
				panic("pgx exploded")
			})
		expectTruncated(t, srv, first)
	})
}
