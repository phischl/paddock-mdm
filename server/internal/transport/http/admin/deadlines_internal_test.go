package admin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestUploadDeadlinesOutliveTimeouts covers plan M12h decision 15: on a server whose write timeout has passed, the
// agent release uploads still complete, because they extend the connection's deadlines, while any other operation is
// cut at the server's timeout. The audit export download keeps its own per-chunk deadlines (plan M10 decision 35,
// TestAuditExportDownloadOutlivesWriteTimeout).
func TestUploadDeadlinesOutliveTimeouts(t *testing.T) {
	const writeTimeout = 200 * time.Millisecond
	slow := func(_ context.Context, w http.ResponseWriter, _ *http.Request, _ any) (any, error) {
		time.Sleep(3 * writeTimeout)
		_, _ = io.WriteString(w, "package")
		return nil, nil
	}
	for op, wantComplete := range map[string]bool{
		"UploadAgentArtifact": true,
		"UploadAgentPackage":  true,
		"ListAuditExports":    false,
	} {
		t.Run(op, func(t *testing.T) {
			h := uploadDeadlines(slow, op)
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = h(r.Context(), w, r, nil)
			}))
			srv.Config.ReadTimeout = writeTimeout
			srv.Config.WriteTimeout = writeTimeout
			srv.Start()
			t.Cleanup(srv.Close)

			body, err := get(t, srv.URL)
			if complete := err == nil && body == "package"; complete != wantComplete {
				t.Fatalf("complete = %v (body %q, err %v), want %v", complete, body, err, wantComplete)
			}
		})
	}
}

func get(t *testing.T, url string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	return string(b), err
}
