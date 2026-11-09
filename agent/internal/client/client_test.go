package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/identity"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// TestCatalogIcon: the icon is a signed GET whose 2xx body comes back raw; an entry without an icon is an *APIError
// with status 404.
func TestCatalogIcon(t *testing.T) {
	const entry = "aaaaaaaa-0000-4000-8000-000000000001"
	png := []byte("\x89PNG\r\n\x1a\nicon")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Content-Type") != "" || r.Header.Get(protocol.HeaderSignature) == "" || r.Header.Get(protocol.HeaderDevice) != "device-1" {
			t.Errorf("request %s %v", r.Method, r.Header)
		}
		if r.URL.Path != "/v1/catalog/"+entry+"/icon" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"not_found","detail":"no icon"}`))
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	}))
	defer srv.Close()
	key, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "device.key"))
	if err != nil {
		t.Fatal(err)
	}
	c := NewWithHTTP(srv.URL, srv.Client(), key, time.Now)
	data, err := c.CatalogIcon(context.Background(), "device-1", 1, entry)
	if err != nil || string(data) != string(png) {
		t.Fatalf("icon %q %v", data, err)
	}
	_, err = c.CatalogIcon(context.Background(), "device-1", 2, "bbbbbbbb-0000-4000-8000-000000000002")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound || Code(err) != "not_found" {
		t.Fatalf("missing icon: %v", err)
	}
}
