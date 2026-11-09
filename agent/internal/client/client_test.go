package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/identity"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// TestCatalogIcon (architect decision A10-14): the icon is a signed GET that the device API answers with a redirect to
// the bundles host; the client follows it without the signed headers and returns the body only for 200 image/png of at
// most MaxIconBytes with the PNG signature. An entry without an icon is an *APIError with status 404.
func TestCatalogIcon(t *testing.T) {
	const entry = "aaaaaaaa-0000-4000-8000-000000000001"
	png := []byte("\x89PNG\r\n\x1a\nicon")
	store := struct {
		contentType string
		body        []byte
		status      int
	}{"image/png", png, http.StatusOK}
	objects := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for h := range r.Header {
			if strings.HasPrefix(h, "Paddock-") {
				t.Errorf("signed header %s reached the object store", h)
			}
		}
		if r.URL.Path != "/paddock-bundles/icon.png" || r.URL.Query().Get("X-Amz-Signature") != "x" {
			t.Errorf("object request %s", r.URL)
		}
		w.Header().Set("Content-Type", store.contentType)
		w.WriteHeader(store.status)
		_, _ = w.Write(store.body)
	}))
	defer objects.Close()
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
		http.Redirect(w, r, objects.URL+"/paddock-bundles/icon.png?X-Amz-Signature=x", http.StatusFound)
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

	for name, change := range map[string]func(){
		"content type": func() { store.contentType = "text/html" },
		"not a png":    func() { store.body = []byte("<html>") },
		"over 64 KiB":  func() { store.body = append(slices.Clone(png), make([]byte, MaxIconBytes)...) },
		"status":       func() { store.status = http.StatusForbidden },
	} {
		store.contentType, store.body, store.status = "image/png", png, http.StatusOK
		change()
		if data, err := c.CatalogIcon(context.Background(), "device-1", 3, entry); err == nil || data != nil {
			t.Errorf("%s: %d bytes, %v", name, len(data), err)
		}
	}
}
