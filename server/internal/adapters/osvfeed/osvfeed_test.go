package osvfeed

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetch(t *testing.T) {
	var gotIfNoneMatch string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfNoneMatch = r.Header.Get("If-None-Match")
		switch {
		case r.URL.Path == "/fail":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case gotIfNoneMatch == `"v1"`:
			w.WriteHeader(http.StatusNotModified)
		default:
			w.Header().Set("ETag", `"v1"`)
			_, _ = io.WriteString(w, "zip bytes")
		}
	}))
	defer srv.Close()
	ctx := context.Background()

	t.Run("download", func(t *testing.T) {
		var etag, body string
		nm, err := New(srv.URL+"/all.zip").Fetch(ctx, "", func(e string, r io.Reader) error {
			b, err := io.ReadAll(r)
			etag, body = e, string(b)
			return err
		})
		if err != nil || nm || etag != `"v1"` || body != "zip bytes" || gotIfNoneMatch != "" {
			t.Errorf("nm %v err %v etag %q body %q if-none-match %q", nm, err, etag, body, gotIfNoneMatch)
		}
	})
	t.Run("not modified", func(t *testing.T) {
		nm, err := New(srv.URL+"/all.zip").Fetch(ctx, `"v1"`, func(string, io.Reader) error {
			t.Error("read called")
			return nil
		})
		if err != nil || !nm || gotIfNoneMatch != `"v1"` {
			t.Errorf("nm %v err %v if-none-match %q", nm, err, gotIfNoneMatch)
		}
	})
	t.Run("failure", func(t *testing.T) {
		_, err := New(srv.URL+"/fail").Fetch(ctx, "", func(string, io.Reader) error { return nil })
		if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
			t.Errorf("err %v", err)
		}
	})
	t.Run("reader error", func(t *testing.T) {
		boom := errors.New("boom")
		if _, err := New(srv.URL).Fetch(ctx, "", func(string, io.Reader) error { return boom }); !errors.Is(err, boom) {
			t.Errorf("err %v", err)
		}
	})
	t.Run("too large", func(t *testing.T) {
		c := New(srv.URL)
		c.maxSize = 4
		if _, err := c.Fetch(ctx, "", func(string, io.Reader) error { return nil }); !errors.Is(err, ErrTooLarge) {
			t.Errorf("content length: err %v", err)
		}
		chunked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "zip ")
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, "bytes")
		}))
		defer chunked.Close()
		c = New(chunked.URL)
		c.maxSize = 4
		_, err := c.Fetch(ctx, "", func(_ string, r io.Reader) error {
			_, err := io.ReadAll(r)
			return err
		})
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("streamed: err %v", err)
		}
	})
}
