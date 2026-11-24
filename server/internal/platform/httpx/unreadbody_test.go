package httpx_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
)

func TestMarkUnreadBody(t *testing.T) {
	ignore := func(status int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
	}
	readAll := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	readPart := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadFull(r.Body, make([]byte, 2))
		_, _ = w.Write([]byte("ok"))
	})
	cases := []struct {
		name    string
		method  string
		body    io.Reader
		chunked bool
		h       http.Handler
		want    bool
	}{
		{"post 200 unread", http.MethodPost, strings.NewReader("hello"), false, ignore(200), true},
		{"post 200 unread chunked", http.MethodPost, strings.NewReader("hello"), true, ignore(200), true},
		{"put 204 unread", http.MethodPut, strings.NewReader("hello"), false, ignore(204), true},
		{"patch 302 unread", http.MethodPatch, strings.NewReader("hello"), false, ignore(302), true},
		{"delete 200 unread", http.MethodDelete, strings.NewReader("hello"), false, ignore(200), true},
		{"post implicit 200 partly read", http.MethodPost, strings.NewReader("hello"), false, readPart, true},
		{"post read to EOF", http.MethodPost, strings.NewReader("hello"), false, readAll, false},
		{"post read to EOF chunked", http.MethodPost, strings.NewReader("hello"), true, readAll, false},
		{"post 400 unread", http.MethodPost, strings.NewReader("hello"), false, ignore(400), false},
		{"post 500 unread", http.MethodPost, strings.NewReader("hello"), false, ignore(500), false},
		{"post without body", http.MethodPost, nil, false, ignore(200), false},
		{"get with body", http.MethodGet, strings.NewReader("hello"), false, ignore(200), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/x", tc.body)
			if tc.chunked {
				req.ContentLength = -1
			}
			rec := httptest.NewRecorder()
			httpx.MarkUnreadBody(tc.h).ServeHTTP(rec, req)
			got := rec.Header().Get(httpx.HeaderBodyUnread) == "1"
			if got != tc.want {
				t.Fatalf("marker = %v, want %v", got, tc.want)
			}
		})
	}
}
