package httpx

import (
	"io"
	"net/http"
)

// HeaderBodyUnread marks a 2xx or 3xx answer to a POST, PUT, PATCH or DELETE whose request body the handler did not
// read to the end. The edge closes the HTTP/1.x connection on it and removes the header (PDK-971).
const HeaderBodyUnread = "X-Paddock-Body-Unread"

// MarkUnreadBody sets HeaderBodyUnread on a successful answer to a state-changing request whose body was not read to
// EOF. Caddy would otherwise drain the rest of such a body before it writes the answer, so a body sent at 1 byte per
// second would hold the connection for about twice the 60 s read timeout. Error answers are closed by the edge anyway.
func MarkUnreadBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			next.ServeHTTP(w, r)
			return
		}
		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		body := &trackedBody{ReadCloser: r.Body}
		r.Body = body
		next.ServeHTTP(&unreadWriter{ResponseWriter: w, body: body}, r)
	})
}

type trackedBody struct {
	io.ReadCloser
	eof bool
}

func (b *trackedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.eof = true
	}
	return n, err
}

type unreadWriter struct {
	http.ResponseWriter
	body        *trackedBody
	wroteHeader bool
}

func (u *unreadWriter) WriteHeader(code int) {
	// Informational answers (1xx) precede the final status and keep the header map open.
	if code >= 200 && !u.wroteHeader {
		u.wroteHeader = true
		if code < 400 && !u.body.eof {
			u.Header().Set(HeaderBodyUnread, "1")
		}
	}
	u.ResponseWriter.WriteHeader(code)
}

func (u *unreadWriter) Write(b []byte) (int, error) {
	if !u.wroteHeader {
		u.WriteHeader(http.StatusOK)
	}
	return u.ResponseWriter.Write(b)
}

func (u *unreadWriter) Flush() {
	if !u.wroteHeader {
		u.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(u.ResponseWriter).Flush()
}

func (u *unreadWriter) Unwrap() http.ResponseWriter { return u.ResponseWriter }
