// Package httpx holds the HTTP middleware shared by all HTTP roles: request ID, RFC 9457 problem details, panic
// recovery, JSON access log and request metrics.
package httpx

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// HeaderRequestID carries the request ID in responses.
const HeaderRequestID = "X-Request-Id"

var metricRequests = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "paddock_http_requests_total", Help: "HTTP requests by route pattern and status code.",
}, []string{"route", "code"})

type ctxKey struct{}

// RequestID returns the request ID of ctx ("" outside a request).
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// WithRequestID returns ctx carrying id (tests and background jobs).
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// RequestIDMiddleware assigns every request a new UUIDv7 request ID; client-supplied IDs are ignored.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.Must(uuid.NewV7()).String()
		w.Header().Set(HeaderRequestID, id)
		next.ServeHTTP(w, r.WithContext(WithRequestID(r.Context(), id)))
	})
}

// Problem is the RFC 9457 body.
type Problem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Code     string `json:"code"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance"`
}

// WriteProblem writes err as problem details. Errors that are not *problem.Error become 500 internal.
func WriteProblem(w http.ResponseWriter, r *http.Request, err error) {
	p := problem.From(err)
	if p.Status == 499 { // canceled: the client is gone; answer like a server error for logs and proxies
		p = problem.Internal
	}
	if p.Status >= 500 {
		slog.ErrorContext(r.Context(), "request failed", "error", err, "request_id", RequestID(r.Context()))
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(p.Status)
	detail := p.Detail
	if p.Status >= 500 {
		detail = "" // never leak internals
	}
	_ = json.NewEncoder(w).Encode(Problem{
		Type: "urn:paddock:problem:" + p.Code, Title: http.StatusText(p.Status), Status: p.Status, Code: p.Code,
		Detail: detail, Instance: RequestID(r.Context()),
	})
}

// statusRecorder captures the status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Recover turns panics into 500 internal problems. The ActionRunner has already recorded the audit failure of a
// running action before re-panicking.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler { //nolint:errorlint // sentinel compared by identity, as net/http does
					panic(v)
				}
				slog.ErrorContext(r.Context(), "panic", "panic", v, "request_id", RequestID(r.Context()))
				WriteProblem(w, r, problem.Internal)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type routeKey struct{}

type routeHolder struct{ route string }

// NoteRoute records the matched route pattern of r for the access log and metrics. Nested muxes call it after
// dispatching, because the outer request does not see the pattern of an inner mux.
func NoteRoute(r *http.Request) {
	if h, ok := r.Context().Value(routeKey{}).(*routeHolder); ok && r.Pattern != "" {
		h.route = r.Pattern
	}
}

// AccessLog logs one JSON line per request (no bodies) and counts paddock_http_requests_total{route,code}.
func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		holder := &routeHolder{}
		r = r.WithContext(context.WithValue(r.Context(), routeKey{}, holder))
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		route := holder.route
		if route == "" {
			route = r.Pattern
		}
		if route == "" {
			route = "unmatched"
		}
		metricRequests.WithLabelValues(route, strconv.Itoa(rec.status)).Inc()
		slog.InfoContext(r.Context(), "http request", "method", r.Method, "route", route, "path", r.URL.Path,
			"status", rec.status, "duration_ms", time.Since(start).Milliseconds(), "request_id", RequestID(r.Context()),
			"ip", ClientIP(r))
	})
}

// ClientIP is the client address: the first X-Forwarded-For entry set by the reverse proxy, else RemoteAddr.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
