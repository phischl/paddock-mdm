// Package device is the device API of the gateway role (api/openapi/device.yaml, plan M2a §6.2): request signature
// verification in the order of architecture §6.3, rate limits, and the enrollment, check-in, event, command result
// and escrow endpoints.
// The gateway reads only Valkey and writes only to RabbitMQ (and nonces, sequence numbers and enrollment requests to
// Valkey); it has no database credentials.
package device

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
)

var (
	metricRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "paddock_gateway_requests_total", Help: "Device API requests by route and status code.",
	}, []string{"route", "code"})
	metricAuthFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "paddock_gateway_auth_failures_total", Help: "Rejected device requests by reason.",
	}, []string{"reason"})
)

// Request size limits.
const (
	maxBody       = 64 << 10
	maxEventsBody = 1 << 20
)

// Default rate limits per minute (plan M2a §6.2).
const (
	DefaultPerKeyLimit = 30
	DefaultPerIPLimit  = 300
)

// BundleURLTTL is the validity of presigned bundle URLs (architecture §7.3).
const BundleURLTTL = 120 * time.Second

// ArtifactURLTTL is the validity of presigned agent artifact URLs; a download only has to start within it.
const ArtifactURLTTL = 5 * time.Minute

// HeaderUploadTTL is the validity of the presigned PUT of an escrowed LUKS header (plan M4b decision 10).
const HeaderUploadTTL = 10 * time.Minute

// Publisher publishes with publisher confirms (mq.Publisher).
type Publisher interface {
	PublishBatch(ctx context.Context, exchange string, msgs []mq.Message) ([]error, error)
}

// Presigner computes presigned bundle URLs (objectstore.Presigner).
type Presigner interface {
	PresignGet(ctx context.Context, key string, ttl time.Duration) (string, error)
}

// UploadPresigner computes presigned PUT URLs (objectstore.Presigner of the escrow bucket).
type UploadPresigner interface {
	PresignPut(ctx context.Context, key string, ttl time.Duration) (string, error)
}

// Deps are the dependencies of the device API.
type Deps struct {
	Cache     *devicecache.Cache
	Publisher Publisher
	Presigner Presigner
	// Artifacts presigns agent artifacts in paddock-agent-artifacts; nil disables agent updates.
	Artifacts Presigner
	// Escrow presigns header uploads to paddock-escrow; nil refuses header escrows.
	Escrow       UploadPresigner
	PerKeyLimit  int
	PerIPLimit   int
	Now          func() time.Time
	CheckinDelay func() int // seconds until the next check-in; default 300 × U(0.8, 1.2)
}

type gateway struct{ d Deps }

// NewHandler builds the device API with the shared middleware.
func NewHandler(d Deps) http.Handler {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.PerKeyLimit == 0 {
		d.PerKeyLimit = DefaultPerKeyLimit
	}
	if d.PerIPLimit == 0 {
		d.PerIPLimit = DefaultPerIPLimit
	}
	if d.CheckinDelay == nil {
		d.CheckinDelay = func() int { return int(300 * (0.8 + 0.4*rand.Float64())) } //nolint:gosec // jitter, not a secret
	}
	g := &gateway{d: d}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", g.enroll)
	mux.HandleFunc("GET /v1/enroll/{enrollment_id}", g.enrollStatus)
	mux.HandleFunc("POST /v1/checkin", g.checkin)
	mux.HandleFunc("POST /v1/events", g.events)
	mux.HandleFunc("POST /v1/commands/{command_id}/result", g.commandResult)
	mux.HandleFunc("POST /v1/escrow", g.escrowUpload)
	mux.HandleFunc("GET /v1/escrow/{escrow_id}", g.escrowStatus)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		g.fail(w, r, errNotFound)
	})
	return httpx.RequestIDMiddleware(httpx.Recover(httpx.AccessLog(countRequests(mux))))
}

// apiError is a device API problem.
type apiError struct {
	status     int
	code       string
	detail     string
	retryAfter time.Duration
}

func (e *apiError) Error() string { return e.code + ": " + e.detail }

func newError(status int, code string) *apiError { return &apiError{status: status, code: code} }

func (e *apiError) with(detail string) *apiError {
	c := *e
	c.detail = detail
	return &c
}

var (
	errInvalidRequest   = newError(http.StatusBadRequest, protocol.CodeInvalidRequest)
	errUnknownEventType = newError(http.StatusBadRequest, protocol.CodeUnknownEventType)
	errInvalidSignature = newError(http.StatusUnauthorized, protocol.CodeInvalidSignature)
	errClockSkew        = newError(http.StatusUnauthorized, protocol.CodeClockSkew)
	errReplay           = newError(http.StatusUnauthorized, protocol.CodeReplay)
	errInvalidToken     = newError(http.StatusUnauthorized, protocol.CodeInvalidToken)
	errIdentityRevoked  = newError(http.StatusUnauthorized, protocol.CodeIdentityRevoked)
	errNotFound         = newError(http.StatusNotFound, protocol.CodeNotFound)
	errTooLarge         = newError(http.StatusRequestEntityTooLarge, protocol.CodePayloadTooLarge)
	errConflict         = newError(http.StatusConflict, protocol.CodeConflict)
	errRateLimited      = newError(http.StatusTooManyRequests, protocol.CodeRateLimited)
	errBackpressure     = newError(http.StatusServiceUnavailable, protocol.CodeBackpressure)
	errInternal         = newError(http.StatusInternalServerError, "internal")
)

// fail writes err as problem details; anything that is not an *apiError is logged and answered 500.
func (g *gateway) fail(w http.ResponseWriter, r *http.Request, err error) {
	var e *apiError
	if !errors.As(err, &e) {
		slog.ErrorContext(r.Context(), "device request failed", "error", err, "request_id", httpx.RequestID(r.Context()))
		e = errInternal
	}
	p := protocol.Problem{
		Type: "urn:paddock:problem:" + e.code, Title: http.StatusText(e.status), Status: e.status, Code: e.code,
		Detail: e.detail, Instance: httpx.RequestID(r.Context()),
	}
	if e.status == http.StatusUnauthorized {
		now := g.d.Now().UTC()
		p.ServerTime = &now
		metricAuthFailures.WithLabelValues(e.code).Inc()
	}
	if e.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(e.retryAfter.Seconds())))
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(e.status)
	_ = json.NewEncoder(w).Encode(p)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// readBody reads at most limit bytes (413 above).
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return nil, errTooLarge
	}
	if err != nil {
		return nil, errInvalidRequest.with("unreadable body")
	}
	return body, nil
}

// decodeJSON parses a request body; unknown fields are allowed so newer agents stay compatible (ADR 0013).
func decodeJSON(body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return errInvalidRequest.with("body is not valid JSON for this endpoint")
	}
	return nil
}

// limit applies the per-minute rate limit of scope.
func (g *gateway) limit(ctx context.Context, scope string, n int) error {
	ok, wait, err := g.d.Cache.Allow(ctx, scope, n, g.d.Now())
	if err != nil {
		return err
	}
	if !ok {
		e := errRateLimited.with("too many requests")
		e.retryAfter = max(wait, time.Second)
		return e
	}
	return nil
}

// publish sends one message; a negative confirm is backpressure (503 with Retry-After).
func (g *gateway) publish(ctx context.Context, exchange string, msg mq.Message) error {
	res, err := g.d.Publisher.PublishBatch(ctx, exchange, []mq.Message{msg})
	if err != nil {
		return err
	}
	if res[0] != nil {
		if errors.Is(res[0], mq.ErrNacked) {
			e := errBackpressure.with("ingest queue full")
			e.retryAfter = 30 * time.Second
			return e
		}
		return res[0]
	}
	return nil
}

// countRequests counts paddock_gateway_requests_total{route,code}.
func countRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		route := r.Pattern
		if route == "" {
			route = "unmatched"
		}
		metricRequests.WithLabelValues(route, strconv.Itoa(rec.status)).Inc()
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
