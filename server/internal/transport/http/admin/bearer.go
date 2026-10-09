package admin

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

var metricAPITokenAuth = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "paddock_api_token_auth_total",
	Help: "API token authentications of the admin API by result (ok, unknown, revoked, expired).",
}, []string{"result"})

// bearerSecret returns the secret of an Authorization: Bearer header.
func bearerSecret(r *http.Request) (string, bool) {
	scheme, secret, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	return strings.TrimSpace(secret), true
}

// bearer authenticates a request with an API token (plan M6c decision 9) instead of the session cookie. Unknown and
// malformed secrets are refused without an audit event, revoked and expired tokens with one api_token.use_denied
// event; the secret is never logged.
func (s *server) bearer(next http.Handler, w http.ResponseWriter, r *http.Request, secret string) {
	if s.d.APITokens == nil {
		httpx.WriteProblem(w, r, problem.Unauthenticated)
		return
	}
	p, result, err := s.d.APITokens.Authenticate(r.Context(), secret, httpx.ClientIP(r))
	if result != "" {
		metricAPITokenAuth.WithLabelValues(string(result)).Inc()
	}
	if err != nil {
		if errors.Is(err, problem.Unauthenticated) {
			slog.WarnContext(r.Context(), "api token refused", "result", result, "ip", httpx.ClientIP(r))
		}
		httpx.WriteProblem(w, r, err)
		return
	}
	next.ServeHTTP(w, r.WithContext(principal.With(r.Context(), p)))
}
