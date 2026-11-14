package admin

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/platform/ratelimit"
)

// repositoryPrefix is the path of the organizations' Paddock repositories on the bundles host (ADR 0050 decision 1).
const repositoryPrefix = "/apt/"

// RepositoryLocator answers apt's requests for an organization's Paddock repository (app.SoftwarePackages).
type RepositoryLocator interface {
	Locate(ctx context.Context, slug, username, password, path string) (string, error)
}

// bundlesHost answers every request for the bundles host with the repository route group (plan M13c decision 14):
// Caddy forwards only /apt/* of that host to the api, and none of the admin API, the portal or the IP allow list of
// the administrative surfaces applies to it. Other hosts pass to next.
func (s *server) bundlesHost(next http.Handler) http.Handler {
	if s.d.BundlesHost == "" || s.d.Repositories == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Host, s.d.BundlesHost) {
			next.ServeHTTP(w, r)
			return
		}
		s.serveRepository(w, r)
	})
}

// serveRepository answers GET /apt/<org_slug>/<path> for apt: 429 beyond the bundles_apt limit per client address,
// 401 with a Basic challenge unless the request carries the organization's credential, 302 to a presigned URL of the
// object, 404 for anything else. Only the path (with the slug) is logged, by the access log; never the credential.
func (s *server) serveRepository(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	rest, ok := strings.CutPrefix(r.URL.Path, repositoryPrefix)
	slug, path, hasPath := strings.Cut(rest, "/")
	if !ok || !hasPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if s.d.RateLimiter != nil && s.rateLimited(w, r, ratelimit.BundlesAPT, ratelimit.IPKey(httpx.ClientIP(r), ratelimit.DefaultV6Prefix)) {
		return
	}
	user, password, _ := r.BasicAuth()
	url, err := s.d.Repositories.Locate(r.Context(), slug, user, password, path)
	switch {
	case errors.Is(err, app.ErrRepositoryUnauthorized):
		w.Header().Set("WWW-Authenticate", `Basic realm="paddock"`)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	case errors.Is(err, app.ErrRepositoryNotFound):
		http.NotFound(w, r)
	case err != nil:
		slog.ErrorContext(r.Context(), "repository request failed", "path", r.URL.Path, "error", err,
			"request_id", httpx.RequestID(r.Context()))
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	default:
		// url is a presigned URL of the bundles host that Locate built from the configured public endpoint, never from
		// the request.
		http.Redirect(w, r, url, http.StatusFound) //nolint:gosec // see above
	}
}
