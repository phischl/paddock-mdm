package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/platform/ratelimit"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// limitAuth applies the per-address class auth to /api/auth/* (plan M12h decision 8: after the client address is
// resolved, before any session or token is looked at); every other path passes untouched.
func (s *server) limitAuth(next http.Handler) http.Handler {
	if s.d.RateLimiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/auth/") && s.rateLimited(w, r, ratelimit.Auth,
			ratelimit.IPKey(httpx.ClientIP(r), ratelimit.DefaultV6Prefix)) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// limitPrincipal applies the per-principal classes after authentication and before the handlers (plan M12h decision
// 8): agent artifact and package uploads count as platform_upload, reads as admin_read, every other method as
// admin_write.
func (s *server) limitPrincipal(next http.Handler) http.Handler {
	if s.d.RateLimiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal.From(r.Context())
		if ok && s.rateLimited(w, r, principalClass(r), principalKey(p)) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// principalClass is the rate limit class of an authenticated admin API request.
func principalClass(r *http.Request) ratelimit.Class {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return ratelimit.AdminRead
	case http.MethodPut:
		if isAgentUpload(r.URL.Path) {
			return ratelimit.PlatformUpload
		}
	}
	return ratelimit.AdminWrite
}

// isAgentUpload matches PUT /api/platform/v1/agent-releases/{version}/artifacts/{arch} and
// /api/platform/v1/agent-releases/{version}/packages/{name}/{arch}.
func isAgentUpload(path string) bool {
	rest, ok := strings.CutPrefix(path, "/api/platform/v1/agent-releases/")
	if !ok {
		return false
	}
	seg := strings.Split(rest, "/")
	return len(seg) == 3 && seg[1] == "artifacts" || len(seg) == 4 && seg[1] == "packages"
}

// principalKey is the rate limit key of a principal: an API token is its own principal (its ID is the creator's
// account), a portal or MCP session is keyed by the session, anything else by its account. The session ID is hashed:
// it authenticates the session and has no business in a key name.
func principalKey(p principal.Principal) string {
	switch {
	case p.APITokenID != uuid.Nil:
		return "token:" + p.APITokenID.String()
	case p.SessionID != "":
		sum := sha256.Sum256([]byte(p.SessionID))
		return "session:" + hex.EncodeToString(sum[:16])
	default:
		return string(p.Kind) + ":" + p.ID.String()
	}
}

// rateLimited counts the request in class under key and answers 429 rate_limited with Retry-After once the limit is
// spent. Clients in the development exemption are not counted. A store error lets the request through.
func (s *server) rateLimited(w http.ResponseWriter, r *http.Request, class ratelimit.Class, key string) bool {
	if a, ok := httpx.ClientAddr(r); ok {
		for _, p := range s.d.RateLimitExempt {
			if p.Contains(a.Unmap()) {
				return false
			}
		}
	}
	ok, retryAfter, err := s.d.RateLimiter.Allow(r.Context(), class, key)
	if err != nil {
		slog.WarnContext(r.Context(), "rate limit unavailable; request not limited", "class", class, "error", err,
			"request_id", httpx.RequestID(r.Context()))
		return false
	}
	if ok {
		return false
	}
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retryAfter)))
	httpx.WriteProblem(w, r, problem.RateLimited)
	return true
}

func retryAfterSeconds(d time.Duration) int { return max(1, int(math.Ceil(d.Seconds()))) }
