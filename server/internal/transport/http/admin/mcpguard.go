package admin

import (
	"math"
	"net/http"
	"slices"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

var metricMCPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "paddock_mcp_requests_total",
	Help: "Admin API requests of MCP sessions by tool class (read, write) and guard result (ok, denied, rate_limited).",
}, []string{"class", "result"})

// Details of the guard's refusals (plan M14 §3.4 item 20).
const (
	mcpDetailNotOffered     = "this operation is not available through the MCP; use the portal"
	mcpDetailNotSelected    = "the MCP policy of this scope does not include this operation"
	mcpDetailPolicyNoWrite  = "the MCP policy of this scope does not allow changes"
	mcpDetailAccountNoWrite = "enable MCP write access for your account in the portal (account menu)"
)

// mcpGuard decides, before any use case runs, whether an MCP session may call the matched operation: from its class
// in the shared catalog, the MCP policy of the principal's scope and the account's write opt-in, then within the
// account's rate limit (plan M14 §3.4 item 20). Portal sessions and API tokens pass untouched.
func (s *server) mcpGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal.From(r.Context())
		if !ok || p.Channel != principal.ChannelMCP {
			next.ServeHTTP(w, r)
			return
		}
		tool, known := mcpcatalog.ByPattern(r.Pattern)
		class := tool.Class
		if !known {
			class = mcpcatalog.ClassWrite
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				class = mcpcatalog.ClassRead
			}
		}
		refuse := func(err error) {
			metricMCPRequests.WithLabelValues(string(class), "denied").Inc()
			s.refuseMCP(w, r, err)
		}
		switch {
		case !known:
			refuse(problem.MCPToolNotAllowed.WithDetail(mcpDetailNotOffered))
			return
		case tool.Bootstrap:
			if s.mcpRateLimited(w, r, p, mcpcatalog.ClassRead) {
				return
			}
			next.ServeHTTP(w, r)
			return
		case !tool.Expose || tool.StepUp:
			refuse(problem.MCPToolNotAllowed.WithDetail(mcpDetailNotOffered))
			return
		}
		policy, err := s.d.MCPAccess.Policy(r.Context(), p)
		if err != nil {
			// A failed lookup is never "allowed": 500 internal, and no event, since the database is what failed.
			httpx.WriteProblem(w, r, err)
			return
		}
		switch {
		case !policy.Enabled:
			refuse(problem.MCPDisabled)
			return
		case policy.Mode == app.MCPModeSelected && !slices.Contains(policy.AllowedOperations, tool.Name):
			refuse(problem.MCPToolNotAllowed.WithDetail(mcpDetailNotSelected))
			return
		case class == mcpcatalog.ClassWrite && !policy.WriteEnabled:
			refuse(problem.MCPWriteNotEnabled.WithDetail(mcpDetailPolicyNoWrite))
			return
		case class == mcpcatalog.ClassWrite && !p.MCPWriteEnabled:
			refuse(problem.MCPWriteNotEnabled.WithDetail(mcpDetailAccountNoWrite))
			return
		}
		if s.mcpRateLimited(w, r, p, class) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// mcpRateLimited counts the request against the account's budget of the class and answers 429 rate_limited with
// Retry-After once the budget of the current window is spent.
func (s *server) mcpRateLimited(w http.ResponseWriter, r *http.Request, p principal.Principal, class mcpcatalog.Class) bool {
	ok, retryAfter := s.mcpLimit.Allow(p.ID, class)
	if ok {
		metricMCPRequests.WithLabelValues(string(class), "ok").Inc()
		return false
	}
	metricMCPRequests.WithLabelValues(string(class), "rate_limited").Inc()
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retryAfter.Seconds())))))
	s.refuseMCP(w, r, problem.RateLimited)
	return true
}

// refuseMCP answers a refusal of the guard. A privileged route records exactly one event with the refusal's own code
// (a read records none); unlike rejected, the role and step-up checks do not run first, since the guard's decision
// precedes them.
func (s *server) refuseMCP(w http.ResponseWriter, r *http.Request, err error) {
	if scope, spec, ok := privilegedAction(r); ok {
		err = s.d.Runner.RecordRefusal(r.Context(), scope, spec, err)
	}
	httpx.WriteProblem(w, r, err)
}
