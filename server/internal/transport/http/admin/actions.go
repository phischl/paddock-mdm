package admin

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/platform/httpx"
	"github.com/paddock-mdm/paddock/server/internal/principal"
	"github.com/paddock-mdm/paddock/server/internal/problem"
)

// actionRoute is one custom-method operation "POST <collection>/{id}:<action>" of the contract. Go's ServeMux
// cannot route a wildcard followed by ":<action>" inside one segment, so these operations are excluded from code
// generation and dispatched by actionHandler with the same CSRF check, rejection auditing and error rendering as
// the generated operations.
type actionRoute struct {
	spec app.ActionSpec
	run  func(ctx context.Context, id uuid.UUID) (any, error)
}

// actionPathValue is the wildcard name of the registered patterns, e.g. "POST /api/v1/devices/{idAction}".
const actionPathValue = "idAction"

func (s *server) actionHandler(routes map[string]actionRoute) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idPart, action, _ := strings.Cut(r.PathValue(actionPathValue), ":")
		route, ok := routes[action]
		if !ok {
			httpx.WriteProblem(w, r, problem.NotFound)
			return
		}
		if r.Header.Get("X-Paddock-CSRF") != "1" {
			s.rejectedAction(w, r, route.spec, problem.CSRFMissing)
			return
		}
		id, err := uuid.Parse(idPart)
		if err != nil {
			s.rejectedAction(w, r, route.spec, problem.InvalidRequest.WithDetail("id must be a UUID"))
			return
		}
		out, err := route.run(r.Context(), id)
		if err != nil {
			httpx.WriteProblem(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})
}

// rejectedAction records a custom-method action rejected before its use case ran (exactly one audit event).
func (s *server) rejectedAction(w http.ResponseWriter, r *http.Request, spec app.ActionSpec, rejection *problem.Error) {
	if _, authenticated := principal.From(r.Context()); authenticated {
		httpx.WriteProblem(w, r, s.d.Runner.RecordRejected(r.Context(), app.ScopeOrg, spec, rejection))
		return
	}
	httpx.WriteProblem(w, r, rejection)
}

// deviceActions are the lifecycle actions of /api/v1/devices/{id}:<action>.
func (s *server) deviceActions(h *handlers) map[string]actionRoute {
	transition := func(fn func(context.Context, uuid.UUID) error) func(context.Context, uuid.UUID) (any, error) {
		return func(ctx context.Context, id uuid.UUID) (any, error) {
			if err := fn(ctx, id); err != nil {
				return nil, err
			}
			d, err := h.devices.Get(ctx, id)
			if err != nil {
				return nil, err
			}
			return toDevice(d.Device, d.Status), nil
		}
	}
	return map[string]actionRoute{
		"approve": {app.SpecDeviceApprove, transition(func(ctx context.Context, id uuid.UUID) error {
			_, err := h.devices.Approve(ctx, id)
			return err
		})},
		"reject": {app.SpecDeviceReject, transition(func(ctx context.Context, id uuid.UUID) error {
			_, err := h.devices.Reject(ctx, id)
			return err
		})},
		"release-quarantine": {app.SpecDeviceReleaseQuarantine, transition(func(ctx context.Context, id uuid.UUID) error {
			_, err := h.devices.ReleaseQuarantine(ctx, id)
			return err
		})},
		"retire": {app.SpecDeviceRetire, transition(func(ctx context.Context, id uuid.UUID) error {
			_, err := h.devices.Retire(ctx, id)
			return err
		})},
	}
}

// tokenActions are the actions of /api/v1/enrollment-tokens/{id}:<action>.
func (s *server) tokenActions(h *handlers) map[string]actionRoute {
	return map[string]actionRoute{
		"revoke": {app.SpecEnrollmentTokenRevoke, func(ctx context.Context, id uuid.UUID) (any, error) {
			t, err := h.tokens.Revoke(ctx, id)
			if err != nil {
				return nil, err
			}
			return toEnrollmentToken(t, h.now()), nil
		}},
	}
}
