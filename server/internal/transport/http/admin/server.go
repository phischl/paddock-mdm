// Package admin is the admin HTTP surface of the api role: generated admin API (strict server), the portal BFF
// (OIDC login, encrypted session cookie) and the embedded portal (plan M0 §6.6, §6.7).
package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/platform/httpx"
	"github.com/paddock-mdm/paddock/server/internal/principal"
	"github.com/paddock-mdm/paddock/server/internal/problem"
	"github.com/paddock-mdm/paddock/server/internal/transport/http/admin/adminapi"
)

// Deps are the dependencies of the admin HTTP surface.
type Deps struct {
	DeviceGroups  *app.DeviceGroups
	Organizations *app.Organizations
	Accounts      *app.Accounts
	AuditLog      *app.AuditLog
	Tokens        *app.EnrollmentTokens
	Devices       *app.Devices
	Managed       *app.ManagedConfig
	Runner        *app.ActionRunner
	Keys          *Keyring
	OIDC          *OIDC
	PublicURL     string
	Static        *StaticHandler // portal build
	Now           func() time.Time
}

// privileged maps route patterns of privileged actions to their audit spec, so that requests rejected before
// the use case runs (missing CSRF header, malformed body or parameters) still produce exactly one audit event.
var privileged = map[string]struct {
	scope app.Scope
	spec  app.ActionSpec
}{
	"POST /api/v1/device-groups":          {app.ScopeOrg, app.SpecDeviceGroupCreate},
	"PATCH /api/v1/device-groups/{id}":    {app.ScopeOrg, app.SpecDeviceGroupUpdate},
	"DELETE /api/v1/device-groups/{id}":   {app.ScopeOrg, app.SpecDeviceGroupDelete},
	"POST /api/platform/v1/organizations": {app.ScopePlatform, app.SpecOrganizationCreate},
	"POST /api/v1/enrollment-tokens":      {app.ScopeOrg, app.SpecEnrollmentTokenCreate},
	"PUT /api/v1/devices/{id}/groups":     {app.ScopeOrg, app.SpecDeviceSetGroups},
	"POST /api/v1/managed-files":          {app.ScopeOrg, app.SpecManagedFileCreate},
	"PATCH /api/v1/managed-files/{id}":    {app.ScopeOrg, app.SpecManagedFileUpdate},
	"DELETE /api/v1/managed-files/{id}":   {app.ScopeOrg, app.SpecManagedFileDelete},
	"POST /api/v1/managed-units":          {app.ScopeOrg, app.SpecManagedUnitCreate},
	"PATCH /api/v1/managed-units/{id}":    {app.ScopeOrg, app.SpecManagedUnitUpdate},
	"DELETE /api/v1/managed-units/{id}":   {app.ScopeOrg, app.SpecManagedUnitDelete},
}

// NewHandler builds the complete handler including the shared middleware.
func NewHandler(d Deps) http.Handler {
	if d.Now == nil {
		d.Now = time.Now
	}
	s := &server{d: d, bff: &bff{oidc: d.OIDC, keys: d.Keys, accounts: d.Accounts, now: d.Now}}

	api := http.NewServeMux()
	h := &handlers{
		groups: d.DeviceGroups, orgs: d.Organizations, accounts: d.Accounts, audit: d.AuditLog, tokens: d.Tokens,
		devices: d.Devices, managed: d.Managed, now: d.Now,
	}
	strict := adminapi.NewStrictHandlerWithOptions(h, nil,
		adminapi.StrictHTTPServerOptions{
			RequestErrorHandlerFunc:  s.rejected,
			ResponseErrorHandlerFunc: httpx.WriteProblem,
		})
	adminapi.HandlerWithOptions(strict, adminapi.StdHTTPServerOptions{
		BaseRouter:       api,
		Middlewares:      []adminapi.MiddlewareFunc{s.csrf},
		ErrorHandlerFunc: s.rejected,
	})
	api.Handle("POST /api/v1/devices/{"+actionPathValue+"}", s.actionHandler(s.deviceActions(h)))
	api.Handle("POST /api/v1/enrollment-tokens/{"+actionPathValue+"}", s.actionHandler(s.tokenActions(h)))
	api.Handle("POST /api/auth/logout", s.csrf(s.bff.logout(d.PublicURL)))
	api.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { httpx.WriteProblem(w, r, problem.NotFound) })
	authenticated := s.session(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.ServeHTTP(w, r)
		httpx.NoteRoute(r)
	}))

	root := http.NewServeMux()
	root.HandleFunc("GET /api/auth/login", s.bff.login)
	root.HandleFunc("GET /api/auth/callback", s.bff.callback)
	root.Handle("/api/", noStore(authenticated))
	root.Handle("/", d.Static)

	return httpx.RequestIDMiddleware(httpx.Recover(httpx.AccessLog(securityHeaders(root))))
}

type server struct {
	d   Deps
	bff *bff
}

// session turns the session cookie into the request principal; requests without a valid session get 401.
func (s *server) session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(SessionCookie)
		if err != nil {
			httpx.WriteProblem(w, r, problem.Unauthenticated)
			return
		}
		var sess Session
		now := s.d.Now()
		if err := s.d.Keys.Open(SessionCookie, c.Value, &sess); err != nil {
			http.SetCookie(w, sessionCookie("", -1))
			httpx.WriteProblem(w, r, problem.Unauthenticated)
			return
		}
		reissue, err := sess.Validate(now)
		if err != nil {
			http.SetCookie(w, sessionCookie("", -1))
			httpx.WriteProblem(w, r, problem.Unauthenticated)
			return
		}
		if reissue {
			sess.Idle = now.Unix()
			if value, err := s.d.Keys.Seal(SessionCookie, sess); err == nil {
				http.SetCookie(w, sessionCookie(value, int(time.Until(time.Unix(sess.Exp, 0)).Seconds())))
			}
		}
		ctx := principal.With(r.Context(), sess.Principal(httpx.ClientIP(r)))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// csrf requires X-Paddock-CSRF: 1 on mutating requests (403 csrf_missing).
func (s *server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if r.Header.Get("X-Paddock-CSRF") != "1" {
				s.rejected(w, r, problem.CSRFMissing)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// rejected answers a request rejected before its handler ran. Rejected privileged actions are audited.
func (s *server) rejected(w http.ResponseWriter, r *http.Request, err error) {
	var p *problem.Error
	var missingHeader *adminapi.RequiredHeaderError
	switch {
	case errors.As(err, &p):
	case errors.As(err, &missingHeader) && strings.EqualFold(missingHeader.ParamName, "X-Paddock-CSRF"):
		// The generated binder checks the declared header before the csrf middleware runs.
		p = problem.CSRFMissing
	default:
		p = problem.InvalidRequest.WithDetail(err.Error())
	}
	if op, ok := privileged[r.Pattern]; ok {
		if _, authenticated := principal.From(r.Context()); authenticated {
			err := s.d.Runner.RecordRejected(r.Context(), op.scope, op.spec, p)
			httpx.WriteProblem(w, r, err)
			return
		}
	}
	httpx.WriteProblem(w, r, p)
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// cspCommon are the CSP directives shared by every response.
const cspCommon = "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// securityHeaders sets the strict CSP and related headers on every response (architecture §18). The portal's
// index.html replaces the CSP with one that adds a style nonce (StaticHandler.ServeIndex).
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; "+cspCommon)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
