// Package admin is the admin HTTP surface of the api role: generated admin API (strict server), the portal BFF
// (OIDC login, encrypted session cookie) and the embedded portal (plan M0 §6.6, §6.7).
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// Deps are the dependencies of the admin HTTP surface.
type Deps struct {
	DeviceGroups  *app.DeviceGroups
	Organizations *app.Organizations
	Accounts      *app.Accounts
	AuditLog      *app.AuditLog
	Tokens        *app.EnrollmentTokens
	APITokens     *app.APITokens
	Declarative   *app.Declarative
	Devices       *app.Devices
	Managed       *app.ManagedConfig
	Releases      *app.AgentReleases
	Users         *app.Users
	UserGroups    *app.UserGroups
	Logins        *app.Logins
	LoginSettings *app.LoginSettings
	LoginHistory  *app.LoginHistory
	AgentUpdates  *app.AgentUpdates
	Uninstalls    *app.Uninstalls
	Privileges    *app.Privileges
	Commands      *app.DeviceCommands
	LocalAdmin    *app.LocalAdmin
	Autoinstall   *app.Autoinstall
	Disk          *app.Disk
	Revocations   *app.Revocations
	DMS           *app.DMS
	Inventory     *app.Inventory
	Updates       *app.Updates
	Attention     *app.Attention
	Overview      *app.Overview
	// SecurityReview lists existing data from before the step-up rules (ADR 0034 decision 7).
	SecurityReview *app.SecurityReview
	// IPAllowlist and IPGuard are the IP allow list of the administrative surfaces (plan M7a decisions 12 and 17);
	// a nil IPGuard installs no enforcement (serveAPI always installs one).
	IPAllowlist *app.IPAllowlist
	IPGuard     *IPGuard
	Runner      *app.ActionRunner
	Keys        *Keyring
	OIDC        *OIDC
	StepUp      *OIDC // provider paddock-portal-stepup (plan M4a decision 6)
	// StepUpTokens keeps the raw ID token of every step-up for the escrow-reader (plan M4b.1 decision 7).
	StepUpTokens StepUpTokenStore
	// StepUpAccounts checks the role of a step-up against the session (plan M8s decision 20).
	StepUpAccounts StepUpAccounts
	// Sessions holds the server-side record of every portal session (plan M8s decision 12).
	Sessions SessionStore
	// EndSessions ends every portal session of the installation (plan M8s decision 16).
	EndSessions *app.Sessions
	// AutoUnseal is the automatic unseal of OpenBao (plan M8u decision 7).
	AutoUnseal *app.AutoUnseal
	PublicURL  string
	Static     *StaticHandler // portal build
	Now        func() time.Time
	// StepUpMaxAuthAge replaces the production StepUpMaxAuthAge (development only; zero keeps it).
	StepUpMaxAuthAge time.Duration
	// StepUpMFAClass replaces StepUpWebAuthnClass, the authenticator class a step-up must validate (development only;
	// empty keeps it).
	StepUpMFAClass string
	// ExposeStepUp adds the session's step-up time and the step-up timing to GET /api/v1/me (development only, for
	// the acceptance gates).
	ExposeStepUp bool
	// LoginMFAOptional accepts a portal ID token without a second factor (development only,
	// PADDOCK_LOGIN_MFA_OPTIONAL).
	LoginMFAOptional bool
	// TrustedProxies may name the client through X-Paddock-Client-IP (plan M7a decision 5).
	TrustedProxies []netip.Prefix
}

// privileged maps route patterns of privileged actions to their audit spec, so that requests rejected before
// the use case runs (missing CSRF header, malformed body or parameters) still produce exactly one audit event.
var privileged = map[string]struct {
	scope app.Scope
	spec  app.ActionSpec
}{
	"POST /api/v1/device-groups":                                           {app.ScopeOrg, app.SpecDeviceGroupCreate},
	"PATCH /api/v1/device-groups/{id}":                                     {app.ScopeOrg, app.SpecDeviceGroupUpdate},
	"DELETE /api/v1/device-groups/{id}":                                    {app.ScopeOrg, app.SpecDeviceGroupDelete},
	"POST /api/platform/v1/organizations":                                  {app.ScopePlatform, app.SpecOrganizationCreate},
	"POST /api/platform/v1/sessions/end-all":                               {app.ScopePlatform, app.SpecSessionsEndAll},
	"POST /api/platform/v1/openbao/auto-unseal/enable":                     {app.ScopePlatform, app.SpecAutoUnsealEnable},
	"POST /api/platform/v1/openbao/auto-unseal/disable":                    {app.ScopePlatform, app.SpecAutoUnsealDisable},
	"POST /api/v1/enrollment-tokens":                                       {app.ScopeOrg, app.SpecEnrollmentTokenCreate},
	"PUT /api/v1/devices/{id}/groups":                                      {app.ScopeOrg, app.SpecDeviceSetGroups},
	"PUT /api/v1/devices/{id}/owners":                                      {app.ScopeOrg, app.SpecDeviceSetOwners},
	"POST /api/v1/devices/{id}/update-agent":                               {app.ScopeOrg, app.SpecAgentUpdateRequest},
	"POST /api/v1/devices/{id}/uninstall":                                  {app.ScopeOrg, app.SpecUninstallRequest},
	"POST /api/v1/devices/{id}/uninstall/cancel":                           {app.ScopeOrg, app.SpecUninstallCancel},
	"POST /api/v1/devices/{id}/approve":                                    {app.ScopeOrg, app.SpecDeviceApprove},
	"POST /api/v1/devices/{id}/reject":                                     {app.ScopeOrg, app.SpecDeviceReject},
	"POST /api/v1/devices/{id}/release-quarantine":                         {app.ScopeOrg, app.SpecDeviceReleaseQuarantine},
	"POST /api/v1/devices/{id}/retire":                                     {app.ScopeOrg, app.SpecDeviceRetire},
	"POST /api/v1/enrollment-tokens/{id}/revoke":                           {app.ScopeOrg, app.SpecEnrollmentTokenRevoke},
	"POST /api/v1/api-tokens":                                              {app.ScopeOrg, app.SpecAPITokenCreate},
	"POST /api/v1/api-tokens/{id}/revoke":                                  {app.ScopeOrg, app.SpecAPITokenRevoke},
	"PUT /api/v1/config":                                                   {app.ScopeOrg, app.SpecConfigApply},
	"POST /api/platform/v1/agent-releases":                                 {app.ScopePlatform, app.SpecAgentReleaseCreate},
	"PUT /api/platform/v1/agent-releases/{version}/artifacts/{arch}":       {app.ScopePlatform, app.SpecAgentReleaseUpload},
	"PUT /api/platform/v1/agent-releases/{version}/packages/{name}/{arch}": {app.ScopePlatform, app.SpecAgentReleaseUpload},
	"POST /api/platform/v1/agent-releases/{version}/publish":               {app.ScopePlatform, app.SpecAgentReleasePublish},
	"POST /api/platform/v1/agent-releases/{version}/rollout":               {app.ScopePlatform, app.SpecAgentRolloutStart},
	"POST /api/platform/v1/agent-releases/{version}/rollout/halt":          {app.ScopePlatform, app.SpecAgentRolloutHalt},
	"POST /api/platform/v1/agent-releases/{version}/rollout/resume":        {app.ScopePlatform, app.SpecAgentRolloutResume},
	"POST /api/v1/managed-files":                                           {app.ScopeOrg, app.SpecManagedFileCreate},
	"PATCH /api/v1/managed-files/{id}":                                     {app.ScopeOrg, app.SpecManagedFileUpdate},
	"DELETE /api/v1/managed-files/{id}":                                    {app.ScopeOrg, app.SpecManagedFileDelete},
	"POST /api/v1/managed-files/{id}/confirm-sensitive":                    {app.ScopeOrg, app.SpecManagedFileConfirmSensitive},
	"POST /api/v1/managed-units":                                           {app.ScopeOrg, app.SpecManagedUnitCreate},
	"PATCH /api/v1/managed-units/{id}":                                     {app.ScopeOrg, app.SpecManagedUnitUpdate},
	"DELETE /api/v1/managed-units/{id}":                                    {app.ScopeOrg, app.SpecManagedUnitDelete},
	"PATCH /api/platform/v1/organizations/{id}":                            {app.ScopePlatform, app.SpecOrganizationSetDomains},
	"POST /api/v1/users":                                                   {app.ScopeOrg, app.SpecUserCreate},
	"PATCH /api/v1/users/{id}":                                             {app.ScopeOrg, app.SpecUserUpdate},
	"DELETE /api/v1/users/{id}":                                            {app.ScopeOrg, app.SpecUserDelete},
	"POST /api/v1/users/{id}/lock":                                         {app.ScopeOrg, app.SpecUserLock},
	"POST /api/v1/users/{id}/unlock":                                       {app.ScopeOrg, app.SpecUserUnlock},
	"POST /api/v1/user-groups":                                             {app.ScopeOrg, app.SpecUserGroupCreate},
	"PATCH /api/v1/user-groups/{id}":                                       {app.ScopeOrg, app.SpecUserGroupUpdate},
	"DELETE /api/v1/user-groups/{id}":                                      {app.ScopeOrg, app.SpecUserGroupDelete},
	"POST /api/v1/user-groups/{id}/members":                                {app.ScopeOrg, app.SpecUserGroupMemberAdd},
	"DELETE /api/v1/user-groups/{id}/members/{user_id}":                    {app.ScopeOrg, app.SpecUserGroupMemberRemove},
	"PUT /api/v1/settings/login":                                           {app.ScopeOrg, app.SpecLoginSettingsUpdate},
	"PUT /api/v1/devices/{id}/login-assignment":                            {app.ScopeOrg, app.SpecDeviceSetLoginAssignment},
	"POST /api/v1/devices/{id}/suspend-logins":                             {app.ScopeOrg, app.SpecDeviceSuspendLogins},
	"POST /api/v1/devices/{id}/resume-logins":                              {app.ScopeOrg, app.SpecDeviceResumeLogins},
	"POST /api/v1/permission-profiles":                                     {app.ScopeOrg, app.SpecProfileCreate},
	"PATCH /api/v1/permission-profiles/{id}":                               {app.ScopeOrg, app.SpecProfileUpdate},
	"DELETE /api/v1/permission-profiles/{id}":                              {app.ScopeOrg, app.SpecProfileDelete},
	"POST /api/v1/permission-profiles/{id}/confirm-root-grant":             {app.ScopeOrg, app.SpecProfileConfirmRootGrant},
	"POST /api/v1/profile-assignments":                                     {app.ScopeOrg, app.SpecAssignmentCreate},
	"PATCH /api/v1/profile-assignments/{id}":                               {app.ScopeOrg, app.SpecAssignmentUpdate},
	"DELETE /api/v1/profile-assignments/{id}":                              {app.ScopeOrg, app.SpecAssignmentDelete},
	"POST /api/v1/devices/{id}/local-admin/rotate":                         {app.ScopeOrg, app.SpecLocalAdminRotate},
	"POST /api/v1/devices/{id}/local-admin/reveal":                         {app.ScopeOrg, app.SpecLocalAdminReveal},
	"POST /api/v1/autoinstall":                                             {app.ScopeOrg, app.SpecAutoinstallGenerate},
	"POST /api/v1/devices/{id}/disk/recovery-key":                          {app.ScopeOrg, app.SpecDiskRecoveryKeyReveal},
	"POST /api/v1/devices/{id}/disk/header":                                {app.ScopeOrg, app.SpecDiskHeaderDownload},
	"POST /api/v1/devices/{id}/lock":                                       {app.ScopeOrg, app.SpecRevocationRequest},
	"POST /api/v1/devices/{id}/destroy":                                    {app.ScopeOrg, app.SpecRevocationRequest},
	"POST /api/v1/revocation-requests/{id}/approve":                        {app.ScopeOrg, app.SpecRevocationApprove},
	"POST /api/v1/revocation-requests/{id}/reject":                         {app.ScopeOrg, app.SpecRevocationReject},
	"POST /api/v1/revocation-requests/{id}/cancel":                         {app.ScopeOrg, app.SpecRevocationCancel},
	"PUT /api/v1/settings/dms":                                             {app.ScopeOrg, app.SpecDMSUpdate},
	"PUT /api/v1/settings/managed-files":                                   {app.ScopeOrg, app.SpecManagedFileSettingsChange},
	"PUT /api/v1/settings/updates":                                         {app.ScopeOrg, app.SpecUpdateSettings},
	"POST /api/v1/package-holds":                                           {app.ScopeOrg, app.SpecPackageHoldCreate},
	"PATCH /api/v1/package-holds/{id}":                                     {app.ScopeOrg, app.SpecPackageHoldUpdate},
	"DELETE /api/v1/package-holds/{id}":                                    {app.ScopeOrg, app.SpecPackageHoldDelete},
	"POST /api/v1/devices/{id}/install-now":                                {app.ScopeOrg, app.SpecInstallNow},
	"POST /api/v1/device-groups/{id}/install-now":                          {app.ScopeOrg, app.SpecInstallNow},
	"POST /api/platform/v1/ip-allowlist":                                   {app.ScopePlatform, app.SpecIPAllowlistChange},
	"PATCH /api/platform/v1/ip-allowlist/{id}":                             {app.ScopePlatform, app.SpecIPAllowlistChange},
	"DELETE /api/platform/v1/ip-allowlist/{id}":                            {app.ScopePlatform, app.SpecIPAllowlistChange},
}

// NewHandler builds the complete handler including the shared middleware.
func NewHandler(d Deps) http.Handler {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.StepUpMaxAuthAge == 0 {
		d.StepUpMaxAuthAge = StepUpMaxAuthAge
	}
	if d.StepUpMFAClass == "" {
		d.StepUpMFAClass = StepUpWebAuthnClass
	}
	tokenTTL := app.StepUpValidity
	if d.Runner != nil {
		tokenTTL = d.Runner.StepUpWindow()
	}
	s := &server{d: d, bff: &bff{oidc: d.OIDC, stepUp: d.StepUp, keys: d.Keys, accounts: d.Accounts, now: d.Now,
		maxAuthAge: d.StepUpMaxAuthAge, mfaClass: d.StepUpMFAClass, tokens: d.StepUpTokens, tokenTTL: tokenTTL, sessions: d.Sessions,
		roles: d.StepUpAccounts, loginMFAOptional: d.LoginMFAOptional}}

	api := http.NewServeMux()
	h := &handlers{
		groups: d.DeviceGroups, orgs: d.Organizations, accounts: d.Accounts, audit: d.AuditLog, tokens: d.Tokens,
		devices: d.Devices, managed: d.Managed, releases: d.Releases, users: d.Users, userGroups: d.UserGroups,
		logins: d.Logins, loginSettings: d.LoginSettings, loginHistory: d.LoginHistory, agentUpdates: d.AgentUpdates, uninstalls: d.Uninstalls, privileges: d.Privileges, commands: d.Commands,
		localAdmin: d.LocalAdmin, autoinstall: d.Autoinstall, disk: d.Disk, revocations: d.Revocations, dms: d.DMS,
		inventory: d.Inventory, updates: d.Updates, attention: d.Attention, overview: d.Overview, apiTokens: d.APITokens,
		securityReview: d.SecurityReview,
		declarative:    d.Declarative, ipAllowlist: d.IPAllowlist, now: d.Now, sessions: d.EndSessions,
		autoUnseal:   d.AutoUnseal,
		stepUpWindow: tokenTTL,
	}
	if d.ExposeStepUp {
		h.stepUpTiming = &stepUpTiming{window: d.Runner.StepUpWindow(), maxAuthAge: d.StepUpMaxAuthAge}
	}
	strict := adminapi.NewStrictHandlerWithOptions(h, []adminapi.StrictMiddlewareFunc{uploadDeadlines},
		adminapi.StrictHTTPServerOptions{
			RequestErrorHandlerFunc:  s.rejected,
			ResponseErrorHandlerFunc: httpx.WriteProblem,
		})
	adminapi.HandlerWithOptions(strict, adminapi.StdHTTPServerOptions{
		BaseRouter:       api,
		Middlewares:      []adminapi.MiddlewareFunc{s.csrf, limitBody},
		ErrorHandlerFunc: s.rejected,
	})
	api.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { httpx.WriteProblem(w, r, problem.NotFound) })
	authenticated := s.session(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.ServeHTTP(w, r)
		httpx.NoteRoute(r)
	}))

	root := http.NewServeMux()
	root.HandleFunc("GET /api/auth/login", s.bff.login)
	root.HandleFunc("GET /api/auth/callback", s.bff.callback)
	root.HandleFunc("GET /api/auth/stepup", s.bff.stepUpStart)
	root.HandleFunc("GET /api/auth/stepup/callback", s.bff.stepUpCallback)
	// Outside the session middleware: signing out works while the session store is unreachable (plan M8s decision 15).
	root.Handle("POST /api/auth/logout", noStore(s.csrf(s.bff.logout(d.PublicURL))))
	root.Handle("/api/", noStore(authenticated))
	root.Handle("/", d.Static)

	var guarded http.Handler = root
	if d.IPGuard != nil {
		// Before the static handler, /api/auth/* and the session middleware: a denied request never touches a
		// session, a token or a use case (plan M7a decision 17).
		guarded = d.IPGuard.Middleware(root)
	}
	return httpx.RequestIDMiddleware(httpx.WithClientIP(d.TrustedProxies)(httpx.Recover(httpx.AccessLog(securityHeaders(guarded)))))
}

type server struct {
	d   Deps
	bff *bff
}

// session turns the session cookie, or the API token of an Authorization: Bearer header (bearer.go), into the request
// principal; requests without a valid session or token get 401.
func (s *server) session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secret, ok := bearerSecret(r); ok {
			s.bearer(next, w, r, secret)
			return
		}
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
		if !s.bff.sessionLive(w, r, sess) {
			return
		}
		if reissue {
			sess.Idle = now.Unix()
			remaining := time.Unix(sess.Exp, 0).Sub(now)
			if err := s.d.Sessions.Touch(r.Context(), sess.SID, sess.PID, remaining); err != nil {
				slog.WarnContext(r.Context(), "session record not extended", "error", err)
			}
			if value, err := s.d.Keys.Seal(SessionCookie, sess); err == nil {
				http.SetCookie(w, sessionCookie(value, int(remaining.Seconds())))
			}
		}
		ctx := principal.With(r.Context(), sess.Principal(httpx.ClientIP(r)))
		if s.d.ExposeStepUp {
			ctx = context.WithValue(ctx, stepUpClassesKey{}, sess.StepUpClasses)
		}
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

// maxBodyBytes bounds the body of every admin API request without its own limit (plan M8s decision 32).
const maxBodyBytes = 256 << 10

// artifactUploadPrefix is the path prefix of the agent release uploads, whose handlers bound the body to
// agentrelease.MaxArtifactBytes themselves.
const artifactUploadPrefix = "/api/platform/v1/agent-releases/"

// artifactUploadDeadline is how long an agent release upload may take to read its body and write the answer, in place
// of the server's read and write timeouts (plan M8s decision 33).
const artifactUploadDeadline = 10 * time.Minute

// limitBody bounds request bodies one byte above their limit, so that a larger body is refused while it is read
// (400 invalid_request, audited by rejected) and a body of exactly the limit reaches the use case: PUT /api/v1/config
// at app.MaxDocumentBytes, the artifact uploads not at all, every other request at maxBodyBytes.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/config":
			r.Body = http.MaxBytesReader(w, r.Body, app.MaxDocumentBytes+1)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, artifactUploadPrefix):
		default:
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes+1)
		}
		next.ServeHTTP(w, r)
	})
}

// uploadDeadlines extends the read and write deadlines of the agent release uploads before their handlers read the
// body: a 128 MiB artifact over a slow link takes longer than the server's timeouts allow.
func uploadDeadlines(f adminapi.StrictHandlerFunc, operationID string) adminapi.StrictHandlerFunc {
	if operationID != "UploadAgentArtifact" && operationID != "UploadAgentPackage" {
		return f
	}
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
		rc := http.NewResponseController(w)
		deadline := time.Now().Add(artifactUploadDeadline)
		// A writer without deadline support (HTTP/2 streams, tests) has no connection timeout to extend either.
		_ = rc.SetReadDeadline(deadline)
		_ = rc.SetWriteDeadline(deadline)
		return f(ctx, w, r, request)
	}
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
