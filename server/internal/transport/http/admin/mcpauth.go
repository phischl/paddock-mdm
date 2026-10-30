package admin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/sessions"
)

var metricMCPAuth = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "paddock_mcp_auth_total",
	Help: "Authentications of admin API requests with an MCP access token by result (ok, no_session, invalid, revoked).",
}, []string{"result"})

const (
	// mcpMaxTokenLife refuses an access token that lives longer than the blueprint issues them (30 minutes, plan M14
	// §3.3 item 13), with five minutes for clock skew.
	mcpMaxTokenLife = 35 * time.Minute
	// mcpRefreshLifetime is the refresh token validity of the blueprint paddock-mcp.yaml: a refresh chain, and so the
	// login binding of its renewals, never outlives it (ADR 0044 amendment 2026-10-28).
	mcpRefreshLifetime = 8 * time.Hour
	// mcpSessionBodyBytes bounds the body of POST /api/auth/mcp/session: two JWTs and the role.
	mcpSessionBodyBytes = 64 << 10
	// mcpClockSkew extends the single-use marker of a login token beyond the token's expiry, so that a verifier whose
	// clock lags still finds it.
	mcpClockSkew = time.Minute
	// mcpLoginHint is the detail of mcp_login_required.
	mcpLoginHint = "run paddockctl mcp login"
)

// MCPScopes are the scopes paddockctl requests on the device authorization grant (ADR 0044 amendment A1).
var MCPScopes = []string{"openid", "profile", "email", "groups", "offline_access"}

// MCPSessionStore keeps the MCP session records and the login bindings of their renewals (sessions.Store).
type MCPSessionStore interface {
	SessionStore
	RevokeAccount(ctx context.Context, accountID uuid.UUID) (int, error)
	Bind(ctx context.Context, sub string, authTime int64, b sessions.Binding, ttl time.Duration) (sessions.Binding, error)
	Binding(ctx context.Context, sub string, authTime int64) (b sessions.Binding, gen int64, found bool, err error)
	Unbind(ctx context.Context, sub string, authTime int64, accountID uuid.UUID) error
	CreateMCP(ctx context.Context, sid string, rec sessions.Record, ttl time.Duration, ch sessions.Chain) (sessions.Record, error)
	UseLoginToken(ctx context.Context, identity string, ttl time.Duration) (bool, error)
}

// MCPAuth is the MCP login through Authentik (ADR 0044 amendment 2026-10-25, plan M14 §3.3 items 13 and 14): the
// routes /api/auth/mcp/* and the bearer authentication of MCP access tokens.
type MCPAuth struct {
	oidc     *OIDC // provider paddock-mcp, public client without a secret
	sessions MCPSessionStore
	accounts *app.Accounts
	now      func() time.Time
	// loginMFAOptional accepts an ID token without "mfa" in amr (development only, PADDOCK_LOGIN_MFA_OPTIONAL).
	loginMFAOptional bool
}

// NewMCPAuth creates the MCP login; now nil is time.Now.
func NewMCPAuth(oidc *OIDC, store MCPSessionStore, accounts *app.Accounts, loginMFAOptional bool, now func() time.Time) *MCPAuth {
	if now == nil {
		now = time.Now
	}
	return &MCPAuth{oidc: oidc, sessions: store, accounts: accounts, now: now, loginMFAOptional: loginMFAOptional}
}

// McpLoginConfig is the answer of GET /api/auth/mcp/config (schema McpLoginConfig).
type McpLoginConfig struct {
	Issuer                      string   `json:"issuer"`
	ClientID                    string   `json:"client_id"`
	Scopes                      []string `json:"scopes"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	RevocationEndpoint          string   `json:"revocation_endpoint"`
}

// Config returns the login configuration paddockctl needs; false while the provider is not discovered.
func (m *MCPAuth) Config() (McpLoginConfig, bool) {
	m.oidc.mu.RLock()
	defer m.oidc.mu.RUnlock()
	if m.oidc.oauth == nil {
		return McpLoginConfig{}, false
	}
	return McpLoginConfig{
		Issuer: m.oidc.cfg.Issuer, ClientID: m.oidc.cfg.ClientID, Scopes: MCPScopes,
		DeviceAuthorizationEndpoint: m.oidc.device, TokenEndpoint: m.oidc.oauth.Endpoint.TokenURL,
		RevocationEndpoint: m.oidc.revocation,
	}, true
}

// serveConfig answers GET /api/auth/mcp/config; 404 when the MCP login is not configured.
func (m *MCPAuth) serveConfig(w http.ResponseWriter, r *http.Request) {
	if m == nil {
		httpx.WriteProblem(w, r, problem.NotFound)
		return
	}
	cfg, ok := m.Config()
	if !ok {
		httpx.WriteProblem(w, r, problem.UpstreamUnavailable.WithDetail("identity provider not reachable"))
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

// mcpSessionRequest is the body of POST /api/auth/mcp/session (schema McpSessionInput).
type mcpSessionRequest struct {
	IDToken     string                  `json:"id_token"`
	AccessToken string                  `json:"access_token"`
	Role        organization.RoleChoice `json:"role"`
}

// mcpTokenClaims are the claims of an MCP ID or access token beyond idClaims. RawAMR shadows idClaims.AMR, so that a
// missing claim (a refreshed ID token) differs from an empty one.
type mcpTokenClaims struct {
	idClaims
	AuthTime int64           `json:"auth_time"`
	RawAMR   json.RawMessage `json:"amr"`
	AZP      string          `json:"azp"`
	Scope    string          `json:"scope"`
	JTI      string          `json:"jti"`
	// payload is the verified payload, the identity of a token without jti.
	payload json.RawMessage
}

// loginTokenIdentity is what the single-use marker of a login token keys on: the verified token's identity, never the
// presented string, whose encoding a replay could vary. Authentik 2026.8.5 sets jti in ID tokens (device grant and
// refresh, checked against the dev stack in PDK-436); without one, the verified payload stands for the token.
func loginTokenIdentity(issuer string, c mcpTokenClaims) string {
	if c.JTI != "" {
		return "jti\x00" + issuer + "\x00" + c.Subject + "\x00" + c.JTI
	}
	return "payload\x00" + string(c.payload)
}

// isAccessToken tells an access token from an ID token of the same provider, which share issuer, audience and
// signature: Authentik 2026.8.5 puts azp and scope into access tokens only (both typ JWT; checked against the dev
// stack in PDK-436), so an ID token never serves as a bearer.
func (c mcpTokenClaims) isAccessToken(clientID string) bool {
	return c.AZP == clientID && c.Scope != ""
}

// amr returns the authentication methods; false when the token carries no amr claim.
func (c mcpTokenClaims) amr() ([]string, bool) {
	if len(c.RawAMR) == 0 || string(c.RawAMR) == "null" {
		return nil, false
	}
	var methods []string
	_ = json.Unmarshal(c.RawAMR, &methods)
	return methods, true
}

// errTokenReplayed is the audit error code of a session call with an ID token that was presented before. It wraps
// problem.Forbidden, so that the runner records the refusal as denied.
var errTokenReplayed = fmt.Errorf("%w (%w)", &problem.Error{Code: app.ReasonTokenReplayed, Status: http.StatusUnauthorized},
	problem.Forbidden)

// errBindingMismatch fails a renewal whose account is not the account of its login binding.
var errBindingMismatch = errors.New("admin: renewal of another account than its login binding")

// OpenSession serves POST /api/auth/mcp/session (plan M14 §3.3 item 13, ADR 0044 amendment 2026-10-28): it verifies
// the ID and the access token with the provider's verifier, resolves the role from the ID token's groups as the portal
// login does and opens the MCP session record of the access token. An ID token with amr is a login and must prove the
// second factor; its (sub, auth_time) is bound for renewals. An ID token without amr (Authentik's refreshed ID tokens
// carry none) is a renewal and is accepted only for a live binding of its sub and auth_time.
func (m *MCPAuth) OpenSession(w http.ResponseWriter, r *http.Request) {
	if m == nil {
		httpx.WriteProblem(w, r, problem.NotFound)
		return
	}
	_, verifier, _ := m.oidc.snapshot()
	if verifier == nil {
		httpx.WriteProblem(w, r, problem.UpstreamUnavailable.WithDetail("identity provider not reachable"))
		return
	}
	var req mcpSessionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, mcpSessionBodyBytes)).Decode(&req); err != nil ||
		req.IDToken == "" || req.AccessToken == "" {
		httpx.WriteProblem(w, r, problem.InvalidRequest.WithDetail("id_token and access_token are required"))
		return
	}
	if !isJWT(req.IDToken) || !isJWT(req.AccessToken) {
		httpx.WriteProblem(w, r, problem.InvalidRequest.WithDetail("id_token and access_token must be compact JWTs"))
		return
	}
	switch req.Role {
	case "", organization.ChoiceOrganization, organization.ChoicePlatform:
	default:
		httpx.WriteProblem(w, r, problem.InvalidRequest.WithDetail("role must be platform or organization"))
		return
	}
	ctx := r.Context()
	ip, client := httpx.ClientIP(r), sanitizeMCPClient(r.Header.Get("X-Paddock-MCP-Client"))
	refuse := func(username, reason string, cause, answer error) {
		m.accounts.RecordLoginFailure(ctx, ip, username, reason, principal.ChannelMCP, cause)
		httpx.WriteProblem(w, r, answer)
	}
	now := m.now()

	idt, err := verifier.Verify(ctx, req.IDToken)
	var claims mcpTokenClaims
	if err == nil {
		err = idt.Claims(&claims)
	}
	if err == nil {
		err = idt.Claims(&claims.payload)
	}
	if err != nil || claims.Subject == "" || claims.AuthTime == 0 {
		slog.WarnContext(ctx, "MCP ID token rejected", "error", err)
		refuse("", app.ReasonLoginFailed, errLoginFailed, problem.Unauthenticated)
		return
	}
	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	if claims.isAccessToken(m.oidc.cfg.ClientID) {
		slog.WarnContext(ctx, "MCP access token presented as the ID token")
		refuse(username, app.ReasonLoginFailed, errLoginFailed, problem.Unauthenticated)
		return
	}
	at, err := verifier.Verify(ctx, req.AccessToken)
	var access mcpTokenClaims
	if err == nil {
		err = at.Claims(&access)
	}
	if err == nil && !access.isAccessToken(m.oidc.cfg.ClientID) {
		err = errors.New("not an access token")
	}
	if err != nil {
		slog.WarnContext(ctx, "MCP access token rejected", "error", err)
		refuse(username, app.ReasonLoginFailed, errLoginFailed, problem.Unauthenticated)
		return
	}
	if access.Subject != claims.Subject {
		bad := problem.InvalidRequest.WithDetail("the tokens belong to different subjects")
		refuse(username, app.ReasonLoginFailed, bad, bad)
		return
	}
	remaining := at.Expiry.Sub(now)
	if remaining > mcpMaxTokenLife {
		bad := problem.InvalidRequest.WithDetail("the access token lives longer than an MCP session may")
		refuse(username, app.ReasonLoginFailed, bad, bad)
		return
	}
	// Before any session or binding exists: a token that already opened a session never opens another one.
	first, err := m.sessions.UseLoginToken(ctx, loginTokenIdentity(idt.Issuer, claims), idt.Expiry.Sub(now)+mcpClockSkew)
	if err != nil {
		slog.ErrorContext(ctx, "session store", "error", err)
		refuse(username, app.ReasonLoginFailed, err, problem.SessionStoreUnavailable)
		return
	}
	if !first {
		slog.WarnContext(ctx, "MCP login token replayed")
		refuse(username, app.ReasonTokenReplayed, errTokenReplayed, problem.MCPLoginRequired.WithDetail(mcpLoginHint))
		return
	}
	bindingLeft := time.Unix(claims.AuthTime, 0).Add(mcpRefreshLifetime).Sub(now)
	methods, hasAMR := claims.amr()
	renewal := !hasAMR
	var binding sessions.Binding
	if renewal {
		b, gen, found, err := m.sessions.Binding(ctx, claims.Subject, claims.AuthTime)
		if err != nil {
			slog.ErrorContext(ctx, "session store", "error", err)
			refuse(username, app.ReasonLoginFailed, err, problem.SessionStoreUnavailable)
			return
		}
		if found && b.Gen < gen {
			// End all sessions already invalidated the chain's records; this removes them and the stale binding.
			if err := m.sessions.Unbind(ctx, claims.Subject, claims.AuthTime, b.AccountID); err != nil {
				slog.WarnContext(ctx, "stale MCP login binding not deleted", "error", err)
			}
		}
		if !found || b.Gen < gen || bindingLeft <= 0 {
			refuse(username, app.ReasonMCPLoginRequired, problem.MCPLoginRequired, problem.MCPLoginRequired.WithDetail(mcpLoginHint))
			return
		}
		binding = b
	} else {
		if !m.loginMFAOptional && !slices.Contains(methods, "mfa") {
			slog.WarnContext(ctx, "MCP ID token without a second factor refused")
			refuse(username, app.ReasonMFARequired, errMFARequired, problem.Unauthenticated.WithDetail(app.ReasonMFARequired))
			return
		}
		if bindingLeft <= 0 {
			refuse(username, app.ReasonLoginFailed, errLoginFailed, problem.MCPLoginRequired.WithDetail(mcpLoginHint))
			return
		}
	}

	res := organization.ResolveRole(claims.Groups)
	choice := req.Role
	if choice == "" && len(res.Choices) > 0 {
		choice = organization.ChoiceOrganization
	}
	role := res
	if !res.Denied {
		active, ok := res.Active(choice)
		if !ok {
			active = organization.RoleResolution{Denied: true, Slugs: res.Slugs, Reason: organization.DenialRoleNotGranted}
		}
		role = active
	}
	// A renewal proves only the login it is bound to and that login's role context: a role the refreshed groups
	// change ends the binding and the account's sessions instead of taking effect without a fresh second factor.
	endRenewal := func() {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), discardTimeout)
		defer cancel()
		if _, err := m.sessions.RevokeAccount(dctx, binding.AccountID); err != nil {
			slog.WarnContext(ctx, "sessions of a mismatching MCP renewal not revoked", "error", err)
		}
	}
	if renewal {
		match, err := m.renewalMatches(ctx, binding, role)
		if err != nil {
			slog.ErrorContext(ctx, "MCP renewal role context", "error", err)
			refuse(username, app.ReasonLoginFailed, err, err)
			return
		}
		if !match {
			endRenewal()
			refuse(username, app.ReasonMCPLoginRequired, problem.MCPLoginRequired, problem.MCPLoginRequired.WithDetail(mcpLoginHint))
			return
		}
	}

	sid := mcpSessionID(req.AccessToken)
	var opened uuid.UUID
	bound := false
	openSession := func(ctx context.Context, p principal.Principal) error {
		if renewal && (p.ID != binding.AccountID || string(p.Kind) != binding.Kind || string(p.Role) != binding.Role ||
			p.OrganizationID != binding.Org) {
			return errBindingMismatch
		}
		// Set before the write: a reply lost after Create or Bind wrote still leaves discard something to delete.
		opened = p.ID
		rec, err := m.sessions.CreateMCP(ctx, sid, sessions.Record{AccountID: p.ID, Kind: string(p.Kind), Role: string(p.Role),
			Org: p.OrganizationID, CreatedAt: now.Unix(), Channel: string(principal.ChannelMCP), Display: username,
			Subject: claims.Subject}, remaining,
			sessions.Chain{Sub: claims.Subject, AuthTime: claims.AuthTime, TTL: bindingLeft, Renewal: renewal})
		if err != nil {
			return err
		}
		if renewal {
			// End all sessions between the binding lookup and this record made the binding stale.
			if rec.Gen != binding.Gen {
				return errBindingMismatch
			}
			return nil
		}
		bound = true
		b, err := m.sessions.Bind(ctx, claims.Subject, claims.AuthTime, sessions.Binding{AccountID: p.ID, Kind: string(p.Kind),
			Role: string(p.Role), Org: p.OrganizationID, Client: client}, bindingLeft)
		if err != nil {
			return err
		}
		// End all sessions between the record and the binding left one of them stale.
		if b.Gen != rec.Gen {
			return errBindingMismatch
		}
		return nil
	}
	discard := func() {
		if opened == uuid.Nil {
			return
		}
		// The request may be ending (a client that gave up); the cleanup does not depend on it.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), discardTimeout)
		defer cancel()
		if err := m.sessions.Delete(dctx, sid, opened); err != nil {
			slog.WarnContext(ctx, "MCP session record of a failed login not deleted", "error", err)
		}
		if bound {
			if err := m.sessions.Unbind(dctx, claims.Subject, claims.AuthTime, opened); err != nil {
				slog.WarnContext(ctx, "MCP login binding of a failed login not deleted", "error", err)
			}
		}
	}
	_, err = m.accounts.Login(ctx,
		app.LoginIdentity{Subject: claims.Subject, Username: username, Name: claims.Name, IP: ip, OpenSession: openSession,
			Channel: principal.ChannelMCP, Renewal: renewal},
		app.LoginRole{Platform: role.Platform, Slug: role.Slug, Role: role.Role, Denied: role.Denied, Slugs: role.Slugs,
			DenialReason: string(role.Reason)})
	switch {
	case errors.Is(err, problem.Forbidden):
		discard()
		httpx.WriteProblem(w, r, problem.Forbidden.WithDetail(denialReason(role, err)))
		return
	case errors.Is(err, sessions.ErrNoBinding):
		// A logout or revocation ended the binding during the renewal: it stands, nothing else needs ending.
		discard()
		httpx.WriteProblem(w, r, problem.MCPLoginRequired.WithDetail(mcpLoginHint))
		return
	case errors.Is(err, errBindingMismatch):
		discard()
		if renewal {
			endRenewal()
		}
		httpx.WriteProblem(w, r, problem.MCPLoginRequired.WithDetail(mcpLoginHint))
		return
	case err != nil:
		discard()
		slog.ErrorContext(ctx, "MCP login failed", "error", err)
		httpx.WriteProblem(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// renewalMatches reports whether the role a renewal resolved is the role context of its login binding: the same kind,
// role and organization.
func (m *MCPAuth) renewalMatches(ctx context.Context, b sessions.Binding, role organization.RoleResolution) (bool, error) {
	switch {
	case role.Denied:
		return false, nil
	case role.Platform:
		return b.Kind == string(principal.KindPlatformAdmin) && b.Role == string(principal.RolePlatform) && b.Org == uuid.Nil, nil
	}
	org, err := m.accounts.OrganizationID(ctx, role.Slug)
	if err != nil {
		return false, err
	}
	return b.Kind == string(principal.KindAdmin) && b.Role == string(role.Role) && org != uuid.Nil && b.Org == org, nil
}

// CloseSession serves POST /api/auth/mcp/logout: it deletes the session record of the bearer's access token and the
// login binding of its renewals with every session record of their refresh chain (PDK-468). A token without a record
// is already signed out.
func (m *MCPAuth) CloseSession(w http.ResponseWriter, r *http.Request) {
	if m == nil {
		httpx.WriteProblem(w, r, problem.NotFound)
		return
	}
	token, ok := bearerSecret(r)
	if !ok || !isJWT(token) {
		httpx.WriteProblem(w, r, problem.Unauthenticated)
		return
	}
	claims, err := m.verifyAccess(r.Context(), token)
	if err != nil {
		httpx.WriteProblem(w, r, err)
		return
	}
	ctx := r.Context()
	sid := mcpSessionID(token)
	rec, _, found, err := m.sessions.Get(ctx, sid)
	var account uuid.UUID
	if err == nil && found && rec.Channel == string(principal.ChannelMCP) {
		account = rec.AccountID
		err = m.sessions.Delete(ctx, sid, rec.AccountID)
	}
	if err == nil {
		var b sessions.Binding
		if b, _, found, err = m.sessions.Binding(ctx, claims.Subject, claims.AuthTime); err == nil {
			if found {
				account = b.AccountID
			}
			// Also without a binding: one that expired at auth_time + 8 h leaves the records of its last renewals alive
			// for up to 30 minutes, and the chain's set still names them.
			err = m.sessions.Unbind(ctx, claims.Subject, claims.AuthTime, account)
		}
	}
	if err != nil {
		slog.ErrorContext(ctx, "session store", "error", err)
		httpx.WriteProblem(w, r, problem.SessionStoreUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// verifyAccess verifies an MCP access token (signature via JWKS, issuer, audience, expiry) and returns its claims.
func (m *MCPAuth) verifyAccess(ctx context.Context, token string) (mcpTokenClaims, error) {
	_, verifier, _ := m.oidc.snapshot()
	if verifier == nil {
		return mcpTokenClaims{}, problem.UpstreamUnavailable.WithDetail("identity provider not reachable")
	}
	at, err := verifier.Verify(ctx, token)
	var claims mcpTokenClaims
	if err == nil {
		err = at.Claims(&claims)
	}
	if err != nil || claims.Subject == "" || !claims.isAccessToken(m.oidc.cfg.ClientID) {
		return mcpTokenClaims{}, problem.Unauthenticated
	}
	return claims, nil
}

// Authenticate turns an MCP access token into the request principal (plan M14 §3.3 item 14): the token must verify and
// have a live MCP session record of the current generation, and the account row must still be active with the
// record's role; otherwise every session of the account is revoked.
func (m *MCPAuth) Authenticate(ctx context.Context, accessToken, ip, mcpClient string) (principal.Principal, error) {
	claims, err := m.verifyAccess(ctx, accessToken)
	if err != nil {
		if errors.Is(err, problem.Unauthenticated) {
			metricMCPAuth.WithLabelValues("invalid").Inc()
		}
		return principal.Principal{}, err
	}
	sid := mcpSessionID(accessToken)
	rec, gen, found, err := m.sessions.Get(ctx, sid)
	if err != nil {
		slog.ErrorContext(ctx, "session store", "error", err)
		return principal.Principal{}, problem.SessionStoreUnavailable
	}
	if !found {
		metricMCPAuth.WithLabelValues("no_session").Inc()
		return principal.Principal{}, problem.MCPLoginRequired.WithDetail(mcpLoginHint)
	}
	if rec.Channel != string(principal.ChannelMCP) || rec.Subject != claims.Subject || rec.Gen < gen {
		metricMCPAuth.WithLabelValues("revoked").Inc()
		return principal.Principal{}, problem.Unauthenticated
	}
	p := principal.Principal{
		Kind: principal.Kind(rec.Kind), ID: rec.AccountID, Subject: rec.Subject, Display: rec.Display,
		Role: principal.Role(rec.Role), OrganizationID: rec.Org, IP: ip, SessionID: sid, Channel: principal.ChannelMCP,
		MCPClient: mcpClient,
	}
	st, err := m.accounts.AccountState(ctx, p)
	if err != nil && !errors.Is(err, problem.Unauthenticated) {
		return principal.Principal{}, err
	}
	if err != nil || st.Disabled || st.Role != p.Role {
		metricMCPAuth.WithLabelValues("revoked").Inc()
		if _, err := m.sessions.RevokeAccount(ctx, p.ID); err != nil {
			slog.ErrorContext(ctx, "sessions of a changed account not revoked", "error", err)
			return principal.Principal{}, problem.SessionStoreUnavailable
		}
		return principal.Principal{}, problem.Unauthenticated
	}
	p.MCPWriteEnabled = st.MCPWriteEnabled
	metricMCPAuth.WithLabelValues("ok").Inc()
	return p, nil
}

// mcpBearer authenticates a request with an MCP access token (plan M14 §3.3 item 14).
func (s *server) mcpBearer(next http.Handler, w http.ResponseWriter, r *http.Request, token string) {
	p, err := s.d.MCPAuth.Authenticate(r.Context(), token, httpx.ClientIP(r), sanitizeMCPClient(r.Header.Get("X-Paddock-MCP-Client")))
	if err != nil {
		httpx.WriteProblem(w, r, err)
		return
	}
	next.ServeHTTP(w, r.WithContext(principal.With(r.Context(), p)))
}

// refuseMCPBearer answers 403 to a request with an MCP access token: the step-up works on the cookie session only
// (ADR 0044 amendment A4).
func refuseMCPBearer(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token, ok := bearerSecret(r); ok && isJWT(token) {
			httpx.WriteProblem(w, r, problem.Forbidden.WithDetail("MCP sessions cannot complete a step-up"))
			return
		}
		next(w, r)
	}
}

// mcpSessionID is the session id of an MCP access token: "mcp:" and the hex SHA-256 of the token, so that the token
// itself is never stored.
func mcpSessionID(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return "mcp:" + hex.EncodeToString(sum[:])
}

// isJWT reports whether bearer is a compact JWS in canonical encoding: three non-empty segments of base64url
// characters only that decode strictly (no padding, no line breaks, no stray trailing bits). The JOSE library also
// accepts other encodings of the same token, which would otherwise pass as a different token.
func isJWT(bearer string) bool {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, c := range part {
			if !isBase64URL(c) {
				return false
			}
		}
		if _, err := base64.RawURLEncoding.Strict().DecodeString(part); err != nil {
			return false
		}
	}
	return true
}

// isBase64URL reports whether c belongs to the base64url alphabet (RFC 4648 §5).
func isBase64URL(c rune) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		return true
	}
	return false
}
