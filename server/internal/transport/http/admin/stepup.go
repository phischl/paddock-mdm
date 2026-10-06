package admin

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Step-up authentication (plan M4a decision 6): a second authorization through the provider paddock-portal-stepup
// with prompt=login, which re-runs its flow paddock-stepup (password and MFA). The callback request comes from
// Authentik, so the SameSite=Strict session cookie is not sent with it: the step-up cookie carries the session it
// started from, and the callback issues that session again with the step-up time.
const (
	StepUpCookie   = "paddock_stepup"
	StepUpLifetime = 10 * time.Minute
	// StepUpMaxAuthAge is the oldest auth_time the callback accepts (Deps.StepUpMaxAuthAge may shorten it in
	// development).
	StepUpMaxAuthAge = 60 * time.Second
)

// stepUpState is the payload of the paddock_stepup cookie.
type stepUpState struct {
	loginState
	Session Session `json:"session"`
}

func stepUpCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: StepUpCookie, Value: value, Path: "/api/auth/stepup", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	}
}

// currentSession returns the valid session of a request.
func (b *bff) currentSession(r *http.Request) (Session, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return Session{}, false
	}
	var sess Session
	if err := b.keys.Open(SessionCookie, c.Value, &sess); err != nil {
		return Session{}, false
	}
	if _, err := sess.Validate(b.now()); err != nil {
		return Session{}, false
	}
	return sess, true
}

// stepUpStart starts the step-up authorization for the current session: PKCE, state and nonce as in login,
// prompt=login and max_age force a fresh authentication, login_hint pre-fills the session's username.
//
// max_age is the maximum auth age (StepUpMaxAuthAge), not 0: Authentik ignores max_age=0, and it honours prompt=login only once per
// login (it remembers the login it forced away, not the one that followed), so a second step-up would get a token
// of the first one. max_age re-authenticates every login older than the callback accepts.
func (b *bff) stepUpStart(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.currentSession(r)
	if !ok {
		httpx.WriteProblem(w, r, problem.Unauthenticated)
		return
	}
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}
	if !ValidReturnTo(returnTo) {
		httpx.WriteProblem(w, r, problem.InvalidRequest.WithDetail("return_to must be a relative path"))
		return
	}
	oauth, _, _ := b.stepUp.snapshot()
	if oauth == nil {
		httpx.WriteProblem(w, r, problem.UpstreamUnavailable.WithDetail("identity provider not reachable"))
		return
	}
	st := stepUpState{loginState: loginState{
		State: randomToken(), Verifier: oauth2.GenerateVerifier(), Nonce: randomToken(), ReturnTo: returnTo,
		Exp: b.now().Add(StepUpLifetime).Unix(),
	}, Session: sess}
	value, err := b.keys.Seal(StepUpCookie, st)
	if err != nil {
		httpx.WriteProblem(w, r, err)
		return
	}
	http.SetCookie(w, stepUpCookie(value, int(StepUpLifetime.Seconds())))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, oauth.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier),
		oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", strconv.Itoa(int(b.maxAuthAge.Seconds()))),
		oauth2.SetAuthURLParam("login_hint", sess.Disp)), http.StatusFound)
}

// StepUpTokenStore keeps the raw ID token of a step-up under its jti for ttl (stepupproof.Store), so that the reveal and
// recovery use cases can pass it to the escrow-reader as proof (plan M4b.1 decision 7).
type StepUpTokenStore interface {
	Put(ctx context.Context, jti, raw string, ttl time.Duration) error
}

type stepUpClaims struct {
	Subject  string   `json:"sub"`
	AuthTime int64    `json:"auth_time"`
	AMR      []string `json:"amr"`
	JTI      string   `json:"jti"`
}

// stepUpCallback completes a step-up: state, code exchange with PKCE, ID token (issuer, audience, nonce, expiry),
// the same subject as the session, auth_time at most the maximum auth age old and MFA in amr. On success the session
// is issued again with stepup_at and stepup_jti; any failure leaves the session as it was and returns to return_to
// with stepup=failed.
func (b *bff) stepUpCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	http.SetCookie(w, stepUpCookie("", -1))
	var st stepUpState
	c, err := r.Cookie(StepUpCookie)
	if err == nil {
		err = b.keys.Open(StepUpCookie, c.Value, &st)
	}
	now := b.now()
	q := r.URL.Query()
	switch {
	case err != nil || st.State == "" || now.Unix() > st.Exp:
		slog.WarnContext(ctx, "step-up callback without valid step-up cookie")
		stepUpFailed(w, r, "/")
		return
	case q.Get("state") != st.State:
		slog.WarnContext(ctx, "step-up callback with mismatching state")
		stepUpFailed(w, r, st.ReturnTo)
		return
	case q.Get("error") != "" || q.Get("code") == "":
		slog.InfoContext(ctx, "step-up aborted at the identity provider", "error", q.Get("error"))
		stepUpFailed(w, r, st.ReturnTo)
		return
	}
	claims, raw, err := b.stepUpToken(r, st)
	if err == nil {
		err = checkStepUp(claims, st.Session, now, b.maxAuthAge)
	}
	if err != nil {
		slog.WarnContext(ctx, "step-up rejected", "error", err, "account_id", st.Session.PID)
		stepUpFailed(w, r, st.ReturnTo)
		return
	}
	sess := st.Session
	if _, err := sess.Validate(now); err != nil {
		slog.InfoContext(ctx, "step-up for a session that ended meanwhile", "account_id", sess.PID)
		stepUpFailed(w, r, st.ReturnTo)
		return
	}
	// Without the stored token the step-up still counts for the api; only decryptions need the escrow-reader's proof.
	if err := b.tokens.Put(ctx, claims.JTI, raw, b.tokenTTL); err != nil {
		slog.ErrorContext(ctx, "keeping the step-up token failed; decryptions will ask for a new step-up", "error", err)
	}
	sess.Idle, sess.StepUpAt, sess.StepUpJTI = now.Unix(), now.Unix(), claims.JTI
	value, err := b.keys.Seal(SessionCookie, sess)
	if err != nil {
		slog.ErrorContext(ctx, "session cookie", "error", err)
		stepUpFailed(w, r, st.ReturnTo)
		return
	}
	http.SetCookie(w, sessionCookie(value, int(time.Unix(sess.Exp, 0).Sub(now).Seconds())))
	slog.InfoContext(ctx, "step-up completed", "account_id", sess.PID)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, st.ReturnTo, http.StatusFound)
}

// stepUpToken exchanges the code and returns the verified claims and the raw ID token.
func (b *bff) stepUpToken(r *http.Request, st stepUpState) (stepUpClaims, string, error) {
	var claims stepUpClaims
	oauth, verifier, _ := b.stepUp.snapshot()
	if oauth == nil {
		return claims, "", errors.New("step-up provider not discovered")
	}
	token, err := oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return claims, "", err
	}
	raw, _ := token.Extra("id_token").(string)
	idt, err := verifier.Verify(r.Context(), raw)
	if err != nil {
		return claims, "", err
	}
	if idt.Nonce != st.Nonce {
		return claims, "", errors.New("nonce mismatch")
	}
	if err := idt.Claims(&claims); err != nil {
		return claims, "", err
	}
	if claims.JTI == "" {
		return claims, "", errors.New("ID token without jti")
	}
	return claims, raw, nil
}

// checkStepUp checks that the step-up authenticated the session's own user just now, with MFA.
func checkStepUp(c stepUpClaims, sess Session, now time.Time, maxAuthAge time.Duration) error {
	if c.Subject == "" || c.Subject != sess.Sub {
		return errors.New("the step-up authenticated another user")
	}
	age := now.Sub(time.Unix(c.AuthTime, 0))
	if c.AuthTime == 0 || age > maxAuthAge || age < -maxAuthAge {
		return errors.New("auth_time missing or not fresh")
	}
	if !slices.Contains(c.AMR, "mfa") {
		return errors.New("the step-up did not use MFA")
	}
	return nil
}

// stepUpFailed returns to returnTo with stepup=failed.
func stepUpFailed(w http.ResponseWriter, r *http.Request, returnTo string) {
	sep := "?"
	if strings.Contains(returnTo, "?") {
		sep = "&"
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, returnTo+sep+url.Values{"stepup": {"failed"}}.Encode(), http.StatusFound)
}
