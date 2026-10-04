package authflow

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) is defined over HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrAccessDenied means Authentik refused the device approval (application policy).
var ErrAccessDenied = errors.New("authflow: access denied")

// TOTP generates RFC 6238 codes for an authenticator secret and never repeats a time step (Authentik rejects a
// replayed code). The zero value has no secret: the first device login enrolls one.
type TOTP struct {
	mu     sync.Mutex
	Secret string // base32
	last   int64
}

// Code returns the code of the next unused 30 s step, waiting for it if necessary.
func (t *TOTP) Code() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(t.Secret, "=")))
	if err != nil {
		return "", fmt.Errorf("authflow: totp secret: %w", err)
	}
	step := time.Now().Unix() / 30
	if step <= t.last {
		time.Sleep(time.Until(time.Unix((t.last+1)*30+1, 0)))
		step = time.Now().Unix() / 30
	}
	t.last = step
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // positive
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// DeviceAuthorization is the answer of the device authorization endpoint (RFC 8628).
type DeviceAuthorization struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	// VerificationURIComplete is the approval URL with the user code (…/device?code=…), the content of a QR code.
	VerificationURIComplete string `json:"verification_uri_complete"`
	Interval                int    `json:"interval"`
}

// Tokens are the answer of the token endpoint.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// TokenError is an OAuth error of the token endpoint (e.g. invalid_grant, access_denied, expired_token).
type TokenError struct {
	Status int
	Code   string `json:"error"`
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("authflow: token endpoint HTTP %d: %s", e.Status, e.Code)
}

// DeviceScopes are the scopes Himmelblau requests (PoC M1).
const DeviceScopes = "openid profile email offline_access"

// StartDevice requests a device code for the public client clientID at authURL.
func StartDevice(ctx context.Context, client *http.Client, authURL, clientID string) (DeviceAuthorization, error) {
	var out DeviceAuthorization
	_, err := postForm(ctx, client, strings.TrimRight(authURL, "/")+"/application/o/device/",
		url.Values{"client_id": {clientID}, "scope": {DeviceScopes}}, &out)
	if err == nil && (out.DeviceCode == "" || out.VerificationURIComplete == "") {
		err = errors.New("authflow: no device code or no verification_uri_complete")
	}
	return out, err
}

// ApproveDevice approves a device authorization as username in a new browser session, starting at its
// verification_uri_complete (the QR code path): the provider's sign-in flow with password and MFA (enrolling TOTP into
// totp when it has no secret yet) and the device-code confirmation. It returns the stages it passed as
// "<flow slug> <component>", in order. A refusal by the application's policy is ErrAccessDenied.
func ApproveDevice(ctx context.Context, caRoot string, da DeviceAuthorization, username, password string, totp *TOTP) ([]string, error) {
	browser, err := NewClient(caRoot)
	if err != nil {
		return nil, err
	}
	var stages []string
	next := da.VerificationURIComplete
	for hop := 0; hop < 30; hop++ {
		u, err := url.Parse(next)
		if err != nil {
			return stages, err
		}
		if slug, ok := strings.CutPrefix(u.Path, "/if/flow/"); ok {
			done, to, err := runDeviceFlow(ctx, browser, u, strings.TrimSuffix(slug, "/"), username, password, da.UserCode, totp, &stages)
			if err != nil || done {
				return stages, err
			}
			next = to
			continue
		}
		resp, err := get(ctx, browser, next)
		if err != nil {
			return stages, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
		// Signed in, the device page answers instead of redirecting into the authorization: the application's
		// policy refused the user (Authentik's access denied page).
		if resp.StatusCode == http.StatusOK && u.Path == "/device" && hop > 0 {
			return stages, fmt.Errorf("%w: the device page refused the approval", ErrAccessDenied)
		}
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return stages, fmt.Errorf("authflow: GET %s: HTTP %d: %s", next, resp.StatusCode, truncate(body))
		}
		loc, err := resp.Location()
		if err != nil {
			return stages, err
		}
		next = loc.String()
	}
	return stages, errors.New("authflow: too many redirects")
}

// runDeviceFlow runs one flow page; done is true once the device code is confirmed.
func runDeviceFlow(ctx context.Context, client *http.Client, page *url.URL, slug, username, password, userCode string,
	totp *TOTP, stages *[]string) (done bool, next string, err error) {
	exec := &url.URL{Scheme: page.Scheme, Host: page.Host, Path: "/api/v3/flows/executor/" + slug + "/",
		RawQuery: url.Values{"query": {page.RawQuery}}.Encode()}
	ch, err := executor(ctx, client, http.MethodGet, exec, nil)
	if err != nil {
		return false, "", err
	}
	for step := 0; step < 15; step++ {
		trace(slug, ch.Component)
		*stages = append(*stages, slug+" "+ch.Component)
		var answer map[string]any
		switch ch.Component {
		case "xak-flow-redirect":
			to, err := page.Parse(ch.To)
			return false, to.String(), err
		case "ak-stage-access-denied":
			return false, "", fmt.Errorf("%w in flow %s: %s", ErrAccessDenied, slug, ch.Error)
		case "ak-provider-oauth2-device-code-finish":
			return true, "", nil
		case "ak-stage-identification":
			answer = map[string]any{"uid_field": username}
		case "ak-stage-password":
			answer = map[string]any{"password": password}
		case "ak-provider-oauth2-device-code":
			answer = map[string]any{"code": userCode}
		case "ak-stage-consent":
			answer = map[string]any{"token": ch.Token}
		case "ak-stage-authenticator-validate":
			if answer, err = validateAnswer(ch.Raw, totp); err != nil {
				return false, "", err
			}
		case "ak-stage-authenticator-totp":
			if answer, err = enrollTOTP(ch.Raw, totp); err != nil {
				return false, "", err
			}
		default:
			return false, "", fmt.Errorf("authflow: unsupported stage %q in flow %s: %s", ch.Component, slug, truncate(ch.Raw))
		}
		answer["component"] = ch.Component
		if ch, err = executor(ctx, client, http.MethodPost, exec, answer); err != nil {
			return false, "", err
		}
	}
	return false, "", fmt.Errorf("authflow: flow %s did not finish", slug)
}

// validateAnswer answers the MFA stage: the TOTP code, or the choice of the TOTP setup stage when the user has no
// authenticator yet (not_configured_action configure).
func validateAnswer(raw json.RawMessage, totp *TOTP) (map[string]any, error) {
	var ch struct {
		DeviceChallenges []struct {
			DeviceClass string `json:"device_class"`
		} `json:"device_challenges"`
		ConfigurationStages []struct {
			PK        string `json:"pk"`
			MetaModel string `json:"meta_model_name"`
		} `json:"configuration_stages"`
	}
	if err := json.Unmarshal(raw, &ch); err != nil {
		return nil, err
	}
	if len(ch.DeviceChallenges) > 0 {
		code, err := totp.Code()
		return map[string]any{"code": code}, err
	}
	for _, s := range ch.ConfigurationStages {
		if strings.Contains(s.MetaModel, "totp") {
			return map[string]any{"selected_stage": s.PK}, nil
		}
	}
	return nil, fmt.Errorf("authflow: MFA stage without TOTP challenge or setup: %s", truncate(raw))
}

// enrollTOTP takes the secret of the TOTP setup stage and answers with a code.
func enrollTOTP(raw json.RawMessage, totp *TOTP) (map[string]any, error) {
	var ch struct {
		ConfigURL string `json:"config_url"`
	}
	if err := json.Unmarshal(raw, &ch); err != nil {
		return nil, err
	}
	u, err := url.Parse(ch.ConfigURL)
	if err != nil {
		return nil, err
	}
	totp.Secret = u.Query().Get("secret")
	code, err := totp.Code()
	return map[string]any{"code": code}, err
}

// PollDeviceToken redeems an approved device code (polling while the approval is pending, up to timeout).
func PollDeviceToken(ctx context.Context, client *http.Client, authURL, clientID string, da DeviceAuthorization, timeout time.Duration) (Tokens, error) {
	deadline := time.Now().Add(timeout)
	for {
		var out Tokens
		_, err := postForm(ctx, client, strings.TrimRight(authURL, "/")+"/application/o/token/", url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {da.DeviceCode}, "client_id": {clientID},
		}, &out)
		var te *TokenError
		if errors.As(err, &te) && (te.Code == "authorization_pending" || te.Code == "slow_down") && time.Now().Before(deadline) {
			time.Sleep(time.Duration(max(da.Interval, 1)) * time.Second)
			continue
		}
		return out, err
	}
}

// Refresh redeems a refresh token.
func Refresh(ctx context.Context, client *http.Client, authURL, clientID, refreshToken string) (Tokens, error) {
	var out Tokens
	_, err := postForm(ctx, client, strings.TrimRight(authURL, "/")+"/application/o/token/", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {clientID},
	}, &out)
	return out, err
}

// UserInfo returns the userinfo claims of an access token.
func UserInfo(ctx context.Context, client *http.Client, authURL, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(authURL, "/")+"/application/o/userinfo/", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authflow: userinfo HTTP %d: %s", resp.StatusCode, truncate(data))
	}
	var out map[string]any
	return out, json.Unmarshal(data, &out)
}

func postForm(ctx context.Context, client *http.Client, u string, form url.Values, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		te := &TokenError{Status: resp.StatusCode}
		_ = json.Unmarshal(data, te)
		return resp.StatusCode, te
	}
	return resp.StatusCode, json.Unmarshal(data, out)
}

// trace prints the stages of a device approval to stderr when PADDOCK_AUTHFLOW_TRACE is set (diagnosing flows).
func trace(slug, component string) {
	if os.Getenv("PADDOCK_AUTHFLOW_TRACE") != "" {
		fmt.Fprintf(os.Stderr, "authflow: %s %s\n", slug, component)
	}
}
