// Package config reads the configuration of paddock-server from environment variables (plan M0 §6.9).
// Secrets are never read from the environment directly: a *_FILE variable names the file holding the secret.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// MissingError lists every required variable that is not set.
type MissingError struct{ Names []string }

func (e *MissingError) Error() string {
	return "missing required environment variables: " + strings.Join(e.Names, ", ")
}

// Loader collects values and all problems, so one run reports every missing variable at once.
type Loader struct {
	lookup  func(string) (string, bool)
	missing []string
	errs    []string
}

// NewLoader reads from the process environment.
func NewLoader() *Loader { return &Loader{lookup: os.LookupEnv} }

// NewLoaderFrom reads from the given map (tests).
func NewLoaderFrom(env map[string]string) *Loader {
	return &Loader{lookup: func(k string) (string, bool) { v, ok := env[k]; return v, ok && v != "" }}
}

func (l *Loader) get(name string) (string, bool) {
	v, ok := l.lookup(name)
	if !ok || strings.TrimSpace(v) == "" {
		return "", false
	}
	return strings.TrimSpace(v), true
}

// String returns the variable or def.
func (l *Loader) String(name, def string) string {
	if v, ok := l.get(name); ok {
		return v
	}
	return def
}

// Required returns the variable and records it as missing when unset.
func (l *Loader) Required(name string) string {
	v, ok := l.get(name)
	if !ok {
		l.missing = append(l.missing, name)
	}
	return v
}

// SecretFile reads the file named by the *_FILE variable name. Missing variable and unreadable file are recorded.
func (l *Loader) SecretFile(name string) string {
	path := l.Required(name)
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path) //nolint:gosec // the path is operator configuration
	if err != nil {
		l.errs = append(l.errs, fmt.Sprintf("%s: %v", name, err))
		return ""
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		l.errs = append(l.errs, fmt.Sprintf("%s: file %s is empty", name, path))
	}
	return v
}

// Int returns the integer variable or def.
func (l *Loader) Int(name string, def int) int {
	v, ok := l.get(name)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		l.errs = append(l.errs, fmt.Sprintf("%s: not an integer: %q", name, v))
		return def
	}
	return n
}

// Bool returns the boolean variable ("true" or "false") or def.
func (l *Loader) Bool(name string, def bool) bool {
	v, ok := l.get(name)
	if !ok {
		return def
	}
	switch v {
	case "true":
		return true
	case "false":
		return false
	}
	l.errs = append(l.errs, fmt.Sprintf("%s: not true or false: %q", name, v))
	return def
}

// RevocationEnabled reads the feature flag PADDOCK_REVOCATION_ENABLED (default false; plan M4c decision 1). The
// revocation path stays disabled until its second-person review and the hardware acceptance protocol have passed;
// only development and test configurations enable it.
func RevocationEnabled(l *Loader) bool { return l.Bool("PADDOCK_REVOCATION_ENABLED", false) }

// Duration returns the duration variable or def.
func (l *Loader) Duration(name string, def time.Duration) time.Duration {
	v, ok := l.get(name)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		l.errs = append(l.errs, fmt.Sprintf("%s: not a duration: %q", name, v))
		return def
	}
	return d
}

// Invalid records a validation problem of an already loaded value.
func (l *Loader) Invalid(name, reason string) {
	l.errs = append(l.errs, fmt.Sprintf("%s: %s", name, reason))
}

// Err returns a *MissingError when required variables are missing, otherwise an error for invalid values.
func (l *Loader) Err() error {
	if len(l.missing) > 0 {
		return &MissingError{Names: l.missing}
	}
	if len(l.errs) > 0 {
		return fmt.Errorf("invalid configuration: %s", strings.Join(l.errs, "; "))
	}
	return nil
}

// Common is shared by all roles.
type Common struct {
	Env      string // production | development
	LogLevel string
	OpsAddr  string
	// TrustedProxies are the peers whose X-Paddock-Client-IP header names the client (plan M7a decision 4); empty
	// trusts no peer.
	TrustedProxies []netip.Prefix
}

// Development reports whether development-only behaviour may be enabled.
func (c Common) Development() bool { return c.Env == "development" }

// LoadCommon reads the variables every role uses.
func LoadCommon(l *Loader) Common {
	c := Common{
		Env:      l.String("PADDOCK_ENV", "production"),
		LogLevel: l.String("PADDOCK_LOG_LEVEL", "info"),
		OpsAddr:  l.String("PADDOCK_OPS_ADDR", ":9090"),
	}
	if c.Env != "production" && c.Env != "development" {
		l.Invalid("PADDOCK_ENV", "must be production or development")
	}
	c.TrustedProxies = trustedProxies(l)
	return c
}

// trustedProxies parses PADDOCK_TRUSTED_PROXY_CIDRS (space-separated CIDRs). A /0 is refused: it would let every
// peer choose its own client address.
func trustedProxies(l *Loader) []netip.Prefix {
	const name = "PADDOCK_TRUSTED_PROXY_CIDRS"
	v, ok := l.get(name)
	if !ok {
		return nil
	}
	var out []netip.Prefix
	for _, f := range strings.Fields(v) {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			l.Invalid(name, fmt.Sprintf("not a CIDR: %q", f))
			continue
		}
		if p.Bits() == 0 {
			l.Invalid(name, fmt.Sprintf("%s trusts every address", f))
			continue
		}
		out = append(out, p.Masked())
	}
	return out
}

// DevStepUp shortens the step-up timing for the acceptance gates (PADDOCK_STEPUP_WINDOW: how long a step-up
// satisfies a privileged action; PADDOCK_STEPUP_MAX_AUTH_AGE: the oldest login a step-up callback accepts, sent as
// max_age). Zero keeps the production value. Either variable outside PADDOCK_ENV=development is a configuration
// error, so production never runs with a shortened step-up.
type DevStepUp struct {
	Window     time.Duration
	MaxAuthAge time.Duration
}

// LoadDevStepUp reads PADDOCK_STEPUP_WINDOW and PADDOCK_STEPUP_MAX_AUTH_AGE.
func LoadDevStepUp(l *Loader, c Common) DevStepUp {
	var d DevStepUp
	for name, dst := range map[string]*time.Duration{"PADDOCK_STEPUP_WINDOW": &d.Window, "PADDOCK_STEPUP_MAX_AUTH_AGE": &d.MaxAuthAge} {
		v, ok := l.get(name)
		if !ok {
			continue
		}
		if !c.Development() {
			l.Invalid(name, "only allowed with PADDOCK_ENV=development")
			continue
		}
		if parsed, err := time.ParseDuration(v); err != nil || parsed <= 0 {
			l.Invalid(name, fmt.Sprintf("not a positive duration: %q", v))
		} else {
			*dst = parsed
		}
	}
	return d
}

// LoadDevLoginMFAOptional reads PADDOCK_LOGIN_MFA_OPTIONAL: true lets a portal sign-in without a second factor pass,
// so that the development users without an authenticator can sign in (plan M8x decision 3). Any value outside
// PADDOCK_ENV=development is a configuration error, so production always requires the second factor.
func LoadDevLoginMFAOptional(l *Loader, c Common) bool {
	const name = "PADDOCK_LOGIN_MFA_OPTIONAL"
	v, ok := l.get(name)
	switch {
	case !ok:
		return false
	case !c.Development():
		l.Invalid(name, "only allowed with PADDOCK_ENV=development")
	case v == "true":
		return true
	case v != "false":
		l.Invalid(name, fmt.Sprintf("not true or false: %q", v))
	}
	return false
}

// StalenessUnit reads PADDOCK_STALENESS_UNIT, the unit of the organizations' staleness thresholds (plan M5b decision
// 9): "hour" (default) or, with PADDOCK_ENV=development only, "minute" for the acceptance gate U4.
func StalenessUnit(l *Loader, c Common) time.Duration {
	v, ok := l.get("PADDOCK_STALENESS_UNIT")
	switch {
	case !ok || v == "hour":
		return time.Hour
	case v != "minute":
		l.Invalid("PADDOCK_STALENESS_UNIT", fmt.Sprintf("not hour or minute: %q", v))
	case !c.Development():
		l.Invalid("PADDOCK_STALENESS_UNIT", "minute is only allowed with PADDOCK_ENV=development")
	default:
		return time.Minute
	}
	return time.Hour
}

// RetentionUnit reads PADDOCK_RETENTION_UNIT, the length of a "day" of the retention periods (plan M10 decision 14,
// plan M8d decision 19): "days" (default) or, with PADDOCK_ENV=development only, "seconds" for the acceptance gates.
func RetentionUnit(l *Loader, c Common) time.Duration {
	v, ok := l.get("PADDOCK_RETENTION_UNIT")
	switch {
	case !ok || v == "days":
		return 24 * time.Hour
	case v != "seconds":
		l.Invalid("PADDOCK_RETENTION_UNIT", fmt.Sprintf("not days or seconds: %q", v))
	case !c.Development():
		l.Invalid("PADDOCK_RETENTION_UNIT", "seconds is only allowed with PADDOCK_ENV=development")
	default:
		return time.Second
	}
	return 24 * time.Hour
}

// AMQP is the RabbitMQ connection of relay, audit-writer and provision.
type AMQP struct {
	URL      string
	User     string
	Password string
}

// LoadAMQP reads PADDOCK_AMQP_*.
func LoadAMQP(l *Loader) AMQP {
	return AMQP{
		URL:      l.Required("PADDOCK_AMQP_URL"),
		User:     l.Required("PADDOCK_AMQP_USER"),
		Password: l.SecretFile("PADDOCK_AMQP_PASSWORD_FILE"),
	}
}

// OpenBao is the AppRole login of api and audit-writer.
type OpenBao struct {
	Addr     string
	RoleID   string
	SecretID string
}

// LoadOpenBao reads PADDOCK_OPENBAO_*.
func LoadOpenBao(l *Loader) OpenBao {
	return OpenBao{
		Addr:     l.Required("PADDOCK_OPENBAO_ADDR"),
		RoleID:   l.SecretFile("PADDOCK_OPENBAO_ROLE_ID_FILE"),
		SecretID: l.SecretFile("PADDOCK_OPENBAO_SECRET_ID_FILE"),
	}
}

// LoadOpenBaoAddr reads PADDOCK_OPENBAO_ADDR only (roles without an AppRole: the unsealer).
func LoadOpenBaoAddr(l *Loader) string {
	return l.Required("PADDOCK_OPENBAO_ADDR")
}

// Valkey is the Valkey connection of gateway, worker and compiler.
type Valkey struct {
	Addr     string
	Password string
}

// LoadValkey reads PADDOCK_VALKEY_*.
func LoadValkey(l *Loader) Valkey {
	return Valkey{
		Addr:     l.Required("PADDOCK_VALKEY_ADDR"),
		Password: l.SecretFile("PADDOCK_VALKEY_PASSWORD_FILE"),
	}
}
