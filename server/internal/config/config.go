// Package config reads the configuration of paddock-server from environment variables (plan M0 §6.9).
// Secrets are never read from the environment directly: a *_FILE variable names the file holding the secret.
package config

import (
	"fmt"
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
	return c
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
