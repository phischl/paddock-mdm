package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/notifier"
)

// TestNotifierSettings: defaults, limits, and PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE only in development (plan M9
// decision 20).
func TestNotifierSettings(t *testing.T) {
	base := func(extra map[string]string) map[string]string {
		env := map[string]string{"PADDOCK_PUBLIC_ADMIN_URL": "https://admin.example/"}
		for k, v := range extra {
			env[k] = v
		}
		return env
	}
	load := func(env map[string]string) (notifierSettings, error) {
		l := config.NewLoaderFrom(env)
		common := config.LoadCommon(l)
		s := loadNotifierSettings(l, common)
		return s, l.Err()
	}

	s, err := load(base(nil))
	if err != nil {
		t.Fatal(err)
	}
	if s.engine.PollInterval != 30*time.Second || s.engine.StallAfter != 15*time.Minute || s.engine.Batch != 100 ||
		s.engine.PublicAdminURL != "https://admin.example" || s.allowPrivate {
		t.Errorf("defaults %+v", s)
	}

	s, err = load(base(map[string]string{"PADDOCK_ENV": "development", "PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE": "true",
		"PADDOCK_NOTIFY_POLL_INTERVAL": "5s", "PADDOCK_NOTIFY_STALL_AFTER": "1m", "PADDOCK_NOTIFY_BATCH": "1"}))
	if err != nil || !s.allowPrivate || s.engine.PollInterval != 5*time.Second || s.engine.Batch != 1 {
		t.Errorf("development: %+v, %v", s, err)
	}

	for name, env := range map[string]map[string]string{
		"PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE": {"PADDOCK_ENV": "production", "PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE": "true"},
		"PADDOCK_NOTIFY_POLL_INTERVAL":       {"PADDOCK_NOTIFY_POLL_INTERVAL": "4s"},
		"PADDOCK_NOTIFY_STALL_AFTER":         {"PADDOCK_NOTIFY_STALL_AFTER": "59s"},
		"PADDOCK_NOTIFY_BATCH":               {"PADDOCK_NOTIFY_BATCH": "101"},
		"PADDOCK_PUBLIC_ADMIN_URL":           {"PADDOCK_PUBLIC_ADMIN_URL": ""},
	} {
		if _, err := load(base(env)); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: error %v", name, err)
		}
	}
	if _, err := load(base(map[string]string{"PADDOCK_NOTIFY_BATCH": "0"})); err == nil {
		t.Error("PADDOCK_NOTIFY_BATCH=0 accepted")
	}
}

// TestSMTPSettings: the relay of plan M9 decision 27. Without a host e-mail is off; TLS none only in development and
// never with credentials; the password comes from a file; the sender must be an address.
func TestSMTPSettings(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "smtp_password")
	if err := os.WriteFile(pw, []byte("relay-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	load := func(env map[string]string) (*notifier.EmailConfig, error) {
		env["PADDOCK_PUBLIC_ADMIN_URL"] = "https://admin.example"
		l := config.NewLoaderFrom(env)
		s := loadNotifierSettings(l, config.LoadCommon(l))
		return s.smtp, l.Err()
	}

	if cfg, err := load(map[string]string{}); err != nil || cfg != nil {
		t.Fatalf("without a host: %+v %v", cfg, err)
	}
	cfg, err := load(map[string]string{"PADDOCK_SMTP_HOST": "relay.example", "PADDOCK_SMTP_FROM": "paddock@example.com"})
	if err != nil || cfg == nil || cfg.Port != 587 || cfg.TLS != notifier.SMTPStartTLS || cfg.Timeout != 30*time.Second ||
		cfg.From.Address != "paddock@example.com" || cfg.Username != "" || cfg.RootCAs != nil {
		t.Fatalf("defaults %+v %v", cfg, err)
	}
	cfg, err = load(map[string]string{"PADDOCK_SMTP_HOST": "relay.example", "PADDOCK_SMTP_FROM": "Paddock <paddock@example.com>",
		"PADDOCK_SMTP_TLS": "implicit", "PADDOCK_SMTP_USERNAME": "relay-user", "PADDOCK_SMTP_PASSWORD_FILE": pw,
		"PADDOCK_SMTP_TIMEOUT": "10s"})
	if err != nil || cfg.Port != 465 || cfg.TLS != notifier.SMTPImplicit || cfg.Password != "relay-secret" ||
		cfg.Timeout != 10*time.Second || cfg.From.Name != "Paddock" {
		t.Fatalf("implicit with credentials %+v %v", cfg, err)
	}
	cfg, err = load(map[string]string{"PADDOCK_ENV": "development", "PADDOCK_SMTP_TLS": "none",
		"PADDOCK_SMTP_HOST": "acceptance-host", "PADDOCK_SMTP_PORT": "2525", "PADDOCK_SMTP_FROM": "paddock@paddock.localhost"})
	if err != nil || cfg.TLS != notifier.SMTPNone || cfg.Port != 2525 {
		t.Fatalf("development none %+v %v", cfg, err)
	}

	relay := map[string]string{"PADDOCK_SMTP_HOST": "relay.example", "PADDOCK_SMTP_FROM": "paddock@example.com"}
	with := func(extra map[string]string) map[string]string {
		env := map[string]string{}
		for k, v := range relay {
			env[k] = v
		}
		for k, v := range extra {
			env[k] = v
		}
		return env
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
	}{
		{"PADDOCK_SMTP_TLS", with(map[string]string{"PADDOCK_SMTP_TLS": "none"})},
		{"PADDOCK_SMTP_TLS", map[string]string{"PADDOCK_SMTP_TLS": "none", "PADDOCK_ENV": "production"}},
		{"PADDOCK_SMTP_TLS", with(map[string]string{"PADDOCK_SMTP_TLS": "ssl"})},
		{"PADDOCK_SMTP_USERNAME", with(map[string]string{"PADDOCK_ENV": "development", "PADDOCK_SMTP_TLS": "none",
			"PADDOCK_SMTP_USERNAME": "u", "PADDOCK_SMTP_PASSWORD_FILE": pw})},
		{"PADDOCK_SMTP_PASSWORD_FILE", with(map[string]string{"PADDOCK_SMTP_USERNAME": "u"})},
		{"PADDOCK_SMTP_FROM", map[string]string{"PADDOCK_SMTP_HOST": "relay.example"}},
		{"PADDOCK_SMTP_FROM", with(map[string]string{"PADDOCK_SMTP_FROM": "not an address"})},
		{"PADDOCK_SMTP_PORT", with(map[string]string{"PADDOCK_SMTP_PORT": "70000"})},
		{"PADDOCK_SMTP_TIMEOUT", with(map[string]string{"PADDOCK_SMTP_TIMEOUT": "0s"})},
		{"PADDOCK_SMTP_CA_FILE", with(map[string]string{"PADDOCK_SMTP_CA_FILE": pw})},
	} {
		if _, err := load(tc.env); err == nil || !strings.Contains(err.Error(), tc.name) {
			t.Errorf("%s %v: error %v", tc.name, tc.env, err)
		}
	}
}
