package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestLoadOpenBaoAddr reads the address only: no AppRole file is required (plan M8u decision 9).
func TestLoadOpenBaoAddr(t *testing.T) {
	l := NewLoaderFrom(map[string]string{"PADDOCK_OPENBAO_ADDR": "https://openbao:8200"})
	if got := LoadOpenBaoAddr(l); got != "https://openbao:8200" || l.Err() != nil {
		t.Fatalf("LoadOpenBaoAddr = %q, err %v", got, l.Err())
	}
	l = NewLoaderFrom(map[string]string{})
	_ = LoadOpenBaoAddr(l)
	var missing *MissingError
	if !errors.As(l.Err(), &missing) || !reflect.DeepEqual(missing.Names, []string{"PADDOCK_OPENBAO_ADDR"}) {
		t.Fatalf("Err() = %v, want PADDOCK_OPENBAO_ADDR missing", l.Err())
	}
}

func TestMissingVariablesAreReportedTogether(t *testing.T) {
	l := NewLoaderFrom(map[string]string{"PADDOCK_AMQP_URL": "amqp://x"})
	_ = LoadAMQP(l)
	_ = l.SecretFile("PADDOCK_DB_URL_FILE")
	var missing *MissingError
	if !errors.As(l.Err(), &missing) {
		t.Fatalf("Err() = %v, want *MissingError", l.Err())
	}
	want := []string{"PADDOCK_AMQP_USER", "PADDOCK_AMQP_PASSWORD_FILE", "PADDOCK_DB_URL_FILE"}
	if !reflect.DeepEqual(missing.Names, want) {
		t.Fatalf("missing = %v, want %v", missing.Names, want)
	}
}

func TestSecretFileIsTrimmed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("  s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLoaderFrom(map[string]string{"X_FILE": path})
	if got := l.SecretFile("X_FILE"); got != "s3cret" {
		t.Fatalf("SecretFile = %q", got)
	}
	if err := l.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidEnv(t *testing.T) {
	l := NewLoaderFrom(map[string]string{"PADDOCK_ENV": "staging"})
	LoadCommon(l)
	if l.Err() == nil {
		t.Fatal("PADDOCK_ENV=staging accepted")
	}
}

// TestDevStepUp: the step-up timing can be shortened in development only; in production setting either variable
// fails the start.
func TestDevStepUp(t *testing.T) {
	both := map[string]string{"PADDOCK_STEPUP_WINDOW": "30s", "PADDOCK_STEPUP_MAX_AUTH_AGE": "15s"}

	l := NewLoaderFrom(both)
	if d := LoadDevStepUp(l, Common{Env: "development"}); d != (DevStepUp{Window: 30 * time.Second, MaxAuthAge: 15 * time.Second}) || l.Err() != nil {
		t.Fatalf("development: %+v, %v", d, l.Err())
	}
	l = NewLoaderFrom(nil)
	if d := LoadDevStepUp(l, Common{Env: "development"}); d != (DevStepUp{}) || l.Err() != nil {
		t.Fatalf("unset: %+v, %v", d, l.Err())
	}
	for name := range both {
		l = NewLoaderFrom(map[string]string{name: "30s"})
		if d := LoadDevStepUp(l, Common{Env: "production"}); d != (DevStepUp{}) || l.Err() == nil ||
			!strings.Contains(l.Err().Error(), name+": only allowed with PADDOCK_ENV=development") {
			t.Fatalf("production with %s: %+v, %v", name, d, l.Err())
		}
	}
	for _, v := range []string{"0s", "-5s", "soon"} {
		l = NewLoaderFrom(map[string]string{"PADDOCK_STEPUP_WINDOW": v})
		if d := LoadDevStepUp(l, Common{Env: "development"}); d.Window != 0 || l.Err() == nil {
			t.Fatalf("window %q: %+v, %v", v, d, l.Err())
		}
	}
}

// TestDevLoginMFAOptional: the portal second factor can be made optional in development only; in production the
// variable fails the start whatever its value.
func TestDevLoginMFAOptional(t *testing.T) {
	const name = "PADDOCK_LOGIN_MFA_OPTIONAL"
	for v, want := range map[string]bool{"true": true, "false": false} {
		l := NewLoaderFrom(map[string]string{name: v})
		if got := LoadDevLoginMFAOptional(l, Common{Env: "development"}); got != want || l.Err() != nil {
			t.Fatalf("development %q: %v, %v", v, got, l.Err())
		}
	}
	l := NewLoaderFrom(nil)
	if LoadDevLoginMFAOptional(l, Common{Env: "production"}) || l.Err() != nil {
		t.Fatalf("unset: %v", l.Err())
	}
	for _, v := range []string{"true", "false"} {
		l = NewLoaderFrom(map[string]string{name: v})
		if LoadDevLoginMFAOptional(l, Common{Env: "production"}) || l.Err() == nil ||
			!strings.Contains(l.Err().Error(), name+": only allowed with PADDOCK_ENV=development") {
			t.Fatalf("production %q: %v", v, l.Err())
		}
	}
	l = NewLoaderFrom(map[string]string{name: "yes"})
	if LoadDevLoginMFAOptional(l, Common{Env: "development"}) || l.Err() == nil {
		t.Fatal("development \"yes\" accepted")
	}
}

// TestRevocationEnabled: the revocation feature flag is off unless set to true; anything but true or false fails the
// start (plan M4c decision 1).
func TestRevocationEnabled(t *testing.T) {
	cases := map[string]struct {
		env     map[string]string
		want    bool
		invalid bool
	}{
		"unset": {env: nil, want: false},
		"true":  {env: map[string]string{"PADDOCK_REVOCATION_ENABLED": "true"}, want: true},
		"false": {env: map[string]string{"PADDOCK_REVOCATION_ENABLED": "false"}, want: false},
		"1":     {env: map[string]string{"PADDOCK_REVOCATION_ENABLED": "1"}, invalid: true},
		"yes":   {env: map[string]string{"PADDOCK_REVOCATION_ENABLED": "yes"}, invalid: true},
	}
	for name, c := range cases {
		l := NewLoaderFrom(c.env)
		if got := RevocationEnabled(l); got != c.want || (l.Err() != nil) != c.invalid {
			t.Errorf("%s: %v, %v", name, got, l.Err())
		}
	}
}

// TestStalenessUnit: thresholds count hours; minutes only in development (plan M5b decision 9).
func TestStalenessUnit(t *testing.T) {
	for _, tc := range []struct {
		env, value string
		want       time.Duration
		fails      bool
	}{
		{"production", "", time.Hour, false},
		{"production", "hour", time.Hour, false},
		{"development", "minute", time.Minute, false},
		{"production", "minute", time.Hour, true},
		{"development", "second", time.Hour, true},
	} {
		vars := map[string]string{}
		if tc.value != "" {
			vars["PADDOCK_STALENESS_UNIT"] = tc.value
		}
		l := NewLoaderFrom(vars)
		if got := StalenessUnit(l, Common{Env: tc.env}); got != tc.want || (l.Err() != nil) != tc.fails {
			t.Errorf("%s %q: %s, %v", tc.env, tc.value, got, l.Err())
		}
	}
}

// TestTrustedProxies: PADDOCK_TRUSTED_PROXY_CIDRS is a space-separated CIDR list; unset trusts nobody, unparsable
// entries and any /0 fail the start (plan M7a decision 4).
func TestTrustedProxies(t *testing.T) {
	c := LoadCommon(NewLoaderFrom(map[string]string{}))
	if len(c.TrustedProxies) != 0 {
		t.Fatalf("unset: %v", c.TrustedProxies)
	}
	l := NewLoaderFrom(map[string]string{"PADDOCK_TRUSTED_PROXY_CIDRS": " 10.0.0.0/8  fc00::/7 172.16.0.1/12 "})
	c = LoadCommon(l)
	if err := l.Err(); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(c.TrustedProxies); got != "[10.0.0.0/8 fc00::/7 172.16.0.0/12]" {
		t.Fatalf("parsed %s", got)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/8 ::/0", "10.0.0.1", "nonsense", "10.0.0.0/33"} {
		l := NewLoaderFrom(map[string]string{"PADDOCK_TRUSTED_PROXY_CIDRS": bad})
		LoadCommon(l)
		if err := l.Err(); err == nil || !strings.Contains(err.Error(), "PADDOCK_TRUSTED_PROXY_CIDRS") {
			t.Errorf("%q: err %v", bad, err)
		}
	}
}
