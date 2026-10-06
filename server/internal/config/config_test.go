package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

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
