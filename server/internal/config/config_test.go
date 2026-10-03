package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
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
