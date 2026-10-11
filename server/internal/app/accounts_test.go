package app_test

import (
	"errors"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// TestValidateAccountSettings: a settings patch needs at least one field and only supported values (plan M7c
// decision 3).
func TestValidateAccountSettings(t *testing.T) {
	cases := []struct {
		name    string
		in      app.AccountSettings
		wantErr bool
	}{
		{"empty patch", app.AccountSettings{}, true},
		{"unsupported theme", app.AccountSettings{Theme: ptr("blue")}, true},
		{"unsupported locale", app.AccountSettings{Locale: ptr("fr")}, true},
		{"theme only", app.AccountSettings{Theme: ptr("dark")}, false},
		{"locale only", app.AccountSettings{Locale: ptr("de")}, false},
		{"system theme", app.AccountSettings{Theme: ptr(app.ThemeSystem)}, false},
		{"both", app.AccountSettings{Locale: ptr("en"), Theme: ptr("light")}, false},
		{"one bad field fails the patch", app.AccountSettings{Locale: ptr("en"), Theme: ptr("neon")}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := app.ValidateAccountSettings(c.in)
			if (err != nil) != c.wantErr {
				t.Fatalf("ValidateAccountSettings(%+v) = %v, wantErr %v", c.in, err, c.wantErr)
			}
			if err != nil && !errors.Is(err, problem.InvalidRequest) {
				t.Fatalf("error %v is not invalid_request", err)
			}
		})
	}
}
