package loginsettings

import (
	"errors"
	"strings"
	"testing"
)

func valid() Settings {
	return Settings{
		HelloEnabled: true, HelloPinMinLength: 6, UserLockSessionAction: "lock_screen",
		BreakGlassAccounts: []string{"paddock"}, SudoersDAllowlist: []string{"README", "90-paddock"},
		SudoLectureText: "Be careful.", LocalAdminUsername: "paddock-admin", LocalAdminRotationDays: 30,
	}
}

func hours(h int) *int { return &h }

func TestValidate(t *testing.T) {
	if err := Validate(valid()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		mutate func(*Settings)
		want   error
	}{
		"pin too short":        {func(s *Settings) { s.HelloPinMinLength = 5 }, ErrPinLength},
		"pin too long":         {func(s *Settings) { s.HelloPinMinLength = 33 }, ErrPinLength},
		"unknown action":       {func(s *Settings) { s.UserLockSessionAction = "logout" }, ErrSessionAction},
		"break-glass upper":    {func(s *Settings) { s.BreakGlassAccounts = []string{"Admin"} }, ErrBreakGlass},
		"break-glass with @":   {func(s *Settings) { s.BreakGlassAccounts = []string{"dave@acme.test"} }, ErrBreakGlass},
		"break-glass twice":    {func(s *Settings) { s.BreakGlassAccounts = []string{"a", "a"} }, ErrBreakGlass},
		"allowlist with dot":   {func(s *Settings) { s.SudoersDAllowlist = []string{"x.conf"} }, ErrAllowlist},
		"allowlist with slash": {func(s *Settings) { s.SudoersDAllowlist = []string{"../sudoers"} }, ErrAllowlist},
		"allowlist paddock-":   {func(s *Settings) { s.SudoersDAllowlist = []string{"paddock-u-0123456789abcdef"} }, ErrAllowlist},
		"empty lecture":        {func(s *Settings) { s.SudoLectureText = "" }, ErrLecture},
		"long lecture":         {func(s *Settings) { s.SudoLectureText = strings.Repeat("x", 2001) }, ErrLecture},
		"local admin option":   {func(s *Settings) { s.LocalAdminUsername = "-admin" }, ErrLocalAdmin},
		"local admin with @":   {func(s *Settings) { s.LocalAdminUsername = "admin@acme.test" }, ErrLocalAdmin},
		"local admin empty":    {func(s *Settings) { s.LocalAdminUsername = "" }, ErrLocalAdmin},
		"rotation 0 days":      {func(s *Settings) { s.LocalAdminRotationDays = 0 }, ErrRotationDays},
		"rotation 366 days":    {func(s *Settings) { s.LocalAdminRotationDays = 366 }, ErrRotationDays},
		"reveal 0 hours":       {func(s *Settings) { s.RotateAfterRevealHours = hours(0) }, ErrRevealHours},
		"reveal 169 hours":     {func(s *Settings) { s.RotateAfterRevealHours = hours(169) }, ErrRevealHours},
		"long notice":          {func(s *Settings) { s.NoticeText = strings.Repeat("x", 2001) }, ErrNotice},
		"notice with escape":   {func(s *Settings) { s.NoticeText = "a\x1b[31mred" }, ErrNotice},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := valid()
			c.mutate(&s)
			if err := Validate(Normalize(s)); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}
