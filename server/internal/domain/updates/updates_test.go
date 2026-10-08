package updates

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func ptr(s string) *string { return &s }

func TestValidate(t *testing.T) {
	if err := Defaults().Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	for name, tc := range map[string]struct {
		change func(*Settings)
		want   error
	}{
		"security time":     {func(s *Settings) { s.SecurityDailyAt = "3:00" }, ErrSchedule},
		"regular schedule":  {func(s *Settings) { s.RegularSchedule = "Mon..Fri 04:00" }, ErrSchedule},
		"delay negative":    {func(s *Settings) { s.MaxRandomDelayMin = -1 }, ErrSettings},
		"delay too long":    {func(s *Settings) { s.MaxRandomDelayMin = 721 }, ErrSettings},
		"warning zero":      {func(s *Settings) { s.StalenessWarningH = 0 }, ErrSettings},
		"warning too long":  {func(s *Settings) { s.StalenessWarningH = 721; s.StalenessCriticalH = 800 }, ErrSettings},
		"critical = warn":   {func(s *Settings) { s.StalenessCriticalH = s.StalenessWarningH }, ErrSettings},
		"critical too long": {func(s *Settings) { s.StalenessCriticalH = 2161 }, ErrSettings},
		"all days":          {func(s *Settings) { s.RegularSchedule = "Mon,Tue,Wed,Thu,Fri,Sat,Sun 23:59" }, nil},
		"every day":         {func(s *Settings) { s.RegularSchedule = "04:00"; s.MaxRandomDelayMin = 0 }, nil},
	} {
		s := Defaults()
		tc.change(&s)
		if err := s.Validate(); !errors.Is(err, tc.want) && (tc.want != nil || err != nil) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

func TestValidateHold(t *testing.T) {
	if err := ValidateHold("openssl", ptr("3.0.13-0ubuntu3.4"), "CVE fix breaks app"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		pkg     string
		version *string
		reason  string
	}{
		{"-oDpkg", nil, ""}, {"openssl", ptr("1.0 2"), ""}, {"openssl", ptr(""), ""}, {"openssl", nil, strings.Repeat("ä", 501)},
	} {
		if err := ValidateHold(tc.pkg, tc.version, tc.reason); !errors.Is(err, ErrHold) {
			t.Errorf("ValidateHold(%q, %v, %d runes) = %v", tc.pkg, tc.version, len([]rune(tc.reason)), err)
		}
	}
}

func TestMerge(t *testing.T) {
	g1, g2 := uuid.New(), uuid.New()
	merged, conflicts := Merge([]Hold{
		{Package: "zsh"},
		{GroupID: &g1, Package: "openssl", Version: ptr("3.0.13-0ubuntu3.4")},
		{GroupID: &g2, Package: "openssl", Version: ptr("3.0.13-0ubuntu3.1")},
		{GroupID: &g1, Package: "zsh"},
		{GroupID: &g2, Package: "curl", Version: ptr("8.5.0-2")},
		{Package: "curl"},
	})
	got := make([]string, len(merged))
	for i, h := range merged {
		got[i] = h.Package
		if h.Version != nil {
			got[i] += "=" + *h.Version
		}
	}
	want := []string{"curl", "openssl=3.0.13-0ubuntu3.1", "zsh"}
	if !slices.Equal(got, want) {
		t.Errorf("merged %v, want %v", got, want)
	}
	if len(conflicts) != 2 || conflicts[0].Package != "curl" || conflicts[0].Chosen != nil ||
		conflicts[1].Package != "openssl" || *conflicts[1].Chosen != "3.0.13-0ubuntu3.1" || len(conflicts[1].Versions) != 2 {
		t.Errorf("conflicts %+v", conflicts)
	}
	if m, c := Merge(nil); len(m) != 0 || c != nil {
		t.Errorf("Merge(nil) = %v %v", m, c)
	}
}

func TestHeld(t *testing.T) {
	holds := []Hold{{Package: "openssl"}, {Package: "curl", Version: ptr("8.5.0-2")}}
	if got := Held(holds, []string{"htop", "curl", "openssl"}); !slices.Equal(got, []string{"curl", "openssl"}) {
		t.Errorf("Held = %v", got)
	}
}

func TestNormalizeInstall(t *testing.T) {
	got, err := NormalizeInstall([]string{"htop", "curl", "htop"}, 20)
	if err != nil || !slices.Equal(got, []string{"htop", "curl"}) {
		t.Fatalf("NormalizeInstall = %v %v", got, err)
	}
	for _, pkgs := range [][]string{nil, {"-y"}, {"a b"}, {"a1", "a2", "a3"}} {
		if _, err := NormalizeInstall(pkgs, 2); !errors.Is(err, ErrInstall) {
			t.Errorf("NormalizeInstall(%v) = %v", pkgs, err)
		}
	}
}

func TestStaleLevel(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for silent, want := range map[time.Duration]string{
		0: StaleNone, 23*time.Hour + 59*time.Minute: StaleNone, 24 * time.Hour: StaleWarning, 167 * time.Hour: StaleWarning,
		168 * time.Hour: StaleCritical, -time.Hour: StaleNone,
	} {
		if got := StaleLevel(now.Add(-silent), now, 24, 168, time.Hour); got != want {
			t.Errorf("silent %s: %q, want %q", silent, got, want)
		}
	}
	if got := StaleLevel(now.Add(-2*time.Minute), now, 1, 3, time.Minute); got != StaleWarning {
		t.Errorf("minute unit: %q", got)
	}
}
