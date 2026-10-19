package disk

import "testing"

// TestEffectiveUnlockMode (plan M8d decision 44): tpm_pin wins across groups, then tpm_only, then the organization.
func TestEffectiveUnlockMode(t *testing.T) {
	for _, tc := range []struct {
		org    string
		groups []string
		want   string
	}{
		{UnlockModeTPMPIN, nil, UnlockModeTPMPIN},
		{UnlockModeTPMOnly, nil, UnlockModeTPMOnly},
		{UnlockModeTPMOnly, []string{UnlockModeTPMPIN}, UnlockModeTPMPIN},
		{UnlockModeTPMPIN, []string{UnlockModeTPMOnly}, UnlockModeTPMOnly},
		{UnlockModeTPMPIN, []string{UnlockModeTPMOnly, UnlockModeTPMPIN}, UnlockModeTPMPIN},
		{"", nil, UnlockModeTPMPIN},
	} {
		if got := EffectiveUnlockMode(tc.org, tc.groups); got != tc.want {
			t.Errorf("EffectiveUnlockMode(%q, %v) = %q, want %q", tc.org, tc.groups, got, tc.want)
		}
	}
	if ValidUnlockMode("tpm") || !ValidUnlockMode(UnlockModeTPMOnly) {
		t.Fatal("ValidUnlockMode")
	}
}
