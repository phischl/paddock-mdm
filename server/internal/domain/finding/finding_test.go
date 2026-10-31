package finding

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

var allStatuses = []Status{StatusOpen, StatusAcknowledged, StatusInProgress, StatusResolved, StatusAcceptedRisk, StatusFalsePositive}

func TestTransitions(t *testing.T) {
	cases := []struct {
		from                       Status
		acknowledge, assign, close bool
	}{
		{StatusOpen, true, true, true},
		{StatusAcknowledged, false, true, true},
		{StatusInProgress, false, true, true},
		{StatusResolved, false, false, false},
		{StatusAcceptedRisk, false, false, false},
		{StatusFalsePositive, false, false, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.from), func(t *testing.T) {
			if got := CanAcknowledge(tc.from); got != tc.acknowledge {
				t.Errorf("CanAcknowledge = %v, want %v", got, tc.acknowledge)
			}
			if got := CanAssign(tc.from); got != tc.assign {
				t.Errorf("CanAssign = %v, want %v", got, tc.assign)
			}
			if got := CanClose(tc.from); got != tc.close {
				t.Errorf("CanClose = %v, want %v", got, tc.close)
			}
		})
	}
}

func TestCanReopen(t *testing.T) {
	for _, s := range allStatuses {
		for _, kind := range []Kind{KindTamper, KindAttention} {
			for _, cleared := range []bool{false, true} {
				want := s.Resolution() && (kind == KindTamper || !cleared)
				if got := CanReopen(s, kind, cleared); got != want {
					t.Errorf("CanReopen(%s, %s, cleared %v) = %v, want %v", s, kind, cleared, got, want)
				}
			}
		}
	}
	if CanReopen(StatusResolved, KindAttention, true) {
		t.Error("a cleared attention finding must not reopen")
	}
	if !CanReopen(StatusFalsePositive, KindTamper, true) {
		t.Error("a closed tamper finding must reopen")
	}
}

func TestStatusClasses(t *testing.T) {
	for _, s := range allStatuses {
		if !s.Valid() || s.Live() == s.Resolution() {
			t.Errorf("%s: valid %v, live %v, resolution %v", s, s.Valid(), s.Live(), s.Resolution())
		}
	}
	if Status("closed").Valid() || Kind("other").Valid() || !KindTamper.Valid() || !KindAttention.Valid() {
		t.Error("unexpected validity")
	}
}

func TestValidReason(t *testing.T) {
	cases := []struct {
		reason string
		want   bool
	}{
		{"", false},
		{"   ", false},
		{"x", true},
		{strings.Repeat("ä", MaxReason), true},
		{strings.Repeat("a", MaxReason+1), false},
	}
	for _, tc := range cases {
		if got := ValidReason(tc.reason); got != tc.want {
			t.Errorf("ValidReason(%d runes) = %v, want %v", len([]rune(tc.reason)), got, tc.want)
		}
	}
	if !ValidExternalRef("") || !ValidExternalRef(strings.Repeat("ü", MaxExternalRef)) || ValidExternalRef(strings.Repeat("a", MaxExternalRef+1)) {
		t.Error("external reference limits wrong")
	}
}

func TestKeys(t *testing.T) {
	id := uuid.MustParse("01890000-0000-7000-8000-000000000001")
	if got := TamperKey(id, "device.tamper_sudoers_d_file", "/etc/sudoers.d/x"); got != "tamper:01890000-0000-7000-8000-000000000001:device.tamper_sudoers_d_file:/etc/sudoers.d/x" {
		t.Errorf("TamperKey = %q", got)
	}
	if got := TamperKey(id, "device.clone_suspected", ""); !strings.HasSuffix(got, ":device.clone_suspected:") {
		t.Errorf("TamperKey without subject = %q", got)
	}
	if got := AttentionKey("stale_critical:42"); got != "attention:stale_critical:42" {
		t.Errorf("AttentionKey = %q", got)
	}
}
