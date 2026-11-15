package system

import "testing"

// TestOffboardingHelpersUnit covers the pure helpers of gate OS1.
func TestOffboardingHelpersUnit(t *testing.T) {
	if got := offboardingOffVM([]string{"a", "b"}); got != "b" {
		t.Fatalf("off VM %s, want b", got)
	}
	if got := offboardingOffVM([]string{"a"}); got != "a" {
		t.Fatalf("off VM of a single VM run %s, want a", got)
	}
	for _, tt := range []struct {
		out       string
		phase     guestPhase
		triggered bool
		bad       bool
	}{
		{"armed no\n", phaseArmed, false, false},
		{"disarmed yes", phaseDisarmed, true, false},
		{"removed no", phaseRemoved, false, false},
		{"removed", "", false, true},
		{"lost no", "", false, true},
		{"armed maybe", "", false, true},
		{"", "", false, true},
	} {
		p, trig, err := parseGuestPhase(tt.out)
		if (err != nil) != tt.bad || p != tt.phase || trig != tt.triggered {
			t.Errorf("parseGuestPhase(%q) = %q, %v, %v", tt.out, p, trig, err)
		}
	}
	for _, tt := range []struct {
		seen []guestPhase
		bad  bool
	}{
		{[]guestPhase{phaseArmed, phaseDisarmed, phaseRemoved}, false},
		{[]guestPhase{phaseDisarmed, phaseRemoved}, false},
		{[]guestPhase{phaseRemoved}, false},
		{[]guestPhase{phaseArmed, phaseDisarmed}, true},
		{[]guestPhase{phaseDisarmed, phaseArmed, phaseRemoved}, true},
		{[]guestPhase{phaseRemoved, phaseDisarmed}, true},
		{nil, true},
	} {
		var tr phaseTrace
		for _, p := range tt.seen {
			tr.add(p)
			tr.add(p)
		}
		if err := tr.check(); (err != nil) != tt.bad {
			t.Errorf("trace %v: %v", tt.seen, err)
		}
	}

	for _, tt := range []struct {
		log string
		bad bool
	}{
		{"1.0 armed\n2.5 token_gone installed=yes\n3.0 removed\n", false},
		{"2.5 token_gone installed=yes\n2.5 removed\n", false},
		{"1.0 armed\n2.5 token_gone installed=no\n3.0 removed\n", true},
		{"1.0 armed\n3.0 removed\n", true},
		{"1.0 armed\n2.0 token_gone installed=yes\n", true},
		{"3.5 token_gone installed=yes\n3.0 removed\n", true},
		{"x token_gone installed=yes\n", true},
		{"", true},
	} {
		if err := checkWatchLog(tt.log); (err != nil) != tt.bad {
			t.Errorf("checkWatchLog(%q): %v", tt.log, err)
		}
	}
}
