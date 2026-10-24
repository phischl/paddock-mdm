package device

import (
	"testing"
	"time"
)

func TestDriftState(t *testing.T) {
	cases := []struct {
		name               string
		offset             time.Duration
		drifting           bool
		wantRaise, wantClr bool
	}{
		{"61 s raises", 61 * time.Second, false, true, false},
		{"60 s does not raise", 60 * time.Second, false, false, false},
		{"-120 s raises", -120 * time.Second, false, true, false},
		{"-60 s does not raise", -60 * time.Second, false, false, false},
		{"45 s while drifting keeps drifting", 45 * time.Second, true, false, false},
		{"31 s while drifting keeps drifting", 31 * time.Second, true, false, false},
		{"30 s clears", 30 * time.Second, true, false, true},
		{"-30 s clears", -30 * time.Second, true, false, true},
		{"0 s clears", 0, true, false, true},
		{"120 s while drifting raises nothing", 120 * time.Second, true, false, false},
		{"0 s while in sync does nothing", 0, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raise, clear := DriftState(tc.offset, tc.drifting)
			if raise != tc.wantRaise || clear != tc.wantClr {
				t.Fatalf("DriftState(%v, %v) = (%v, %v), want (%v, %v)", tc.offset, tc.drifting, raise, clear, tc.wantRaise, tc.wantClr)
			}
		})
	}
}
