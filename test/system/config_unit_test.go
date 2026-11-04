package system

import "testing"

// TestConfigBucket pins the Go twin of the server's rollout bucket to vectors of configrollout.Bucket: a drift would
// silently invert which VM the rollout gate expects inside the first wave.
func TestConfigBucket(t *testing.T) {
	for _, c := range []struct {
		device, rollout string
		want            int
	}{
		{"00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000000", 45},
		{"ffffffff-ffff-ffff-ffff-ffffffffffff", "01890000-0000-7000-8000-000000000001", 25},
	} {
		if got := configBucket(c.device, c.rollout); got != c.want {
			t.Errorf("configBucket(%s, %s) = %d, want %d", c.device, c.rollout, got, c.want)
		}
	}
}
