package acceptance

import (
	"testing"
	"time"
)

func TestStepUpDue(t *testing.T) {
	cases := []struct {
		name        string
		age, window time.Duration
		want        bool
	}{
		{"dev window, fresh", 5 * time.Second, 30 * time.Second, false},
		{"dev window, at the margin", 20 * time.Second, 30 * time.Second, false},
		{"dev window, inside the margin", 21 * time.Second, 30 * time.Second, true},
		{"dev window, expired", 45 * time.Second, 30 * time.Second, true},
		{"production window, three minutes", 3 * time.Minute, productionStepUpWindow, false},
		{"production window, inside the margin", 4*time.Minute + time.Second, productionStepUpWindow, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stepUpDue(c.age, c.window); got != c.want {
				t.Fatalf("stepUpDue(%s, %s) = %v, want %v", c.age, c.window, got, c.want)
			}
		})
	}
}
