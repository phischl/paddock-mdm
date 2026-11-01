package configrollout

import (
	"errors"
	"testing"
)

func TestValidateWaves(t *testing.T) {
	valid := [][]int{{100}, {1, 100}, {1, 10, 50, 100}, {10, 20, 30, 40, 50, 60, 70, 80, 90, 100}}
	for _, w := range valid {
		if err := ValidateWaves(w); err != nil {
			t.Errorf("%v rejected: %v", w, err)
		}
	}
	invalid := [][]int{nil, {}, {50}, {1, 10}, {0, 100}, {10, 10, 100}, {50, 10, 100}, {1, 101, 100}, {-1, 100},
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100}}
	for _, w := range invalid {
		if err := ValidateWaves(w); !errors.Is(err, ErrInvalidWaves) {
			t.Errorf("%v accepted: %v", w, err)
		}
	}
}

func TestDefaultsAreValidAndOff(t *testing.T) {
	d := Defaults()
	if d.Enabled || d.MinWaveMinutes != 60 || d.FailureThresholdPercent != 2 || d.FailureThresholdMin != 3 {
		t.Fatalf("defaults %+v", d)
	}
	if err := d.Validate(false); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
}

func TestDefaultWavesAreFresh(t *testing.T) {
	a := DefaultWaves()
	a[0] = 99
	if DefaultWaves()[0] != 1 {
		t.Fatal("default waves are shared")
	}
}

func TestValidateMinWaveMinutes(t *testing.T) {
	cases := []struct {
		minutes     int
		development bool
		ok          bool
	}{
		{15, false, true}, {14, false, false}, {1, false, false}, {0, false, false},
		{1, true, true}, {0, true, false}, {-5, true, false},
	}
	for _, c := range cases {
		s := Defaults()
		s.MinWaveMinutes = c.minutes
		err := s.Validate(c.development)
		if (err == nil) != c.ok || (!c.ok && !errors.Is(err, ErrInvalidMinWave)) {
			t.Errorf("minutes %d development %v: %v", c.minutes, c.development, err)
		}
	}
}

func TestValidateThresholds(t *testing.T) {
	for _, c := range []struct {
		percent, minimum int
		ok               bool
	}{{0, 0, true}, {100, 5, true}, {-1, 3, false}, {101, 3, false}, {2, -1, false}} {
		s := Defaults()
		s.FailureThresholdPercent, s.FailureThresholdMin = c.percent, c.minimum
		if err := s.Validate(false); (err == nil) != c.ok {
			t.Errorf("%d/%d: %v", c.percent, c.minimum, err)
		}
	}
}

func TestValidateRejectsInvalidWaves(t *testing.T) {
	s := Defaults()
	s.Waves = []int{1, 10}
	if err := s.Validate(true); !errors.Is(err, ErrInvalidWaves) {
		t.Fatalf("%v", err)
	}
}
