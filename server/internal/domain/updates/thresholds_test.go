package updates

import (
	"strings"
	"testing"
)

func TestThresholdsPreferTheGroupOverride(t *testing.T) {
	if w, c, src := Thresholds(120, 840, 24, 168); w != 120 || c != 840 || src != SourceDeviceGroup {
		t.Fatalf("with override: %d %d %s", w, c, src)
	}
	if w, c, src := Thresholds(0, 0, 24, 168); w != 24 || c != 168 || src != SourceOrganization {
		t.Fatalf("without override: %d %d %s", w, c, src)
	}
	if _, _, src := Thresholds(2, 0, 24, 168); src != SourceOrganization {
		t.Fatalf("half an override counts as none: %s", src)
	}
}

func TestValidateThresholds(t *testing.T) {
	for _, c := range []struct {
		w, c int
		ok   bool
	}{{1, 2, true}, {720, 2160, true}, {0, 2, false}, {721, 800, false}, {4, 4, false}, {2, 2161, false}} {
		err := ValidateThresholds("staleness.", c.w, c.c)
		if (err == nil) != c.ok {
			t.Errorf("%d/%d: %v", c.w, c.c, err)
		}
		if err != nil && !strings.HasPrefix(err.Error(), "staleness.") {
			t.Errorf("message %q does not name the field", err)
		}
	}
}
