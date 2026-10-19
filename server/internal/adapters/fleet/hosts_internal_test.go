package fleet

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestHostReadsNoVolatileFacts: free disk space, uptime and network addresses stay in Fleet (plan M8d decision 6);
// the parsed host struct has no field for them.
func TestHostReadsNoVolatileFacts(t *testing.T) {
	forbidden := []string{"gigs_disk_space_available", "percent_disk_space_available", "uptime", "primary_ip", "primary_mac", "public_ip"}
	typ := reflect.TypeFor[host]()
	for i := range typ.NumField() {
		tag, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		for _, f := range forbidden {
			if tag == f {
				t.Errorf("host reads %s", f)
			}
		}
	}
}

func TestHardwareTextTrimsAndCuts(t *testing.T) {
	if got := hardwareText("  LENOVO \t"); got != "LENOVO" {
		t.Fatalf("trim = %q", got)
	}
	long := strings.Repeat("ä", 200)
	if got := hardwareText(long); utf8.RuneCountInString(got) != maxHardwareRunes || !utf8.ValidString(got) {
		t.Fatalf("cut to %d runes", utf8.RuneCountInString(got))
	}
}
