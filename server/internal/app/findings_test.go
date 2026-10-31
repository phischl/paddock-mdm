package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// TestFindingSubject (PDK-126 fix round 1): a subject within the param limit is kept as sent (without control
// characters); a longer one is cut to the limit at a character boundary and ends with a hash of the whole value, so
// two long names that share their beginning stay apart and the same name always gives the same subject.
func TestFindingSubject(t *testing.T) {
	data := func(file string) json.RawMessage {
		raw, _ := json.Marshal(map[string]string{"file": file})
		return raw
	}
	if got := findingSubject(data("evil\x00"), "file"); got != "evil" {
		t.Errorf("short subject %q", got)
	}
	if got := findingSubject(data("evil"), ""); got != "" {
		t.Errorf("code without subject: %q", got)
	}
	if got := findingSubject(json.RawMessage(`not json`), "file"); got != "" {
		t.Errorf("malformed data: %q", got)
	}
	prefix := strings.Repeat("ä", maxParamString)
	a, b := findingSubject(data(prefix+"-a"), "file"), findingSubject(data(prefix+"-b"), "file")
	for _, s := range []string{a, b} {
		if len(s) > maxParamString || !utf8.ValidString(s) || !strings.HasPrefix(s, "ää") || !strings.Contains(s, "…") {
			t.Fatalf("long subject %q (%d bytes)", s, len(s))
		}
	}
	if a == b {
		t.Fatal("two long names map to the same subject")
	}
	if again := findingSubject(data(prefix+"-a"), "file"); again != a {
		t.Fatalf("subject not deterministic: %q vs %q", again, a)
	}
	exact := strings.Repeat("x", maxParamString)
	if got := findingSubject(data(exact), "file"); got != exact {
		t.Fatal("a subject of exactly the limit was changed")
	}
}

// TestTamperFindingAfterCodes: only the tamper codes of tamperFindingCodes open findings.
func TestTamperFindingAfterCodes(t *testing.T) {
	dev := uuid.Must(uuid.NewV7())
	for code := range tamperFindingCodes {
		if tamperFindingAfter(dev, code, nil, time.Now()) == nil {
			t.Errorf("%s opens no finding", code)
		}
	}
	for _, code := range []audit.Code{audit.CodeDeviceBundleApplied, audit.CodeDeviceEventGap, audit.CodeDeviceClockDrift} {
		if tamperFindingAfter(dev, code, nil, time.Now()) != nil {
			t.Errorf("%s opens a finding", code)
		}
	}
}

// TestAuditText (PDK-126 fix round 1): a text within its limit is the param as given; a longer one is cut to the
// limit in characters.
func TestAuditText(t *testing.T) {
	if got := auditText("test file", 1000); got != "test file" {
		t.Errorf("short text %q", got)
	}
	long := strings.Repeat("ü", 300*1024)
	if got := auditText(long, 1000); utf8.RuneCountInString(got) != 1000 || !strings.HasPrefix(long, got) {
		t.Errorf("long text cut to %d characters", utf8.RuneCountInString(got))
	}
}
