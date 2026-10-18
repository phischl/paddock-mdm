package autounseal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestValidateAcknowledgement(t *testing.T) {
	for _, tc := range []struct {
		name, version, ack string
		want               error
	}{
		{"english", "2026-10-17", "I understand and accept the risk", nil},
		{"german", "2026-10-17", "Ich verstehe und akzeptiere das Risiko", nil},
		{"outdated version", "2000-01-01", "I understand and accept the risk", ErrDisclaimerOutdated},
		{"empty version", "", "I understand and accept the risk", ErrDisclaimerOutdated},
		{"trailing space", "2026-10-17", "I understand and accept the risk ", ErrAcknowledgementMismatch},
		{"leading space", "2026-10-17", " I understand and accept the risk", ErrAcknowledgementMismatch},
		{"lower case", "2026-10-17", "i understand and accept the risk", ErrAcknowledgementMismatch},
		{"trailing period", "2026-10-17", "I understand and accept the risk.", ErrAcknowledgementMismatch},
		{"other sentence", "2026-10-17", "I accept", ErrAcknowledgementMismatch},
		{"empty", "2026-10-17", "", ErrAcknowledgementMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateAcknowledgement(tc.version, tc.ack); !errors.Is(err, tc.want) {
				t.Fatalf("ValidateAcknowledgement(%q, %q) = %v, want %v", tc.version, tc.ack, err, tc.want)
			}
		})
	}
}

// TestAcknowledgementsMatchCatalogs: the sentences the server accepts are exactly the sentences the portal asks to
// type (plan M8u §6.6).
func TestAcknowledgementsMatchCatalogs(t *testing.T) {
	if len(Acknowledgements) != 2 {
		t.Fatalf("Acknowledgements has %d entries, want 2", len(Acknowledgements))
	}
	var sentences []string
	for _, lang := range []string{"en", "de"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "web", "src", "locales", lang+".json")) //nolint:gosec // fixed path
		if err != nil {
			t.Fatal(err)
		}
		var cat struct {
			OpenBao struct {
				Disclaimer struct {
					Sentence string `json:"sentence"`
				} `json:"disclaimer"`
			} `json:"openbao"`
		}
		if err := json.Unmarshal(raw, &cat); err != nil {
			t.Fatalf("%s.json: %v", lang, err)
		}
		s := cat.OpenBao.Disclaimer.Sentence
		if !slices.Contains(Acknowledgements, s) {
			t.Errorf("%s.json openbao.disclaimer.sentence %q is not in Acknowledgements %q", lang, s, Acknowledgements)
		}
		sentences = append(sentences, s)
	}
	if sentences[0] == sentences[1] {
		t.Errorf("en and de sentences are equal: %q", sentences[0])
	}
}

func TestUnsealerRunning(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		seenAt time.Time
		want   bool
	}{
		{"never reported", time.Time{}, false},
		{"just now", now, true},
		{"at the limit", now.Add(-UnsealerStaleAfter), true},
		{"stale", now.Add(-UnsealerStaleAfter - time.Second), false},
	} {
		if got := (Report{SeenAt: tc.seenAt}).UnsealerRunning(now); got != tc.want {
			t.Errorf("%s: UnsealerRunning = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSharesOnHost(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	stale := now.Add(-UnsealerStaleAfter - time.Second)
	for _, tc := range []struct {
		name   string
		report Report
		want   bool
	}{
		{"running with shares", Report{SeenAt: now, SharesPresent: true}, true},
		{"running without shares", Report{SeenAt: now}, false},
		{"removed after reporting shares", Report{SeenAt: stale, SharesPresent: true}, false},
		{"never reported", Report{SharesPresent: true}, false},
	} {
		if got := tc.report.SharesOnHost(now); got != tc.want {
			t.Errorf("%s: SharesOnHost = %v, want %v", tc.name, got, tc.want)
		}
	}
}
