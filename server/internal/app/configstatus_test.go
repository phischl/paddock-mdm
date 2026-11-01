package app

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestResourceType(t *testing.T) {
	for id, want := range map[string]string{
		"file:/etc/a.conf": "file", "unit:a.service": "unit", "time": "time", "pam-deny-list": "pam-deny-list", "file:": "file",
	} {
		if got := ResourceType(id); got != want {
			t.Errorf("ResourceType(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestNormalizeStatusRows(t *testing.T) {
	long := strings.Repeat("ä", 400)
	rows := normalizeStatusRows([]statusRow{
		{ID: "", Status: "applied"},
		{ID: "a", Status: "failed", Message: "first"},
		{ID: "a", Status: "applied", Message: "last wins"},
		{ID: long, Status: "failed", Message: long, Changes: make([]string, 80)},
	})
	if len(rows) != 2 || rows[0].Status != "applied" || rows[0].Message != "last wins" || rows[0].Changes == nil {
		t.Fatalf("rows %+v", rows)
	}
	big := rows[1]
	if len(big.ID) > maxStatusID || len(big.Message) > maxStatusMessage || len(big.Changes) != maxStatusChanges ||
		!utf8.ValidString(big.ID) || !utf8.ValidString(big.Message) {
		t.Fatalf("unbounded row: %d %d %d", len(big.ID), len(big.Message), len(big.Changes))
	}
	if got := boundText("a\x00b", 10); got != "ab" {
		t.Fatalf("control character kept: %q", got)
	}
}
