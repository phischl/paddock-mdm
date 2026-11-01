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
		{ID: "big", Status: "failed", Message: long, Changes: make([]string, 80)},
	})
	if len(rows) != 2 || rows[0].Status != "applied" || rows[0].Message != "last wins" || rows[0].Changes == nil {
		t.Fatalf("rows %+v", rows)
	}
	big := rows[1]
	if len(big.ID) > maxStatusID || len(big.Message) > maxStatusMessage || len(big.Changes) != maxStatusChanges ||
		!utf8.ValidString(big.ID) || !utf8.ValidString(big.Message) {
		t.Fatalf("unbounded row: %d %d %d", len(big.ID), len(big.Message), len(big.Changes))
	}
	prefix := strings.Repeat("p", 256)
	ids := normalizeStatusRows([]statusRow{
		{ID: prefix + "-first", Status: "applied"},
		{ID: prefix + "-second", Status: "applied"},
		{ID: strings.Repeat("x", maxStatusID), Status: "applied"},
		{ID: strings.Repeat("y", maxStatusID+1), Status: "applied"},
		{ID: strings.Repeat("ä", 257), Status: "applied"},
	})
	if len(ids) != 3 || ids[0].ID != prefix+"-first" || ids[1].ID != prefix+"-second" || len(ids[2].ID) != maxStatusID {
		t.Fatalf("long IDs must be kept whole up to %d bytes and dropped beyond: %d rows", maxStatusID, len(ids))
	}
	if got := boundText("a\x00b", 10); got != "ab" {
		t.Fatalf("control character kept: %q", got)
	}
}
