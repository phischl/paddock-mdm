package disk

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// TestConversionActive (plan M8e §14.5 decision 36 as amended on 2026-10-21, §14.6 decision 50): an open conversion,
// a disk the health reports encrypting whatever the conversion says, a completed conversion whose key is still on
// /boot (key_on_boot) and, fail safe, a recent completion without a conversion report are active; a long-converted
// device that is merely not compliant is not.
func TestConversionActive(t *testing.T) {
	now := time.Now()
	recent, old := now.Add(-time.Hour), now.Add(-31*24*time.Hour)
	disk := func(state string, conversion *protocol.DiskConversion) *protocol.DiskHealth {
		return &protocol.DiskHealth{State: state, Conversion: conversion}
	}
	onBoot, regenerated := &protocol.DiskConversion{KeyOnBoot: true}, &protocol.DiskConversion{}
	for _, tc := range []struct {
		name      string
		phase     string
		health    *protocol.DiskHealth
		completed *time.Time
		want      bool
	}{
		{"requested", PhaseRequested, disk("not_encrypted", nil), nil, true},
		{"prepared", PhasePrepared, disk("not_encrypted", nil), nil, true},
		{"encrypting without health", PhaseEncrypting, nil, nil, true},
		{"failed resume, health encrypting", PhaseFailed, disk("encrypting", nil), nil, true},
		{"failed, unencrypted", PhaseFailed, disk("not_encrypted", nil), nil, false},
		{"cancelled, stale initrd converted", PhaseCancelled, disk("encrypting", nil), nil, true},
		{"cancelled", PhaseCancelled, disk("not_encrypted", nil), nil, false},
		{"no conversion, health encrypting", "", disk("encrypting", nil), nil, true},
		{"no conversion", "", disk("not_encrypted", nil), nil, false},
		{"nothing", "", nil, nil, false},
		{"completed, key on boot", PhaseCompleted, disk("tpm_pin_missing", onBoot), &recent, true},
		{"completed long ago, key on boot", PhaseCompleted, disk("tpm_pin_missing", onBoot), &old, true},
		{"completed, regenerated, pin missing", PhaseCompleted, disk("tpm_pin_missing", regenerated), &recent, false},
		{"completed, regenerated, escrow pending", PhaseCompleted, disk("escrow_pending", regenerated), &recent, false},
		{"completed recently, no health", PhaseCompleted, nil, &recent, true},
		{"completed recently, no conversion report", PhaseCompleted, disk("tpm_pin_missing", nil), &recent, true},
		{"completed long ago, no conversion report", PhaseCompleted, disk("tpm_pin_missing", nil), &old, false},
		{"completed recently, compliant", PhaseCompleted, disk("compliant", nil), &recent, false},
		{"older adopted conversion completed, latest cancelled", PhaseCancelled, disk("tpm_pin_missing", onBoot), &recent, true},
		{"older conversion completed, latest cancelled, regenerated", PhaseCancelled, disk("tpm_pin_missing", regenerated), &recent, false},
		{"failed, no completed conversion, key on boot", PhaseFailed, disk("tpm_pin_missing", onBoot), nil, true},
		{"no conversion, key on boot", "", disk("not_encrypted", onBoot), nil, true},
	} {
		if got := ConversionActive(tc.phase, tc.health, tc.completed, now); got != tc.want {
			t.Errorf("%s: ConversionActive = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestNotes (plan M8e amendment 2026-10-21, items 17 to 19): the wait only while encrypting or preparing, the cleanup's
// reason only once failed or cancelled, the initrd issue in every phase.
func TestNotes(t *testing.T) {
	since := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	report := func(phase string) *protocol.DiskConversion {
		return &protocol.DiskConversion{Phase: phase, PausedReason: "packages_busy", PausedSince: &since,
			CleanupError: "dracut: no space left on device", InitrdIssue: "boot_space_low", BootSpaceNeeded: 90, BootSpaceFree: 40}
	}
	initrd := ConversionNotes{InitrdIssue: "boot_space_low", BootSpaceNeeded: 90, BootSpaceFree: 40}
	paused := initrd
	paused.PausedReason, paused.PausedSince = "packages_busy", &since
	cleanup := initrd
	cleanup.CleanupError = "dracut: no space left on device"
	for _, tc := range []struct {
		name   string
		phase  string
		report *protocol.DiskConversion
		want   ConversionNotes
	}{
		{"no report", PhaseRequested, nil, ConversionNotes{}},
		{"requested, device preparing", PhaseRequested, report("preparing"), paused},
		{"requested, device already prepared", PhaseRequested, report("prepared"), initrd},
		{"prepared", PhasePrepared, report("prepared"), initrd},
		{"encrypting", PhaseEncrypting, report("encrypting"), paused},
		{"completed", PhaseCompleted, report("completed"), initrd},
		{"failed, cleanup pending", PhaseFailed, report("failed"), cleanup},
		{"cancelled, cleanup pending", PhaseCancelled, report(""), cleanup},
	} {
		if got := Notes(tc.phase, tc.report); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: Notes = %+v, want %+v", tc.name, got, tc.want)
		}
	}
	shared := Notes(PhaseCompleted, &protocol.DiskConversion{InitrdIssue: "key_material_shared_bootable", InitrdIssueKernel: "6.8.0-45-generic"})
	if shared.InitrdIssue != "key_material_shared_bootable" || shared.InitrdIssueKernel != "6.8.0-45-generic" {
		t.Errorf("Notes = %+v, want the issue with its kernel", shared)
	}
}

// TestNotesBoundsDeviceText (plan M8e amendment 2026-10-21, item 17): cleanup_error is device-supplied free text and
// reaches the admin API only as its first line, without control characters, at most 200 runes.
func TestNotesBoundsDeviceText(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"dracut failed\nsecond line", "dracut failed"},
		{"dracut\x00 failed\tnow\r\nmore", "dracut failednow"},
		{strings.Repeat("ä", 250), strings.Repeat("ä", 200)},
	} {
		if got := Notes(PhaseFailed, &protocol.DiskConversion{CleanupError: tc.in}).CleanupError; got != tc.want {
			t.Errorf("CleanupError(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
