package disk

import (
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
