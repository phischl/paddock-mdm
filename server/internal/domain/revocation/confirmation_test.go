package revocation

import (
	"reflect"
	"testing"
)

// TestParseConfirmation: the extended confirmation of M4c.1 with its volumes and an unresolved entry (so not erased),
// and the confirmation of M4c without them.
func TestParseConfirmation(t *testing.T) {
	got := ParseConfirmation([]byte(`{"erased":true,"slots_before":5,"slots_after":0,"volumes":[` +
		`{"device":"/dev/vdb1","slots_before":3,"slots_after":0,"erased":true},` +
		`{"device":"/dev/vda3","slots_before":2,"slots_after":0,"erased":true}],"unresolved":["UUID=gone"]}`))
	want := Confirmation{Erased: true, SlotsBefore: 5, Volumes: []VolumeConfirmation{
		{Device: "/dev/vdb1", SlotsBefore: 3, Erased: true}, {Device: "/dev/vda3", SlotsBefore: 2, Erased: true},
	}, Unresolved: []string{"UUID=gone"}}
	if !reflect.DeepEqual(got, want) || got.AllErased() {
		t.Fatalf("extended confirmation %+v", got)
	}
	lock := ParseConfirmation([]byte(`{"erased":true,"slots_before":2,"slots_after":0,"volumes":[` +
		`{"device":"/dev/vda3","uuid":"0d8f4c62-0000-4000-8000-0000000000aa","slots_before":2,"slots_after":0,"erased":true}],` +
		`"skipped_not_escrowed":[{"device":"/dev/vdb1","uuid":"0d8f4c62-0000-4000-8000-0000000000bb"},{"device":"/dev/vdc"}]}`))
	if len(lock.SkippedNotEscrowed) != 2 || lock.SkippedNotEscrowed[0].UUID != "0d8f4c62-0000-4000-8000-0000000000bb" ||
		lock.Volumes[0].UUID == "" || !lock.AllErased() {
		t.Fatalf("PDK-009 lock confirmation %+v", lock)
	}
	m4c := ParseConfirmation([]byte(`{"erased":true,"slots_before":2,"slots_after":0}`))
	if !reflect.DeepEqual(m4c, Confirmation{Erased: true, SlotsBefore: 2}) || !m4c.AllErased() {
		t.Fatalf("M4c confirmation %+v", m4c)
	}
	if c := ParseConfirmation([]byte(`{"erased":"yes"`)); !reflect.DeepEqual(c, Confirmation{}) || c.AllErased() {
		t.Fatalf("malformed confirmation %+v", c)
	}
}

// TestAllErased (plan M4c.1 decision 2, review round 1): erased only if every volume has no keyslot left and nothing
// is unresolved, whatever the top level claims.
func TestAllErased(t *testing.T) {
	cases := map[string]struct {
		c    Confirmation
		want bool
	}{
		"every volume erased": {Confirmation{Erased: true, Volumes: []VolumeConfirmation{{Erased: true}, {Erased: true}}}, true},
		"device says failed":  {Confirmation{Erased: false, Volumes: []VolumeConfirmation{{Erased: true}}}, false},
		"a volume kept slots": {Confirmation{Erased: true, Volumes: []VolumeConfirmation{{Erased: true}, {Erased: true, SlotsAfter: 1}}}, false},
		"a volume failed":     {Confirmation{Erased: true, Volumes: []VolumeConfirmation{{Erased: false}, {Erased: true}}}, false},
		"unknown slot count":  {Confirmation{Erased: true, Volumes: []VolumeConfirmation{{Erased: true, SlotsAfter: -1}}}, false},
		"unresolved entries":  {Confirmation{Erased: true, Volumes: []VolumeConfirmation{{Erased: true}}, Unresolved: []string{"UUID=x"}}, false},
		"unreadable crypttab": {Confirmation{Erased: true, Volumes: []VolumeConfirmation{{Erased: true}}, Unresolved: []string{"/etc/crypttab"}}, false},
		"skipped by a lock": {Confirmation{Erased: true, Volumes: []VolumeConfirmation{{Erased: true}},
			SkippedNotEscrowed: []SkippedVolume{{Device: "/dev/vdb1"}}}, true},
	}
	for name, c := range cases {
		if got := c.c.AllErased(); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}
