package app

import (
	"errors"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/domain/software"
)

// TestStrongestIntent (PDK-803): an entry assigned only as available is derived with intent available, never with an
// empty intent; every stronger intent wins over it.
func TestStrongestIntent(t *testing.T) {
	for _, tt := range []struct {
		intents []string
		want    string
	}{
		{[]string{software.IntentAvailable}, software.IntentAvailable},
		{[]string{software.IntentAvailable, software.IntentHold}, software.IntentHold},
		{[]string{software.IntentAvailable, software.IntentRequired}, software.IntentRequired},
		{[]string{software.IntentForbid, software.IntentAvailable}, software.IntentForbid},
		{nil, ""},
	} {
		if got := strongestIntent(tt.intents); got != tt.want {
			t.Errorf("strongestIntent(%v) = %q, want %q", tt.intents, got, tt.want)
		}
	}
}

// TestDerivedScope (plan M13b decision 17): a derived row has the scope of the package that applies; system when none
// applies or the packages cannot be read.
func TestDerivedScope(t *testing.T) {
	refs := []software.PackageRef{
		{Distribution: "ubuntu", Release: "*", Architecture: "*", FlatpakRef: "org.gimp.GIMP", Scope: software.ScopeUser},
		{Distribution: "debian", Release: "*", Architecture: "*", Package: "gimp"},
	}
	for _, tt := range []struct {
		osID, state, scope string
		err                error
	}{
		{"ubuntu", SoftwareStateUnknown, software.ScopeUser, nil},
		{"debian", SoftwareStateUnknown, software.ScopeSystem, nil},
		{"fedora", SoftwareStateNotApplicable, software.ScopeSystem, nil},
		{"ubuntu", SoftwareStateUnknown, software.ScopeSystem, errors.New("unreadable")},
	} {
		if state, _, scope := derivedFromRefs(refs, tt.err, tt.osID, "24.04", "amd64"); state != tt.state || scope != tt.scope {
			t.Errorf("%s (%v): %s %s, want %s %s", tt.osID, tt.err, state, scope, tt.state, tt.scope)
		}
	}
}
