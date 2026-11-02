package bundle

import (
	"slices"
	"testing"
)

func TestProtectedPackages(t *testing.T) {
	list := ProtectedPackages()
	if !slices.IsSorted(list) {
		t.Fatalf("list is not sorted: %v", list)
	}
	for _, name := range []string{"paddock-agent", "paddock-supervisor", "paddock-revoke", "fleet-osquery", "himmelblau", "pam-himmelblau", "nss-himmelblau"} {
		if !IsProtectedPackage(name) || !ValidPackage(name) {
			t.Errorf("%s is not a protected valid package", name)
		}
	}
	if IsProtectedPackage("nano") || IsProtectedPackage("") {
		t.Error("an ordinary package is protected")
	}
	list[0] = "changed"
	if ProtectedPackages()[0] == "changed" {
		t.Error("the returned list aliases the protected list")
	}
}
