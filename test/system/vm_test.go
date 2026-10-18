package system

import "testing"

// TestBind: a bound subtest receives the VM's failures, and the test that bound the VM before gets them back when the
// subtest ends, also through nested subtests.
func TestBind(t *testing.T) {
	v := &VM{Name: "vm", t: t}
	t.Run("outer", func(outer *testing.T) {
		v.Bind(outer)
		if v.t != outer {
			outer.Fatal("Bind did not bind the subtest")
		}
		outer.Run("inner", func(inner *testing.T) {
			v.Bind(inner)
			if v.t != inner {
				inner.Fatal("Bind did not bind the nested subtest")
			}
		})
		if v.t != outer {
			outer.Fatal("the nested subtest did not give the VM back")
		}
	})
	if v.t != t {
		t.Fatal("the subtest did not give the VM back")
	}
}
