package triggers

import (
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestIsTrigger(t *testing.T) {
	nm := "org.freedesktop.DBus.Properties.PropertiesChanged"
	tests := []struct {
		name string
		s    *dbus.Signal
		want bool
	}{
		{"connectivity full", &dbus.Signal{Name: nm, Body: []any{"org.freedesktop.NetworkManager", map[string]dbus.Variant{"Connectivity": dbus.MakeVariant(uint32(4))}, []string{}}}, true},
		{"connectivity limited", &dbus.Signal{Name: nm, Body: []any{"org.freedesktop.NetworkManager", map[string]dbus.Variant{"Connectivity": dbus.MakeVariant(uint32(3))}, []string{}}}, false},
		{"other property", &dbus.Signal{Name: nm, Body: []any{"org.freedesktop.NetworkManager", map[string]dbus.Variant{"State": dbus.MakeVariant(uint32(70))}, []string{}}}, false},
		{"resume", &dbus.Signal{Name: "org.freedesktop.login1.Manager.PrepareForSleep", Body: []any{false}}, true},
		{"suspend", &dbus.Signal{Name: "org.freedesktop.login1.Manager.PrepareForSleep", Body: []any{true}}, false},
		{"malformed", &dbus.Signal{Name: "org.freedesktop.login1.Manager.PrepareForSleep"}, false},
	}
	for _, tt := range tests {
		if got := IsTrigger(tt.s); got != tt.want {
			t.Errorf("%s: %v", tt.name, got)
		}
	}
}
