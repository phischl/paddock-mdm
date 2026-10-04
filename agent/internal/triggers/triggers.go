// Package triggers watches D-Bus for events after which the agent checks in at once (plan M2b decision 8):
// NetworkManager connectivity becoming FULL and logind PrepareForSleep(false) (resume). Without D-Bus or
// NetworkManager it logs once and returns; the check-in timer keeps working.
package triggers

import (
	"context"
	"log/slog"

	"github.com/godbus/dbus/v5"
)

// nmConnectivityFull is NM_CONNECTIVITY_FULL.
const nmConnectivityFull = 4

// Watch sends to out (non-blocking) on every trigger until ctx ends.
func Watch(ctx context.Context, out chan<- struct{}) {
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		slog.WarnContext(ctx, "D-Bus system bus unavailable; check-ins follow the timer only", "error", err)
		return
	}
	defer func() { _ = conn.Close() }()
	var owner string
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, "org.freedesktop.NetworkManager").Store(&owner); err != nil {
		slog.InfoContext(ctx, "NetworkManager not running; no check-in on network changes until it starts")
	}
	matches := [][]dbus.MatchOption{
		{dbus.WithMatchObjectPath("/org/freedesktop/NetworkManager"), dbus.WithMatchInterface("org.freedesktop.DBus.Properties"),
			dbus.WithMatchMember("PropertiesChanged"), dbus.WithMatchArg(0, "org.freedesktop.NetworkManager")},
		{dbus.WithMatchObjectPath("/org/freedesktop/login1"), dbus.WithMatchInterface("org.freedesktop.login1.Manager"),
			dbus.WithMatchMember("PrepareForSleep")},
	}
	for _, m := range matches {
		if err := conn.AddMatchSignalContext(ctx, m...); err != nil {
			slog.WarnContext(ctx, "D-Bus match failed; check-ins follow the timer only", "error", err)
			return
		}
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	for {
		select {
		case <-ctx.Done():
			return
		case s, ok := <-signals:
			if !ok {
				slog.WarnContext(ctx, "D-Bus connection closed; check-ins follow the timer only")
				return
			}
			if IsTrigger(s) {
				select {
				case out <- struct{}{}:
				default:
				}
			}
		}
	}
}

// IsTrigger reports whether a signal means "check in now".
func IsTrigger(s *dbus.Signal) bool {
	switch s.Name {
	case "org.freedesktop.DBus.Properties.PropertiesChanged":
		if len(s.Body) < 2 {
			return false
		}
		changed, ok := s.Body[1].(map[string]dbus.Variant)
		if !ok {
			return false
		}
		v, ok := changed["Connectivity"]
		if !ok {
			return false
		}
		c, ok := v.Value().(uint32)
		return ok && c == nmConnectivityFull
	case "org.freedesktop.login1.Manager.PrepareForSleep":
		if len(s.Body) != 1 {
			return false
		}
		sleeping, ok := s.Body[0].(bool)
		return ok && !sleeping
	}
	return false
}
