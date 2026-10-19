package compiler

import (
	"context"
	"log/slog"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// hostnameSection is the hostname section of a v2 bundle (ADR 0041 decision 3): the device's managed name, nil when
// it has none. The CHECK constraint on device.name makes an invalid name unreachable; the guard keeps it out of a
// signed bundle anyway, since the agent would reject the resource.
func hostnameSection(ctx context.Context, t compileTarget) *bundle.HostnameSpec {
	if t.name == nil {
		return nil
	}
	if !bundle.ValidHostname(*t.name) {
		slog.ErrorContext(ctx, "hostname section omitted: the managed name is not a valid host name", "device_id", t.id)
		return nil
	}
	return &bundle.HostnameSpec{Name: *t.name}
}
