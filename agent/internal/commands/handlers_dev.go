//go:build paddock_dev

package commands

import (
	"context"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// TypeNoop is a command that does nothing; it exists only in development builds (TAGS=paddock_dev) to exercise the
// command path end to end. The server never issues it.
const TypeNoop = "noop"

// devHandlers are the handlers of development builds.
func devHandlers() map[string]Handler {
	return map[string]Handler{TypeNoop: func(context.Context, *command.Command) (string, map[string]any) {
		return protocol.CommandSucceeded, map[string]any{}
	}}
}
