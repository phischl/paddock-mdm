package commands

import "maps"

// Handlers returns the handlers of this build: the given ones plus, in development builds, the noop command.
func Handlers(handlers map[string]Handler) map[string]Handler {
	out := maps.Clone(handlers)
	if out == nil {
		out = map[string]Handler{}
	}
	maps.Copy(out, devHandlers())
	return out
}
