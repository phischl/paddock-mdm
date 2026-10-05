//go:build !paddock_dev

package commands

// devHandlers are the handlers of development builds; release builds have none.
func devHandlers() map[string]Handler { return nil }
