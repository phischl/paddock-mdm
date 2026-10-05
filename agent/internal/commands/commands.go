// Package commands executes device commands (architecture §11.4, plan M4a decision 3): it verifies each envelope
// with the command keys of the applied bundle, the device, the organization and the lifetime, executes a command at
// most once (the IDs are kept 60 days) and returns the results to report. A command whose type has no handler fails
// with reason unsupported_type.
package commands

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/command"
	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// Retention is how long executed command IDs are kept (architecture §11.4).
const Retention = 60 * 24 * time.Hour

// Handler executes one verified command and returns its status (protocol.CommandSucceeded or CommandFailed) and a
// result object without secrets.
type Handler func(ctx context.Context, c *command.Command) (status string, result map[string]any)

// Result is the result of one executed command.
type Result struct {
	CommandID string
	Status    string
	Result    json.RawMessage
}

// Executor verifies and executes commands.
type Executor struct {
	handlers map[string]Handler
	now      func() time.Time
}

// New creates an executor with the handlers by command type.
func New(handlers map[string]Handler, now func() time.Time) *Executor {
	return &Executor{handlers: handlers, now: now}
}

// ErrNoKeys means the applied bundle carries no command keys, so no command can be verified.
var ErrNoKeys = errors.New("commands: the applied bundle has no command keys")

// Run verifies the envelopes with the keys of the applied bundle and executes every command that was not executed
// before. executed is the record of executed command IDs; it is updated through mark before a handler runs, so a
// crash during execution never leads to a second execution. Entries older than Retention are pruned. Envelopes that
// fail verification are logged and skipped.
func (e *Executor) Run(ctx context.Context, envelopes []json.RawMessage, keys *bundle.Keys, deviceID, orgID string,
	executed map[string]time.Time, mark func() error) ([]Result, error) {
	now := e.now()
	for id, at := range executed {
		if now.Sub(at) > Retention {
			delete(executed, id)
		}
	}
	if len(envelopes) == 0 {
		return nil, nil
	}
	if keys == nil || len(keys.CommandSigning) == 0 {
		return nil, ErrNoKeys
	}
	trust, err := command.TrustFromKeys(keys.CommandSigning)
	if err != nil {
		return nil, err
	}
	var results []Result
	for _, env := range envelopes {
		c, err := command.Verify(env, trust, deviceID, orgID, now)
		if err != nil {
			slog.WarnContext(ctx, "command rejected", "error", err)
			continue
		}
		if _, done := executed[c.CommandID]; done {
			continue
		}
		executed[c.CommandID] = now
		if err := mark(); err != nil {
			delete(executed, c.CommandID)
			return results, err
		}
		results = append(results, e.execute(ctx, c))
	}
	return results, nil
}

func (e *Executor) execute(ctx context.Context, c *command.Command) Result {
	status, result := protocol.CommandFailed, map[string]any{"reason": "unsupported_type"}
	if h, ok := e.handlers[c.Type]; ok {
		status, result = h(ctx, c)
	}
	slog.InfoContext(ctx, "command executed", "command_id", c.CommandID, "type", c.Type, "status", status)
	raw, err := json.Marshal(result)
	if err != nil || result == nil {
		raw = json.RawMessage(`{}`)
	}
	return Result{CommandID: c.CommandID, Status: status, Result: raw}
}
