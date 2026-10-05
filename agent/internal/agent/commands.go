package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/client"
	"github.com/paddock-mdm/paddock/agent/internal/state"
	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// handleCommands executes the commands of a check-in with the command keys of the applied bundle (plan M4a
// decision 3) and keeps their results until the server accepted them.
func (a *Agent) handleCommands(ctx context.Context, envelopes []json.RawMessage) {
	if a.st.ExecutedCommands == nil {
		a.st.ExecutedCommands = map[string]time.Time{}
	}
	var keys *bundle.Keys
	if a.current != nil {
		keys = a.current.Keys
	}
	results, err := a.d.Commands.Run(ctx, envelopes, keys, a.st.DeviceID, a.d.Config.OrganizationID, a.st.ExecutedCommands,
		func() error { return state.Save(a.d.Layout.State(), a.st) })
	if err != nil {
		slog.WarnContext(ctx, "commands not executed", "error", err)
	}
	for _, r := range results {
		a.st.CommandResults = append(a.st.CommandResults, state.CommandResult{CommandID: r.CommandID, Status: r.Status, Result: r.Result})
	}
	if len(results) > 0 {
		a.saveState()
	}
}

// postResults reports the kept command results in order. A result the server refuses as unknown (404, e.g. the
// command expired meanwhile) or conflicting (409) is dropped; any other failure is retried at the next check-in.
func (a *Agent) postResults(ctx context.Context) {
	for len(a.st.CommandResults) > 0 {
		r := a.st.CommandResults[0]
		err := a.d.Client.CommandResult(ctx, a.st.DeviceID, a.st.Seq, r.CommandID, protocol.CommandResult{Status: r.Status, Result: r.Result})
		var apiErr *client.APIError
		switch {
		case err == nil:
		case errors.As(err, &apiErr) && (apiErr.Status == http.StatusNotFound || apiErr.Status == http.StatusConflict):
			slog.WarnContext(ctx, "command result refused; dropped", "command_id", r.CommandID, "error", err)
		default:
			slog.WarnContext(ctx, "sending command result failed; retrying at the next check-in", "command_id", r.CommandID, "error", err)
			return
		}
		a.st.CommandResults = a.st.CommandResults[1:]
		a.saveState()
	}
}
