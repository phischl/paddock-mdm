package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"

	"github.com/phischl/paddock-mdm/agent/internal/commands"
	"github.com/phischl/paddock-mdm/agent/internal/localadmin"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/policy"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// escrowClient binds the escrow endpoints of the device API to this device.
type escrowClient struct{ a *Agent }

func (e escrowClient) Upload(ctx context.Context, req escrow.Request) error {
	_, err := e.a.d.Client.EscrowUpload(ctx, e.a.st.DeviceID, e.a.st.Seq, req)
	return err
}

// UploadHeader announces a sealed LUKS header and PUTs it to the presigned URL of the answer.
func (e escrowClient) UploadHeader(ctx context.Context, req escrow.Request, object []byte) error {
	accepted, err := e.a.d.Client.EscrowUpload(ctx, e.a.st.DeviceID, e.a.st.Seq, req)
	if err != nil {
		return err
	}
	if accepted.UploadURL == "" {
		return errors.New("the server answered the header escrow without an upload URL")
	}
	return e.a.d.Client.Upload(ctx, accepted.UploadURL, object)
}

func (e escrowClient) Status(ctx context.Context, escrowID string) (string, error) {
	return e.a.d.Client.EscrowStatus(ctx, e.a.st.DeviceID, e.a.st.Seq, escrowID)
}

// localAdminSpec is the local administrator of the applied bundle's login resource (nil: not managed).
func (a *Agent) localAdminSpec() *bundle.LocalAdminSpec {
	if a.current == nil {
		return nil
	}
	for _, r := range a.current.Resources {
		if r.Type != bundle.TypeLogin {
			continue
		}
		var spec bundle.LoginSpec
		if json.Unmarshal(r.Spec, &spec) != nil || spec.LocalAdmin == nil || spec.LocalAdmin.RotationDays < 1 {
			return nil
		}
		// Defence in depth: a plain local account name (never an option for the account tools) that is a break-glass
		// account, so no other reconciler restricts it.
		if !slices.Contains(spec.BreakGlassAccounts, spec.LocalAdmin.Username) || policy.ValidateOwner(spec.LocalAdmin.Username) != nil {
			return nil
		}
		return spec.LocalAdmin
	}
	return nil
}

// tickLocalAdmin advances the managed local administrator (plan M4a decision 15).
func (a *Agent) tickLocalAdmin(ctx context.Context) {
	if a.d.Accounts == nil || a.st.DeviceID == "" {
		return
	}
	a.localAdmin.Tick(ctx, a.localAdminSpec(), a.bundleKeys())
}

// bundleKeys are the keys of the applied bundle (nil without one).
func (a *Agent) bundleKeys() *bundle.Keys {
	if a.current == nil {
		return nil
	}
	return a.current.Keys
}

// localAdminLogin reports a session of the local administrator (plan M4a decision 16): the PAM service and the time
// only.
func (a *Agent) localAdminLogin(l localadmin.Login) {
	spec := a.localAdminSpec()
	if spec == nil || l.User != spec.Username {
		return
	}
	a.event(protocol.EventLocalAdminLogin, protocol.LocalAdminLogin{Service: l.Service, At: l.At})
}

// rotateCommand defers rotate_admin_password to the next rotation, which reports its result.
func (a *Agent) rotateCommand(_ context.Context, c *command.Command) (string, map[string]any) {
	if a.localAdminSpec() == nil {
		return protocol.CommandFailed, map[string]any{"reason": "not_managed"}
	}
	a.localAdmin.Request(c.CommandID)
	return commands.Deferred, nil
}

// commandResult keeps the result of a deferred command until the server accepted it.
func (a *Agent) commandResult(commandID, status string, result map[string]any) {
	a.st.CommandResults = append(a.st.CommandResults, state.CommandResult{CommandID: commandID, Status: status, Result: commands.Encode(result)})
}

// persist saves the agent state.
func (a *Agent) persist() error {
	err := state.Save(a.d.Layout.State(), a.st)
	if err != nil {
		slog.Error("saving agent state failed", "error", err)
	}
	return err
}
