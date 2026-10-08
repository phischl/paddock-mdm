package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/config"
	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/health"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/pkg/revocation"
)

// RevokeTrustFile is the path reported with revocation.trust_pinned_tofu.
const RevokeTrustFile = "/etc/paddock/revoke-trust.json"

// applyRevocation applies the revocation section of the current bundle. paddockd never interprets revocation tokens
// (plan M4c decision 11); it only keeps the files paddock-revoke checks:
//   - /etc/paddock/revoke-enabled exists exactly while the bundle says revocation.enabled (decision 1);
//   - a device without a revocation trust anchor (enrolled before M4c) pins the bundle's revocation keys once and
//     reports revocation.trust_pinned_tofu; a pinned anchor is never replaced from a bundle (decision 3).
func (a *Agent) applyRevocation(b *bundle.Bundle) {
	marker := a.d.Layout.RevokeEnabled()
	enabled := b.Revocation != nil && b.Revocation.Enabled
	_, err := os.Stat(marker)
	switch {
	case enabled && errors.Is(err, os.ErrNotExist):
		if err := fsutil.WriteFile(marker, []byte{}, 0o644, 0o755); err != nil {
			slog.Error("writing the revocation marker failed", "error", err)
		}
	case !enabled && err == nil:
		if err := os.Remove(marker); err != nil {
			slog.Error("removing the revocation marker failed", "error", err)
		}
	}
	if b.Revocation == nil || len(b.Revocation.Keys) == 0 {
		return
	}
	if _, err := os.Stat(a.d.Layout.RevokeTrust()); !errors.Is(err, os.ErrNotExist) {
		return
	}
	keys := make([]protocol.BundleKey, len(b.Revocation.Keys))
	for i, k := range b.Revocation.Keys {
		keys[i] = protocol.BundleKey{KeyID: k.KeyID, PublicKey: k.PublicKey}
	}
	if err := config.SaveRevokeTrust(a.d.Layout.RevokeTrust(), keys); err != nil {
		slog.Error("pinning the revocation keys failed", "error", err)
		return
	}
	slog.Warn("pinned the revocation keys of the bundle (trust on first use; re-enroll to replace them)")
	a.event(protocol.EventRevocationTrustPinnedTOFU, map[string]any{"file": RevokeTrustFile})
}

// handoffRetention is how long the hash of a handed revocation envelope is kept: longer than a token lives.
const handoffRetention = 31 * 24 * time.Hour

// handRevocations hands every revocation envelope of a check-in to paddock-revoke once and returns the other
// envelopes. paddockd tells revocation envelopes by their DSSE payload type only and never verifies or interprets them
// (plan M4c decision 11); a refusal is reported as revocation.refused {reason}.
func (a *Agent) handRevocations(ctx context.Context, envelopes []json.RawMessage) []json.RawMessage {
	now := a.d.Now()
	for h, at := range a.st.HandedRevocations {
		if now.Sub(at) > handoffRetention {
			delete(a.st.HandedRevocations, h)
		}
	}
	var rest []json.RawMessage
	for _, env := range envelopes {
		if !revocation.IsRevocation(env) {
			rest = append(rest, env)
			continue
		}
		sum := sha256.Sum256(env)
		h := hex.EncodeToString(sum[:])
		if _, done := a.st.HandedRevocations[h]; done {
			continue
		}
		if a.st.HandedRevocations == nil {
			a.st.HandedRevocations = map[string]time.Time{}
		}
		// Recorded first: a token is never handed twice, even if paddock-revoke reboots the device.
		a.st.HandedRevocations[h] = now
		if err := state.Save(a.d.Layout.State(), a.st); err != nil {
			slog.ErrorContext(ctx, "saving the agent state failed; revocation not handed", "error", err)
			delete(a.st.HandedRevocations, h)
			continue
		}
		refused, err := a.d.Revoke(ctx, env)
		switch {
		case err != nil:
			slog.ErrorContext(ctx, "paddock-revoke failed", "error", err)
			a.event(protocol.EventRevocationRefused, map[string]any{"reason": revokeReason(err)})
		case refused != "":
			slog.WarnContext(ctx, "paddock-revoke refused a revocation", "reason", refused)
			a.event(protocol.EventRevocationRefused, map[string]any{"reason": refused})
		}
	}
	return rest
}

// errNotInstalled means paddock-revoke is missing.
var errNotInstalled = errors.New("paddock-revoke is not installed")

func revokeReason(err error) string {
	if errors.Is(err, errNotInstalled) {
		return "not_installed"
	}
	return "internal_error"
}

// runRevoke runs `paddock-revoke execute [args]` with the envelope on stdin. Exit 2 is a refusal with
// {"refused": "<reason>"} on stdout; exit 0 an executed token (a real device reboots before it returns) or a stored
// self-lock token.
// capabilitiesTimeout bounds `paddock-revoke capabilities`.
const capabilitiesTimeout = 10 * time.Second

// refreshRevokeCapabilities reports what the installed paddock-revoke understands in the health report, so that the
// revocation-issuer adds the volumes of a Lock only for a build that accepts them (PDK-009). paddockd only passes the
// answer on: a false report can only make the issuer leave the volumes out (the build then erases the root volume
// and, before PDK-009, every volume) or make an old build refuse the token; it never selects what is erased.
func (a *Agent) refreshRevokeCapabilities(ctx context.Context) {
	caps, err := a.d.RevokeCapabilities(ctx)
	if err != nil {
		slog.DebugContext(ctx, "paddock-revoke reports no capabilities", "error", err)
		caps = nil
	}
	a.d.Health.Update(func(r *health.Report) { r.RevokeCapabilities = caps })
}

// revokeCapabilities runs `paddock-revoke capabilities`; a build before PDK-009 fails (unknown command).
func revokeCapabilities(ctx context.Context, binary string) ([]string, error) {
	if _, err := os.Stat(binary); err != nil {
		return nil, errNotInstalled
	}
	ctx, cancel := context.WithTimeout(ctx, capabilitiesTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "capabilities") //nolint:gosec // the fixed path of paddock-revoke
	cmd.Env = slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(e, "NOTIFY_SOCKET=") })
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("paddock-revoke capabilities: %w", err)
	}
	var c revocation.Capabilities
	if err := json.Unmarshal(out, &c); err != nil {
		return nil, fmt.Errorf("paddock-revoke capabilities: %w", err)
	}
	return c.Capabilities, nil
}

func runRevoke(ctx context.Context, binary string, envelope []byte, args ...string) (string, error) {
	if _, err := os.Stat(binary); err != nil {
		return "", errNotInstalled
	}
	// Not canceled with the agent: a stop of paddockd must never interrupt paddock-revoke inside its sequence.
	cmd := exec.CommandContext(context.WithoutCancel(ctx), binary, append([]string{"execute"}, args...)...) //nolint:gosec // the fixed path of paddock-revoke
	cmd.Stdin = bytes.NewReader(envelope)
	cmd.Env = slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(e, "NOTIFY_SOCKET=") })
	out, err := cmd.Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 2 {
		var r struct {
			Refused string `json:"refused"`
		}
		if json.Unmarshal(out, &r) == nil && r.Refused != "" {
			return r.Refused, nil
		}
	}
	if err != nil {
		return "", fmt.Errorf("paddock-revoke: %w", err)
	}
	return "", nil
}
