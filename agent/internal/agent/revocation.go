package agent

import (
	"errors"
	"log/slog"
	"os"

	"github.com/phischl/paddock-mdm/agent/internal/config"
	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
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
