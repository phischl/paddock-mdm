package devicecache

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go"
)

// DiagnosticsClaimTTL is how long the gateway remembers that a collect_status command was announced (diag:<command_id>):
// beyond the command's lifetime of one hour, after which the command is no longer held for the device anyway.
const DiagnosticsClaimTTL = 24 * time.Hour

func diagnosticsKey(id uuid.UUID) string { return "diag:" + id.String() }

// ClaimDiagnostics records the first announcement of the diagnostics bundle of command id by device; it reports false
// when the bundle was announced before (plan M12 decision 5: 409 already_uploaded).
func (c *Cache) ClaimDiagnostics(ctx context.Context, device, id uuid.UUID) (bool, error) {
	err := c.c.Do(ctx, c.c.B().Set().Key(diagnosticsKey(id)).Value(device.String()).Nx().Ex(DiagnosticsClaimTTL).Build()).Error()
	if valkey.IsValkeyNil(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("devicecache: claim diagnostics: %w", err)
	}
	return true, nil
}

// ReleaseDiagnostics takes back a claim of ClaimDiagnostics whose announcement could not be published, so the device's
// retry is not refused.
func (c *Cache) ReleaseDiagnostics(ctx context.Context, device, id uuid.UUID) error {
	if err := releaseScript.Exec(ctx, c.c, []string{diagnosticsKey(id)}, []string{device.String()}).Error(); err != nil {
		return fmt.Errorf("devicecache: release diagnostics: %w", err)
	}
	return nil
}
