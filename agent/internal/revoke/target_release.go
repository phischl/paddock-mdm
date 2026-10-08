//go:build !paddock_revoke_testtarget

package revoke

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/luks"
)

// dayLength is a day of a self-lock token's period_days.
const dayLength = 24 * time.Hour

// Targets implements System: the root volume and every other LUKS volume of /etc/crypttab (plan M4c.1 decision 1).
// A release binary refuses every token while the test target override exists, so it can never be pointed elsewhere
// (plan M4c decision 13).
func (o OS) Targets(ctx context.Context) (Targets, error) {
	if _, err := os.Lstat(o.path(TestTargetFile)); !errors.Is(err, fs.ErrNotExist) {
		return Targets{}, refuse(ReasonTestTarget)
	}
	v, err := luks.Root(ctx, o.OS)
	if err != nil {
		return Targets{}, err
	}
	return crypttabTargets(ctx, o.OS, o.Root, v.Device), nil
}

// Reboot implements System.
func (OS) Reboot(ctx context.Context) error {
	_, _, err := command(ctx, "systemctl", "reboot", "--force", "--force")
	return err
}
