//go:build !paddock_revoke_testtarget

package revoke

import (
	"context"
	"errors"
	"io/fs"
	"os"

	"github.com/phischl/paddock-mdm/agent/internal/luks"
)

// RootDevice implements System: the LUKS volume of the root file system. A release binary refuses every token while
// the test target override exists, so it can never be pointed elsewhere (plan M4c decision 13).
func (o OS) RootDevice(ctx context.Context) (string, error) {
	if _, err := os.Lstat(o.path(TestTargetFile)); !errors.Is(err, fs.ErrNotExist) {
		return "", refuse(ReasonTestTarget)
	}
	v, err := luks.Root(ctx, o.OS)
	return v.Device, err
}

// Reboot implements System.
func (OS) Reboot(ctx context.Context) error {
	_, _, err := command(ctx, "systemctl", "reboot", "--force", "--force")
	return err
}
