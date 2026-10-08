//go:build paddock_revoke_testtarget

package revoke

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
)

// dayLength is a day of a self-lock token's period_days: a minute in test builds, so the dead man's switch gate runs
// in minutes (plan M4c gate R6).
const dayLength = time.Minute

// Targets implements System for test builds: only the LUKS device named in TestTargetFile (a secondary disk of a
// test VM), never the root volume and never the volumes of /etc/crypttab (plan M4c.1 decision 1).
func (o OS) Targets(context.Context) (Targets, error) {
	data, err := os.ReadFile(o.path(TestTargetFile))
	if err != nil {
		return Targets{}, err
	}
	device := strings.TrimSpace(string(data))
	if !strings.HasPrefix(device, "/dev/") {
		return Targets{}, errors.New("revoke: the test target is no device path")
	}
	return Targets{Devices: []string{device}}, nil
}

// Reboot implements System for test builds: it writes the time it would reboot to WouldRebootFile.
func (o OS) Reboot(context.Context) error {
	return fsutil.WriteFile(o.path(WouldRebootFile), []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o644, 0o755)
}
