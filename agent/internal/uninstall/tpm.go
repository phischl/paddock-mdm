package uninstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/luks"
)

// TPM re-checks the disks and clears the TPM (plan M8d decision 40 step 9).
type TPM interface {
	// InUse reports whether the root volume or a volume of /etc/crypttab has a tpm2 or tpm2+pin keyslot; a volume that
	// cannot be read counts as in use.
	InUse(ctx context.Context) (bool, error)
	// Clear clears the TPM with the lockout hierarchy's empty authorization; ErrTPMAuth when the TPM refuses it.
	Clear(ctx context.Context) error
	// RequestClear asks the firmware to clear the TPM at the next boot (PPI operation 5).
	RequestClear() error
}

// ErrTPMAuth is a clear the TPM refused for its authorization (a lockout authorization is set).
var ErrTPMAuth = errors.New("uninstall: the TPM refused the clear authorization")

// clearTPM clears the TPM only while no disk unlocks with it; an authorization failure asks the firmware instead.
func (h *Helper) clearTPM(ctx context.Context) (result, step string) {
	inUse, err := h.TPM.InUse(ctx)
	if err != nil || inUse {
		return TPMSkippedInUse, stepSkipped
	}
	err = h.TPM.Clear(ctx)
	switch {
	case err == nil:
		return TPMCleared, stepDone
	case errors.Is(err, ErrTPMAuth):
		if perr := h.TPM.RequestClear(); perr != nil {
			return TPMFailed, failed("%v; physical presence request: %v", err, perr)
		}
		return TPMRequestedAtNextBoot, stepDone
	}
	return TPMFailed, failed("%v", err)
}

// DeviceTPM is the TPM of a device: the LUKS volumes through cryptsetup, the TPM through tpm2_clear and the PPI file.
type DeviceTPM struct {
	Tools luks.Tools
	Root  string
	Run   Runner
}

// tpmKinds are the keyslot kinds that unlock with the TPM.
var tpmKinds = []string{luks.KindTPM2, luks.KindTPM2PIN}

// InUse implements TPM.
func (d DeviceTPM) InUse(ctx context.Context) (bool, error) {
	var devices []string
	root, err := luks.Root(ctx, d.Tools)
	switch {
	case err == nil:
		devices = append(devices, root.Device)
	case !errors.Is(err, luks.ErrNotEncrypted):
		return true, err
	}
	ct := luks.ReadCrypttab(ctx, d.Tools, d.Root, root.Device, 30*time.Second)
	if len(ct.Unresolved) > 0 {
		return true, fmt.Errorf("unresolved crypttab entries %v", ct.Unresolved)
	}
	for _, v := range ct.Volumes {
		devices = append(devices, v.Header)
	}
	for _, dev := range devices {
		inv, err := luks.Inspect(ctx, d.Tools, dev)
		if err != nil {
			return true, err
		}
		if slices.ContainsFunc(inv.Kinds, func(k string) bool { return slices.Contains(tpmKinds, k) }) {
			return true, nil
		}
	}
	return false, nil
}

// tpmAuthCodes are the TPM response codes of a refused authorization (TPM_RC_BAD_AUTH, TPM_RC_AUTH_FAIL,
// TPM_RC_LOCKOUT) as tpm2-tools prints them.
var tpmAuthCodes = []string{"0x9a2", "0x98e", "0x921"}

// Clear implements TPM.
func (d DeviceTPM) Clear(ctx context.Context) error {
	out, exit, err := d.Run(ctx, time.Minute, "tpm2_clear", "-c", "l")
	switch {
	case err != nil:
		return err
	case exit == 0:
		return nil
	}
	lower := strings.ToLower(out)
	if slices.ContainsFunc(tpmAuthCodes, func(c string) bool { return strings.Contains(lower, c) }) {
		return fmt.Errorf("%w: %s", ErrTPMAuth, strings.TrimSpace(out))
	}
	return fmt.Errorf("tpm2_clear: exit %d: %s", exit, strings.TrimSpace(out))
}

// ppiRequest is the physical presence interface of the first TPM.
const ppiRequest = "/sys/class/tpm/tpm0/ppi/request"

// RequestClear implements TPM.
func (d DeviceTPM) RequestClear() error {
	return os.WriteFile(d.Root+ppiRequest, []byte("5"), 0o600) //nolint:gosec // fixed sysfs file below the root
}
