// Package update is the agent's side of the update protocol with paddock-supervisor (plan M2b decision 16): it
// stages an offered release (size and SHA-256 checked) and asks the supervisor to install it with SIGUSR1; the
// supervisor alone verifies the release signature, switches slots and writes the result, which the agent turns into
// an event.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/client"
	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Outcomes of an update attempt (update-result.json).
const (
	OutcomeUpdated          = "updated"
	OutcomeSelfTestFailed   = "self_test_failed"
	OutcomeRolledBack       = "rolled_back"
	OutcomeSignatureInvalid = "signature_invalid"
	OutcomeDowngradeRefused = "downgrade_refused"
)

// MaxBinary bounds an agent release download.
const MaxBinary = 256 << 20

// VersionPattern is the accepted form of release versions (semantic version, no path characters).
var VersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// Request is staging/request.json.
type Request struct {
	Version string `json:"version"`
}

// Result is state/update-result.json, written by the supervisor.
type Result struct {
	Version     string    `json:"version"`
	FromVersion string    `json:"from_version"`
	Outcome     string    `json:"outcome"`
	At          time.Time `json:"at"`
}

// EventType maps an outcome to the device event type.
func (r Result) EventType() string {
	switch r.Outcome {
	case OutcomeUpdated:
		return protocol.EventAgentUpdated
	case OutcomeRolledBack:
		return protocol.EventAgentRolledBack
	default:
		return protocol.EventAgentUpdateFailed
	}
}

// Stage downloads an offered release into staging/<version>/ and writes request.json.
func Stage(ctx context.Context, l paths.Layout, c *client.Client, offer protocol.AgentUpdate) error {
	if !VersionPattern.MatchString(offer.Version) {
		return fmt.Errorf("invalid release version %q", offer.Version)
	}
	if offer.Size <= 0 || offer.Size > MaxBinary {
		return fmt.Errorf("invalid release size %d", offer.Size)
	}
	sig, err := base64.StdEncoding.DecodeString(offer.Minisig)
	if err != nil || len(sig) == 0 {
		return errors.New("invalid release signature encoding")
	}
	bin, err := c.Download(ctx, offer.URL, offer.Size)
	if err != nil {
		return fmt.Errorf("download release %s: %w", offer.Version, err)
	}
	sum := sha256.Sum256(bin)
	if int64(len(bin)) != offer.Size || !strings.EqualFold(hex.EncodeToString(sum[:]), offer.SHA256) {
		return fmt.Errorf("release %s: size or SHA-256 differs from the offer", offer.Version)
	}
	dir := filepath.Join(l.Staging(), offer.Version)
	if err := fsutil.WriteFile(filepath.Join(dir, "paddockd"), bin, 0o700, 0o700); err != nil {
		return err
	}
	if err := fsutil.WriteFile(filepath.Join(dir, "paddockd.minisig"), sig, 0o600, 0o700); err != nil {
		return err
	}
	data, _ := json.Marshal(Request{Version: offer.Version})
	return fsutil.WriteFile(l.UpdateRequest(), data, 0o600, 0o700)
}

// Pending reports whether a request waits for the supervisor.
func Pending(l paths.Layout) bool {
	_, err := os.Stat(l.UpdateRequest())
	return err == nil
}

// supervisorComm is the process name of paddock-supervisor as /proc/<pid>/comm shows it (15 characters).
const supervisorComm = "paddock-supervi"

// SupervisorPID returns the parent PID if the parent is paddock-supervisor.
func SupervisorPID(l paths.Layout) (int, error) {
	ppid := os.Getppid()
	comm, err := os.ReadFile(l.Join("/proc/" + strconv.Itoa(ppid) + "/comm"))
	if err != nil || strings.TrimSpace(string(comm)) != supervisorComm {
		return 0, errors.New("not running under paddock-supervisor")
	}
	return ppid, nil
}

// Notify asks the supervisor (pid) to process the staged request.
func Notify(pid int) error { return syscall.Kill(pid, syscall.SIGUSR1) }

// ReadResult reads update-result.json; nil without a result.
func ReadResult(l paths.Layout) (*Result, error) {
	data, err := os.ReadFile(l.UpdateResult())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Result
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", l.UpdateResult(), err)
	}
	return &r, nil
}

// RemoveResult deletes update-result.json once its event was accepted.
func RemoveResult(l paths.Layout) error {
	if err := os.Remove(l.UpdateResult()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
