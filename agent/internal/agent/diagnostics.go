package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/client"
	"github.com/phischl/paddock-mdm/agent/internal/commands"
	"github.com/phischl/paddock-mdm/agent/internal/desktop"
	"github.com/phischl/paddock-mdm/agent/internal/diagnostics"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// collectTimeout bounds the collection of a diagnostics bundle (every command of the list has its own 30 s).
const collectTimeout = 5 * time.Minute

var commandUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// errRefused is a refusal reason of collect_status with its cause, for the log.
type errRefused struct {
	reason string
	err    error
}

func (e *errRefused) Error() string { return e.reason + ": " + e.err.Error() }

func refuse(reason string, err error) error { return &errRefused{reason: reason, err: err} }

// diagnosticsJob is an accepted collect_status command for the diagnostics worker, with what the worker needs of the
// loop's state taken when the command was accepted; diagnosticsDone is its result.
type (
	diagnosticsJob struct {
		commandID string
		reason    string
		deviceID  string
		seq       int64
		keys      *bundle.Keys
	}
	diagnosticsDone struct {
		commandID string
		status    string
		result    map[string]any
	}
)

// diagnosticsQueue bounds the collect_status commands waiting for the worker.
const diagnosticsQueue = 4

// collectStatusCommand is the command collect_status (plan M12 decision 10). It checks the params and hands the
// collection to the diagnostics worker, which reports the result when done: notice, collection, sealing and upload
// take minutes, during which the run loop keeps checking in and re-verifying the protected areas. A pending
// revocation, uninstall or conversion does not refuse it: the device's state is what the operator wants to see.
func (a *Agent) collectStatusCommand(ctx context.Context, c *command.Command) (string, map[string]any) {
	var p command.CollectStatusParams
	if json.Unmarshal(c.Params, &p) != nil || p.RequestID != c.CommandID || !commandUUID.MatchString(p.RequestID) {
		return protocol.CommandFailed, collectResult(command.CollectStatusResult{Reason: command.CollectStatusInvalidParams})
	}
	reason := strings.TrimSpace(p.Reason)
	if n := utf8.RuneCountInString(reason); n < 2 || n > 500 {
		return protocol.CommandFailed, collectResult(command.CollectStatusResult{Reason: command.CollectStatusInvalidParams})
	}
	if a.d.Sys == nil {
		return protocol.CommandFailed, collectResult(command.CollectStatusResult{Reason: command.CollectStatusCollectFailed})
	}
	select {
	case a.diagnosticsJobs <- diagnosticsJob{commandID: c.CommandID, reason: reason, deviceID: a.st.DeviceID, seq: a.st.Seq,
		keys: a.bundleKeys()}:
	default:
		slog.WarnContext(ctx, "diagnostics collection refused: too many waiting", "command_id", c.CommandID)
		return protocol.CommandFailed, collectResult(command.CollectStatusResult{Reason: command.CollectStatusCollectFailed})
	}
	return commands.Deferred, nil
}

// runDiagnostics executes the queued collect_status commands one after another until ctx ends; ctx also aborts a
// running collection. A finished result is handed back even at shutdown while diagnosticsDone has room, and Run
// keeps it (drainDiagnostics). Accepted loss: an aborted collection and a queued one that has not started get no
// result; the server lets their commands expire.
func (a *Agent) runDiagnostics(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-a.diagnosticsJobs:
			status, result := a.collectStatus(ctx, job)
			d := diagnosticsDone{commandID: job.commandID, status: status, result: result}
			select {
			case a.diagnosticsDone <- d:
				continue
			default:
			}
			select {
			case a.diagnosticsDone <- d:
			case <-ctx.Done():
				return
			}
		}
	}
}

// drainDiagnostics keeps the results the worker returned after the loop stopped, once the worker is joined: their
// bundles are uploaded, and the results reach the server at the first check-in after the restart.
func (a *Agent) drainDiagnostics() {
	for {
		select {
		case d := <-a.diagnosticsDone:
			a.finishDiagnostics(d)
		default:
			return
		}
	}
}

// finishDiagnostics keeps the result of a collect_status command until the server accepted it.
func (a *Agent) finishDiagnostics(d diagnosticsDone) {
	a.commandResult(d.commandID, d.status, d.result)
	a.saveState()
}

// collectStatus tells the users of the device's graphical sessions, collects the closed list of the diagnostics
// bundle into a temporary file, seals it to the bundle's escrow key, announces and uploads it and returns the
// command status and result with the facts of the bundle.
func (a *Agent) collectStatus(ctx context.Context, job diagnosticsJob) (string, map[string]any) {
	summary, body := diagnostics.Notice(desktop.Language(a.d.Sys), job.reason)
	notified, err := desktop.Notify(ctx, a.d.Sys, summary, body)
	switch {
	case err != nil:
		slog.WarnContext(ctx, "the users were not notified of the diagnostics collection", "command_id", job.commandID, "error", err)
	case notified == 0:
		slog.InfoContext(ctx, "no active graphical session to notify of the diagnostics collection", "command_id", job.commandID)
	}
	res, err := a.collectAndUpload(ctx, job)
	res.NotifiedSessions = notified
	if err != nil {
		var r *errRefused
		res.Reason = command.CollectStatusCollectFailed
		if errors.As(err, &r) {
			res.Reason = r.reason
		}
		slog.WarnContext(ctx, "diagnostics bundle not uploaded", "command_id", job.commandID, "reason", res.Reason, "error", err)
		return protocol.CommandFailed, collectResult(res)
	}
	slog.InfoContext(ctx, "diagnostics bundle uploaded", "command_id", job.commandID, "files", res.Files, "bytes", res.Bytes,
		"notified_sessions", notified)
	return protocol.CommandSucceeded, collectResult(res)
}

// collectAndUpload collects into the temporary file, seals, announces and uploads; the temporary files are gone when
// it returns.
func (a *Agent) collectAndUpload(ctx context.Context, job diagnosticsJob) (command.CollectStatusResult, error) {
	id := job.commandID
	pub, err := diagnosticsKey(job.keys)
	if err != nil {
		return command.CollectStatusResult{}, refuse(command.CollectStatusCollectFailed, err)
	}
	dir := a.d.Layout.Diagnostics()
	if err := resetDir(dir); err != nil {
		return command.CollectStatusResult{}, refuse(command.CollectStatusCollectFailed, err)
	}
	file := filepath.Join(dir, id+".tar.gz")
	defer func() { _ = os.Remove(file) }()
	m, size, err := a.collectTo(ctx, file, job.deviceID)
	if err != nil {
		return command.CollectStatusResult{}, refuse(command.CollectStatusCollectFailed, err)
	}
	dek := make([]byte, 32)
	defer clear(dek)
	if _, err := rand.Read(dek); err != nil {
		return command.CollectStatusResult{}, refuse(command.CollectStatusCollectFailed, err)
	}
	sealed, nonce, err := sealFile(dek, id, file)
	switch {
	case errors.Is(err, escrow.ErrObjectTooLarge) || err == nil && len(sealed) > protocol.MaxDiagnosticsObject:
		return command.CollectStatusResult{}, refuse(command.CollectStatusTooLarge, fmt.Errorf("archive of %d bytes", size))
	case err != nil:
		return command.CollectStatusResult{}, refuse(command.CollectStatusCollectFailed, err)
	}
	_ = os.Remove(file)
	wrapped, err := escrow.Encrypt(pub, dek)
	if err != nil {
		return command.CollectStatusResult{}, refuse(command.CollectStatusCollectFailed, err)
	}
	sum := sha256.Sum256(sealed)
	answer, err := a.d.Client.Diagnostics(ctx, job.deviceID, job.seq, protocol.DiagnosticsRequest{CommandID: id,
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(sealed)), Nonce: base64.StdEncoding.EncodeToString(nonce),
		WrappedDEK: wrapped})
	var apiErr *client.APIError
	switch {
	case errors.As(err, &apiErr) && apiErr.Status >= 400 && apiErr.Status < 500 && apiErr.Status != http.StatusTooManyRequests:
		return command.CollectStatusResult{}, refuse(command.CollectStatusUploadRefused, err)
	case err != nil:
		return command.CollectStatusResult{}, refuse(command.CollectStatusUploadFailed, err)
	case answer.UploadURL == "":
		return command.CollectStatusResult{}, refuse(command.CollectStatusUploadRefused, errors.New("no upload URL"))
	}
	if err := a.d.Client.Upload(ctx, answer.UploadURL, sealed); err != nil {
		return command.CollectStatusResult{}, refuse(command.CollectStatusUploadFailed, err)
	}
	return command.CollectStatusResult{Uploaded: true, Files: m.Files(), Bytes: size, TruncatedEntries: m.Truncated()}, nil
}

// collectTo writes the archive to file (0600) and returns its manifest and size.
func (a *Agent) collectTo(ctx context.Context, file, deviceID string) (diagnostics.Manifest, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // below the agent's own directory, the ID is a UUID
	if err != nil {
		return diagnostics.Manifest{}, 0, err
	}
	src := diagnostics.Sources{Health: a.d.Health, DeviceID: deviceID, AgentVersion: buildinfo.Version, Now: a.d.Now()}
	if a.d.Client != nil {
		src.Healthz = a.d.Client.Healthz
	}
	m, err := diagnostics.Collect(ctx, a.d.Sys, src, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return diagnostics.Manifest{}, 0, err
	}
	info, err := os.Stat(file)
	if err != nil {
		return diagnostics.Manifest{}, 0, err
	}
	return m, info.Size(), nil
}

func sealFile(dek []byte, id, file string) (sealed, nonce []byte, err error) {
	f, err := os.Open(file) //nolint:gosec // the archive collectTo wrote
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	return escrow.SealObject(dek, id, f)
}

// sweepDiagnostics removes the plaintext archive a collection left when the agent was killed during it.
func (a *Agent) sweepDiagnostics() {
	if err := resetDir(a.d.Layout.Diagnostics()); err != nil {
		slog.Warn("removing leftover diagnostics files failed", "error", err)
	}
}

// resetDir creates the diagnostics directory (0700) and removes what an interrupted collection left in it.
func resetDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// diagnosticsKey is the escrow-wrap key of the applied bundle. POST /v1/diagnostics carries no key version: the
// server unwraps with the latest one (PDK-779).
func diagnosticsKey(keys *bundle.Keys) (*rsa.PublicKey, error) {
	if keys == nil || keys.EscrowWrap == nil {
		return nil, errors.New("the applied bundle has no escrow key")
	}
	return escrow.ParsePublicKey(keys.EscrowWrap.PublicKeyPEM)
}

// collectResult is the result object of collect_status.
func collectResult(r command.CollectStatusResult) map[string]any {
	raw, _ := json.Marshal(r)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}
