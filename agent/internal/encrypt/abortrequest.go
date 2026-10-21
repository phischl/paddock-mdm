package encrypt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// `paddockd encrypt-abort` hands its request to the running agent, the only writer of the agent state and the event
// spool (plan M8e decision 14 as corrected by the architect lead on 2026-10-21). The request and the response are data
// files below /var/lib/paddock (0600); a request is claimed by renaming it, so that the agent and a subcommand that
// gives up can never both act on it.
const (
	// AbortPickup is how long the subcommand waits for an agent to claim its request.
	AbortPickup = 60 * time.Second
	// AbortWait bounds the whole wait (dracut is bounded by LongTimeout).
	AbortWait = 20 * time.Minute
	// AbortStale is the age at which the agent ignores and removes a request.
	AbortStale = 30 * time.Minute
	// abortPoll is how often the subcommand looks for the response.
	abortPoll = time.Second
)

// States of an AbortResponse.
const (
	AbortRunning = "running"
	AbortDone    = "done"
)

// AbortRequest is /var/lib/paddock/encrypt-abort.request.
type AbortRequest struct {
	Nonce        string    `json:"nonce"`
	ConversionID string    `json:"conversion_id,omitempty"`
	By           string    `json:"by"`
	RequestedAt  time.Time `json:"requested_at"`
}

// AbortResponse is /var/lib/paddock/encrypt-abort.response: running once the agent claimed the request, done with
// the outcome.
type AbortResponse struct {
	Nonce   string `json:"nonce"`
	State   string `json:"state"`
	Aborted bool   `json:"aborted"`
	Reason  string `json:"reason,omitempty"`
}

// ErrNoAgent is returned when no agent claimed the request within AbortPickup; the request is withdrawn.
var ErrNoAgent = errors.New("no running Paddock agent picked up the request")

// ErrAbortTimeout is returned when the agent claimed the request but did not answer within AbortWait; it wraps
// ErrOutcomeUnknown.
var ErrAbortTimeout = errors.New("the Paddock agent did not finish the abort in time")

// ErrOutcomeUnknown is returned when the wait ended after the agent may have claimed the request: it may still abort.
var ErrOutcomeUnknown = errors.New("the Paddock agent took the request; whether it aborted is unknown")

// ErrWithdrawn is returned when ctx ended before an agent claimed the request; the request is withdrawn and nothing
// on the device was changed.
var ErrWithdrawn = errors.New("the request was withdrawn before an agent took it")

// claimSuffix and withdrawSuffix are the names a request is renamed to by the agent and by a subcommand that gives up.
const (
	claimSuffix    = ".claimed"
	withdrawSuffix = ".withdrawn"
)

// RequestAbort writes an abort request for the running agent and waits for its answer (`paddockd encrypt-abort`).
// It withdraws the request and returns ErrNoAgent when no agent claims it within AbortPickup, and ErrWithdrawn when
// ctx ends first. Once the request may have been claimed, a wait that ends returns ErrOutcomeUnknown.
func RequestAbort(ctx context.Context, l paths.Layout, conversionID string, now func() time.Time,
	sleep func(ctx context.Context, d time.Duration) error) (AbortResponse, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return AbortResponse{}, err
	}
	req := AbortRequest{Nonce: hex.EncodeToString(raw[:]), ConversionID: conversionID, By: ByOperator, RequestedAt: now().UTC()}
	data, err := json.Marshal(req)
	if err != nil {
		return AbortResponse{}, err
	}
	if err := fsutil.WriteFile(l.EncryptAbortRequest(), data, 0o600, 0o700); err != nil {
		return AbortResponse{}, err
	}
	start, claimed := now(), false
	for {
		if resp, ok := readResponse(l, req.Nonce); ok {
			claimed = true
			if resp.State == AbortDone {
				_ = os.Remove(l.EncryptAbortResponse())
				return resp, nil
			}
		}
		elapsed := now().Sub(start)
		if !claimed && elapsed >= AbortPickup {
			if withdraw(l) {
				return AbortResponse{}, ErrNoAgent
			}
			claimed = true
		}
		if elapsed >= AbortWait {
			return AbortResponse{}, fmt.Errorf("%w: %w", ErrOutcomeUnknown, ErrAbortTimeout)
		}
		if err := sleep(ctx, abortPoll); err != nil {
			if !claimed && withdraw(l) {
				return AbortResponse{}, fmt.Errorf("%w: %w", ErrWithdrawn, err)
			}
			return AbortResponse{}, fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
		}
	}
}

// withdraw takes back an unclaimed request; false when the agent claimed it first (the rename is the arbiter).
func withdraw(l paths.Layout) bool {
	withdrawn := l.EncryptAbortRequest() + withdrawSuffix
	if err := os.Rename(l.EncryptAbortRequest(), withdrawn); err != nil {
		return false
	}
	_ = os.Remove(withdrawn)
	return true
}

// readResponse reads the response of the request with nonce; false when there is none for it.
func readResponse(l paths.Layout, nonce string) (AbortResponse, bool) {
	raw, err := os.ReadFile(l.EncryptAbortResponse())
	if err != nil {
		return AbortResponse{}, false
	}
	var resp AbortResponse
	if json.Unmarshal(raw, &resp) != nil || resp.Nonce != nonce {
		return AbortResponse{}, false
	}
	return resp, true
}

// ClaimAbortRequest claims the pending abort request for the agent; nil without one. A request older than AbortStale
// or unreadable is removed and ignored.
func ClaimAbortRequest(l paths.Layout, now time.Time) (*AbortRequest, error) {
	claimed := l.EncryptAbortRequest() + claimSuffix
	if err := os.Rename(l.EncryptAbortRequest(), claimed); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(claimed) //nolint:gosec // the request path of the agent layout
	_ = os.Remove(claimed)
	if err != nil {
		return nil, err
	}
	var req AbortRequest
	if err := json.Unmarshal(raw, &req); err != nil || req.Nonce == "" {
		return nil, errors.New("unreadable encrypt-abort request ignored")
	}
	if now.Sub(req.RequestedAt) > AbortStale {
		return nil, errors.New("stale encrypt-abort request ignored")
	}
	return &req, nil
}

// WriteAbortResponse writes the agent's answer to a claimed request.
func WriteAbortResponse(l paths.Layout, resp AbortResponse) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return fsutil.WriteFile(l.EncryptAbortResponse(), data, 0o600, 0o700)
}
