package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
)

type apiError struct{ id string }

func (e *apiError) Error() string {
	return "StatusCode: 503, RequestID: " + e.id + ", api error SlowDown"
}
func (e *apiError) ErrorCode() string   { return "SlowDown" }
func (e *apiError) HTTPStatusCode() int { return 503 }

// TestBuildFailure (PDK-813, review 1): the recorded form of a failed build's error carries no request ID or client
// port, so the same failure is recorded once; an error without such parts is recorded as it is.
func TestBuildFailure(t *testing.T) {
	dial := func(port int) error {
		return &net.OpError{Op: "read", Net: "tcp", Source: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 3), Port: port},
			Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 9000}, Err: errors.New("connection reset by peer")}
	}
	timeout := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"API error", &buildStepError{step: "upload InRelease", err: fmt.Errorf("put: %w", &apiError{id: "A1"})},
			"upload InRelease: SlowDown, HTTP 503"},
		{"network error", &buildStepError{step: "upload Release", err: dial(54321)}, "upload Release: network error"},
		{"timeout", &buildStepError{step: "upload Release", err: timeout}, "upload Release: network timeout"},
		{"deadline", &buildStepError{step: "decrypt the signing key", err: context.DeadlineExceeded},
			"decrypt the signing key: network timeout"},
		{"OpenBao error", &buildStepError{step: "decrypt the signing key", err: errors.New("bao: decrypt: Vault is sealed")},
			"decrypt the signing key: bao: decrypt: Vault is sealed"},
		{"other error", errors.New("control fields of a 1 amd64: bad"), "control fields of a 1 amd64: bad"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := buildFailure(c.err); got != c.want {
				t.Fatalf("buildFailure = %q, want %q", got, c.want)
			}
		})
	}
	first := buildFailure(&buildStepError{step: "upload Release", err: dial(40001)})
	if second := buildFailure(&buildStepError{step: "upload Release", err: dial(40002)}); first != second {
		t.Fatalf("two network errors differing in the client port: %q, %q", first, second)
	}
	if a, b := buildFailure(&buildStepError{step: "s", err: &apiError{id: "A1"}}),
		buildFailure(&buildStepError{step: "s", err: &apiError{id: "B2"}}); a != b {
		t.Fatalf("two API errors differing in the request ID: %q, %q", a, b)
	}
}
