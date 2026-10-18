package system

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

// notFound answers every request with 404, a request the helpers do not expect.
type notFound struct{}

func (notFound) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(nil)), Request: r}, nil
}

// TestStackHelpersTakeTheCallersT (PDK-298): a Stack helper that fails inside a gate's subtest fails that subtest
// only; the next subtest still runs and the run does not panic with "subtest may have called FailNow on a parent
// test". A failing subtest fails its parents, so the scenario runs in a child process (TestStackHelperScenario).
func TestStackHelpersTakeTheCallersT(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestStackHelperScenario$", "-test.v")
	cmd.Env = append(os.Environ(), "PADDOCK_SYSTEM_STACK_SCENARIO=1")
	out, _ := cmd.CombinedOutput()
	for _, want := range []string{"--- FAIL: TestStackHelperScenario/gate/failing", "--- PASS: TestStackHelperScenario/gate/next"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("scenario output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(string(out), "panic") || strings.Contains(string(out), "FailNow on a parent") {
		t.Errorf("scenario panicked:\n%s", out)
	}
}

// TestStackHelperScenario is the child process of TestStackHelpersTakeTheCallersT.
func TestStackHelperScenario(t *testing.T) {
	if os.Getenv("PADDOCK_SYSTEM_STACK_SCENARIO") != "1" {
		t.Skip("child process of TestStackHelpersTakeTheCallersT")
	}
	s := &Stack{alice: &portal.Session{Client: &http.Client{Transport: notFound{}}}}
	t.Run("gate", func(t *testing.T) {
		t.Run("failing", func(t *testing.T) {
			s.Call(t, http.MethodGet, "/api/v1/devices", nil, http.StatusOK)
		})
		t.Run("next", func(t *testing.T) {
			s.Call(t, http.MethodGet, "/api/v1/devices", nil, http.StatusNotFound)
		})
	})
}
