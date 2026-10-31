// Package sink is the acceptance gates' webhook receiver (plan M9 decision 26, amendment B0.5): an HTTP server on the
// test host, on a port the test chooses, which the stack's notifier reaches as acceptance-host through the Docker host
// gateway. It records every request and answers with a status the test sets.
package sink

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Host is the name under which the development stack's notifier reaches the test host (compose.dev.yaml extra_hosts).
const Host = "acceptance-host"

// Request is one received request.
type Request struct {
	Header   http.Header
	Body     []byte
	Received time.Time
}

// Sink is a running receiver.
type Sink struct {
	srv  *httptest.Server
	port int

	mu       sync.Mutex
	requests []Request
	status   int
	location string
	hold     time.Duration
}

// Start listens on an ephemeral port of every interface of the test host (two development stacks may share the host,
// PDK-519) and stops when the test ends. It answers 204 until Respond changes it.
func Start(t testing.TB) *Sink {
	t.Helper()
	// Every interface: the stack's containers arrive through the Docker bridge gateway, not through loopback.
	ln, err := net.Listen("tcp", ":0") //nolint:gosec // a test receiver on the test host only
	if err != nil {
		t.Fatalf("sink: listen: %v", err)
	}
	s := &Sink{status: http.StatusNoContent, port: ln.Addr().(*net.TCPAddr).Port}
	s.srv = &httptest.Server{Listener: ln, Config: &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}}
	s.srv.Start()
	t.Cleanup(func() {
		// A held answer would keep Close waiting; the notifier sees a broken connection, which is fine at the end.
		s.srv.CloseClientConnections()
		s.srv.Close()
	})
	return s
}

// URL is the webhook URL of the sink as the stack reaches it.
func (s *Sink) URL() string { return fmt.Sprintf("http://%s:%d/hook", Host, s.port) }

// Respond makes the sink answer every following request with status; a 3xx carries a Location.
func (s *Sink) Respond(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
	s.location = fmt.Sprintf("http://%s:%d/elsewhere", Host, s.port)
}

// Hold delays every following answer by d (after the request was recorded).
func (s *Sink) Hold(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hold = d
}

// ServeHTTP records the request and answers.
func (s *Sink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	s.mu.Lock()
	s.requests = append(s.requests, Request{Header: r.Header.Clone(), Body: body, Received: time.Now()})
	status, location, hold := s.status, s.location, s.hold
	s.mu.Unlock()
	if hold > 0 {
		select {
		case <-time.After(hold):
		case <-r.Context().Done():
			return
		}
	}
	if status >= 300 && status < 400 {
		w.Header().Set("Location", location)
	}
	w.WriteHeader(status)
}

// Requests returns a copy of the requests received so far.
func (s *Sink) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Wait polls until cond holds for the requests received so far and returns them; it fails the test after timeout.
func (s *Sink) Wait(t testing.TB, timeout time.Duration, what string, cond func([]Request) bool) []Request {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got := s.Requests()
		if cond(got) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("sink: %s not received within %s (%d requests)", what, timeout, len(got))
		}
		time.Sleep(250 * time.Millisecond)
	}
}
