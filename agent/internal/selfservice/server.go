package selfservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Limits of the socket server (plan M13b decision 12).
const (
	// MaxConns bounds the connections served at once; further ones wait in the listen backlog.
	MaxConns = 32
	// MaxConnsPerUID bounds the connections one UID holds at once, so one user cannot take every slot; a further
	// connection of that UID is closed unanswered.
	MaxConnsPerUID = 4
	// MaxBody bounds a request body; no endpoint takes one.
	MaxBody = 4 << 10
	// RatePerMinute bounds the requests of one UID per minute.
	RatePerMinute = 60
	// shutdownGrace is how long a stopping server waits for requests in flight.
	shutdownGrace = 5 * time.Second
)

type peerKey struct{}

// peer is the UID the kernel reported for the connection (SO_PEERCRED), or the reason it could not.
type peer struct {
	uid int
	err error
}

func withPeer(ctx context.Context, p peer) context.Context {
	return context.WithValue(ctx, peerKey{}, p)
}

// Serve answers the self-service API on the unix socket path (mode 0666 in a 0755 directory: every local user may
// connect, plan M13b decision 12) until ctx ends, and removes the socket then. Every connection carries the peer
// credentials of its process; a connection without them is closed unanswered.
func (s *Service) Serve(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // /run/paddock: users reach the socket through it
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale self-service socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("self-service socket: %w", err)
	}
	defer func() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("removing the self-service socket failed", "error", err)
		}
	}()
	if err := os.Chmod(path, 0o666); err != nil { //nolint:gosec // world-connectable by design; the caller is identified by SO_PEERCRED
		_ = ln.Close()
		return err
	}
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8 << 10,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if pc, ok := c.(*peerConn); ok {
				return withPeer(ctx, pc.peer)
			}
			return withPeer(ctx, peer{uid: -1, err: errors.New("no peer credentials")})
		},
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(newPeerListener(ln, MaxConns, MaxConnsPerUID, peerOf)) }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		return srv.Shutdown(shutdown)
	case err := <-errCh:
		return err
	}
}

// peerListener accepts at most cap(slots) connections at a time, at most perUID of them from one UID, and reads the
// peer credentials of each.
type peerListener struct {
	net.Listener
	slots  chan struct{}
	perUID int
	peerOf func(net.Conn) peer
	mu     sync.Mutex
	conns  map[int]int
}

func newPeerListener(ln net.Listener, maxConns, perUID int, peerOf func(net.Conn) peer) *peerListener {
	return &peerListener{Listener: ln, slots: make(chan struct{}, maxConns), perUID: perUID, peerOf: peerOf, conns: map[int]int{}}
}

// Accept implements net.Listener. A connection of a UID that holds perUID connections already is closed and the
// next one accepted.
func (l *peerListener) Accept() (net.Conn, error) {
	l.slots <- struct{}{}
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			<-l.slots
			return nil, err
		}
		p := l.peerOf(c)
		l.mu.Lock()
		full := l.conns[p.uid] >= l.perUID
		if !full {
			l.conns[p.uid]++
		}
		l.mu.Unlock()
		if full {
			slog.Warn("self-service connection refused: too many connections of one UID", "uid", p.uid)
			_ = c.Close()
			continue
		}
		return &peerConn{Conn: c, peer: p, release: func() { l.release(p.uid) }}, nil
	}
}

func (l *peerListener) release(uid int) {
	l.mu.Lock()
	if l.conns[uid]--; l.conns[uid] <= 0 {
		delete(l.conns, uid)
	}
	l.mu.Unlock()
	<-l.slots
}

// peerConn is an accepted connection with its peer credentials; Close frees its slot once.
type peerConn struct {
	net.Conn
	peer    peer
	release func()
	once    sync.Once
}

// Close implements net.Conn.
func (c *peerConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// peerOf reads SO_PEERCRED of a unix connection: the kernel's record of the connecting process, which the peer cannot
// forge.
func peerOf(c net.Conn) peer {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return peer{uid: -1, err: errors.New("not a unix connection")}
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peer{uid: -1, err: err}
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return peer{uid: -1, err: err}
	}
	if credErr != nil {
		return peer{uid: -1, err: credErr}
	}
	return peer{uid: int(cred.Uid)}
}

// window counts the requests of one UID in the current minute.
type window struct {
	start time.Time
	n     int
}

// allow counts a request of uid at now against RatePerMinute and forgets the windows that ended.
func (s *Service) allow(uid int, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for u, w := range s.rate {
		if now.Sub(w.start) >= time.Minute {
			delete(s.rate, u)
		}
	}
	w, ok := s.rate[uid]
	if !ok {
		w = &window{start: now}
		s.rate[uid] = w
	}
	w.n++
	return w.n <= RatePerMinute
}

// Handler is the self-service API (plan M13b §6.2). Every request is authenticated by its peer credentials, counted
// against the rate of its UID, resolved to a principal and refused with no_bundle until a bundle is applied.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.authed(func(w http.ResponseWriter, _ *http.Request, p Principal) {
		st, err := s.Status(p)
		reply(w, http.StatusOK, st, err)
	}))
	mux.HandleFunc("GET /v1/apps", s.authed(func(w http.ResponseWriter, _ *http.Request, p Principal) {
		apps, err := s.Apps(p)
		reply(w, http.StatusOK, map[string][]AppView{"apps": apps}, err)
	}))
	mux.HandleFunc("GET /v1/apps/{id}", s.authed(func(w http.ResponseWriter, r *http.Request, p Principal) {
		app, err := s.App(p, r.PathValue("id"))
		reply(w, http.StatusOK, app, err)
	}))
	mux.HandleFunc("GET /v1/apps/{id}/icon", s.authed(func(w http.ResponseWriter, r *http.Request, p Principal) {
		data, err := s.Icon(p, r.PathValue("id"))
		if err != nil {
			reply(w, 0, nil, err)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(data)
	}))
	for _, action := range []string{protocol.SelfServiceInstall, protocol.SelfServiceRemove, protocol.SelfServiceUpdate} {
		mux.HandleFunc("POST /v1/apps/{id}/"+action, s.authed(func(w http.ResponseWriter, r *http.Request, p Principal) {
			id, err := s.Enqueue(p, r.PathValue("id"), action)
			if err == nil {
				slog.InfoContext(r.Context(), "self-service operation queued", "operation_id", id, "action", action, "uid", p.UID)
			}
			reply(w, http.StatusAccepted, map[string]string{"operation_id": id}, err)
		}))
	}
	mux.HandleFunc("GET /v1/operations/{id}", s.authed(func(w http.ResponseWriter, r *http.Request, p Principal) {
		op, ok := s.Operation(p, r.PathValue("id"))
		if !ok {
			reply(w, 0, nil, &Problem{Status: http.StatusNotFound, Code: CodeNotFound, Detail: "no such operation"})
			return
		}
		reply(w, http.StatusOK, op, nil)
	}))
	mux.HandleFunc("/", s.limited(func(w http.ResponseWriter, _ *http.Request, _ int) {
		reply(w, 0, nil, &Problem{Status: http.StatusNotFound, Code: CodeNotFound, Detail: "no such endpoint"})
	}))
	return mux
}

// limited wraps a handler with the checks every request passes, in this order: peer credentials, rate, body size.
func (s *Service) limited(h func(w http.ResponseWriter, r *http.Request, uid int)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pr, ok := r.Context().Value(peerKey{}).(peer)
		if !ok || pr.err != nil || pr.uid < 0 {
			reply(w, 0, nil, &Problem{Status: http.StatusForbidden, Code: CodeUnauthenticated, Detail: "the caller could not be identified"})
			return
		}
		if !s.allow(pr.uid, s.cfg.Now()) {
			w.Header().Set("Retry-After", "60")
			reply(w, 0, nil, &Problem{Status: http.StatusTooManyRequests, Code: CodeRateLimited, Detail: "too many requests"})
			return
		}
		if _, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, MaxBody)); err != nil {
			reply(w, 0, nil, &Problem{Status: http.StatusRequestEntityTooLarge, Code: CodeBodyTooLarge, Detail: "the request body is too large"})
			return
		}
		h(w, r, pr.uid)
	}
}

// authed wraps a handler with the checks of limited, then the principal and the bundle.
func (s *Service) authed(h func(w http.ResponseWriter, r *http.Request, p Principal)) http.HandlerFunc {
	return s.limited(func(w http.ResponseWriter, r *http.Request, uid int) {
		s.mu.Lock()
		applied, domain := s.snap.applied, s.snap.domain
		s.mu.Unlock()
		if !applied {
			reply(w, 0, nil, errNoBundle)
			return
		}
		p, err := Authorize(r.Context(), s.cfg.Sys, uid, domain)
		if err != nil {
			slog.WarnContext(r.Context(), "self-service caller not resolved", "uid", uid, "error", err)
			reply(w, 0, nil, &Problem{Status: http.StatusForbidden, Code: CodeUnauthenticated, Detail: "the caller could not be identified"})
			return
		}
		h(w, r, p)
	})
}

// problemBody is the JSON of a problem (plan M13b §6.2).
type problemBody struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// reply writes v with status, or the problem of err (an unexpected error is a 500 without details).
func reply(w http.ResponseWriter, status int, v any, err error) {
	if err != nil {
		var p *Problem
		if !errors.As(err, &p) {
			slog.Error("self-service request failed", "error", err)
			p = &Problem{Status: http.StatusInternalServerError, Code: "internal", Detail: "internal error"}
		}
		status, v = p.Status, problemBody{Code: p.Code, Detail: p.Detail}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
