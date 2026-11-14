// Package ops serves the internal operations endpoints of every role: /healthz, /readyz, /metrics (architecture §19).
package ops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ReadyFunc reports whether the role's dependencies are reachable.
type ReadyFunc func(ctx context.Context) error

// Serve runs the ops listener until ctx ends. A host name in addr is resolved with ListenAddr first.
func Serve(ctx context.Context, addr string, ready ReadyFunc) error {
	addr, err := ListenAddr(ctx, addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := ready(ctx); err != nil {
			slog.WarnContext(ctx, "not ready", "error", err)
			http.Error(w, "not ready: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.Handle("GET /metrics", promhttp.Handler())

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// ListenAddr returns the address the ops listener binds for addr. An empty host or an IP literal is returned
// unchanged. A host name must resolve to exactly one address assigned to a local interface; that address replaces
// the name, otherwise ListenAddr fails closed.
//
// Scaled replicas share their data-only ops alias (decision A10-1), so the name resolves to every replica's address
// in shuffled order and binding the name directly would pick another replica's address at random.
func ListenAddr(ctx context.Context, addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("ops address %q: %w", addr, err)
	}
	if host == "" || net.ParseIP(host) != nil {
		return addr, nil
	}
	resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("ops address %q: resolve: %w", addr, err)
	}
	ifAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("ops address %q: interface addresses: %w", addr, err)
	}
	remote := make([]net.IP, 0, len(resolved))
	for _, a := range resolved {
		remote = append(remote, a.IP)
	}
	local := make([]net.IP, 0, len(ifAddrs))
	for _, a := range ifAddrs {
		if n, ok := a.(*net.IPNet); ok {
			local = append(local, n.IP)
		}
	}
	ip, err := selectLocal(remote, local)
	if err != nil {
		return "", fmt.Errorf("ops address %q: %w", addr, err)
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// selectLocal returns the one resolved address that is also a local address.
func selectLocal(resolved, local []net.IP) (net.IP, error) {
	var match []net.IP
	for _, r := range resolved {
		if !containsIP(local, r) || containsIP(match, r) {
			continue
		}
		match = append(match, r)
	}
	switch len(match) {
	case 1:
		return match[0], nil
	case 0:
		return nil, fmt.Errorf("none of the resolved addresses %v is assigned to a local interface", resolved)
	default:
		return nil, fmt.Errorf("resolves to %d local addresses %v, want exactly one", len(match), match)
	}
}

func containsIP(ips []net.IP, ip net.IP) bool {
	for _, x := range ips {
		if x.Equal(ip) {
			return true
		}
	}
	return false
}
