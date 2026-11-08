package ops

import (
	"context"
	"net"
	"strings"
	"testing"
)

func ips(s ...string) []net.IP {
	out := make([]net.IP, 0, len(s))
	for _, x := range s {
		out = append(out, net.ParseIP(x))
	}
	return out
}

func TestSelectLocal(t *testing.T) {
	local := ips("127.0.0.1", "::1", "172.25.18.2", "172.28.0.5")
	cases := []struct {
		name     string
		resolved []net.IP
		want     string
		wantErr  string
	}{
		{name: "single replica", resolved: ips("172.25.18.2"), want: "172.25.18.2"},
		{name: "own address first", resolved: ips("172.25.18.2", "172.25.18.4", "172.25.18.3"), want: "172.25.18.2"},
		{name: "own address not first", resolved: ips("172.25.18.4", "172.25.18.3", "172.25.18.2"), want: "172.25.18.2"},
		{name: "duplicate record", resolved: ips("172.25.18.2", "172.25.18.2"), want: "172.25.18.2"},
		{name: "no local address", resolved: ips("172.25.18.4", "172.25.18.3"), wantErr: "no"},
		{name: "nothing resolved", resolved: nil, wantErr: "none of the resolved addresses"},
		{name: "two local addresses", resolved: ips("172.25.18.2", "172.28.0.5"), wantErr: "want exactly one"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectLocal(tc.resolved, local)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("selectLocal = %v, %v; want error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got.String() != tc.want {
				t.Fatalf("selectLocal = %v, %v; want %s", got, err, tc.want)
			}
		})
	}
}

func TestListenAddrPassThrough(t *testing.T) {
	for _, addr := range []string{":9090", "127.0.0.1:9090", "[::1]:9090", "0.0.0.0:0"} {
		got, err := ListenAddr(context.Background(), addr)
		if err != nil || got != addr {
			t.Errorf("ListenAddr(%q) = %q, %v; want unchanged", addr, got, err)
		}
	}
}

func TestListenAddrRejectsMalformed(t *testing.T) {
	if _, err := ListenAddr(context.Background(), "worker-ops"); err == nil {
		t.Fatal("ListenAddr without a port: want error")
	}
}

// canceled makes the name lookup fail at once, which stands for an unresolvable alias without waiting on DNS.
func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestListenAddrFailsClosedOnUnresolvable(t *testing.T) {
	if _, err := ListenAddr(canceled(), "worker-ops:9090"); err == nil {
		t.Fatal("ListenAddr with an unresolvable host: want error")
	}
}

func TestServeFailsClosedOnUnresolvable(t *testing.T) {
	err := Serve(canceled(), "worker-ops:9090", func(context.Context) error { return nil })
	if err == nil {
		t.Fatal("Serve with an unresolvable host: want error, not a listener")
	}
}
