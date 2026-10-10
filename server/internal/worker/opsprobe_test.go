package worker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

type fakeSeal struct {
	sealed bool
	err    error
}

func (f fakeSeal) Sealed(context.Context) (bool, error) { return f.sealed, f.err }

func TestOpsProbeOpenBao(t *testing.T) {
	ctx := context.Background()
	NewOpsProbe(fakeSeal{sealed: true}, nil, nil).ProbeOpenBao(ctx)
	if testutil.ToFloat64(metricOpenBaoSealed) != 1 || testutil.ToFloat64(metricOpenBaoReachable) != 1 {
		t.Fatal("sealed OpenBao must read sealed=1 reachable=1")
	}
	// Unreachable keeps the last seal status and drops reachable.
	NewOpsProbe(fakeSeal{err: errors.New("connection refused")}, nil, nil).ProbeOpenBao(ctx)
	if testutil.ToFloat64(metricOpenBaoSealed) != 1 || testutil.ToFloat64(metricOpenBaoReachable) != 0 {
		t.Fatal("unreachable OpenBao must read reachable=0 and keep sealed")
	}
	NewOpsProbe(fakeSeal{}, nil, nil).ProbeOpenBao(ctx)
	if testutil.ToFloat64(metricOpenBaoSealed) != 0 || testutil.ToFloat64(metricOpenBaoReachable) != 1 {
		t.Fatal("unsealed OpenBao must read sealed=0 reachable=1")
	}
}

func TestOpsProbeCertificates(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	want := srv.Certificate().NotAfter
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	// httptest's certificate is issued for example.com.
	NewOpsProbe(nil, DialCertExpiry(srv.Listener.Addr().String(), roots), []string{"example.com"}).ProbeCertificates(context.Background())
	if got := testutil.ToFloat64(metricTLSExpiry.WithLabelValues("example.com")); got != float64(want.Unix()) {
		t.Fatalf("expiry %v, want %v", got, want.Unix())
	}
	if testutil.ToFloat64(metricTLSProbeSuccess.WithLabelValues("example.com")) != 1 {
		t.Fatal("probe success must be 1")
	}

	failing := func(context.Context, string) (time.Time, error) { return time.Time{}, errors.New("refused") }
	NewOpsProbe(nil, failing, []string{"example.com"}).ProbeCertificates(context.Background())
	if testutil.ToFloat64(metricTLSProbeSuccess.WithLabelValues("example.com")) != 0 {
		t.Fatal("a failed probe must read 0")
	}
	if got := testutil.ToFloat64(metricTLSExpiry.WithLabelValues("example.com")); got != float64(want.Unix()) {
		t.Fatal("a failed probe keeps the last expiry")
	}
}

// TestDialCertExpiryVerifiesTheCertificate: the probe verifies the chain and the name like a client, so an untrusted
// certificate or one for another hostname fails instead of reporting its expiry.
func TestDialCertExpiryVerifiesTheCertificate(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	if _, err := DialCertExpiry(addr, x509.NewCertPool())(context.Background(), "example.com"); err == nil {
		t.Fatal("a certificate from an untrusted issuer was accepted")
	}
	if _, err := DialCertExpiry(addr, roots)(context.Background(), "admin.example.org"); err == nil {
		t.Fatal("a certificate for another hostname was accepted")
	}
	if _, err := DialCertExpiry(addr, roots)(context.Background(), "example.com"); err != nil {
		t.Fatalf("trusted certificate for the hostname: %v", err)
	}
}

// TestOpsProbeExportsHostCount: the number of probed hosts is exported, so that PaddockCertificateExpiryMissing can
// notice expiries that never appear.
func TestOpsProbeExportsHostCount(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	failing := func(context.Context, string) (time.Time, error) { return time.Time{}, errors.New("refused") }
	if err := NewOpsProbe(fakeSeal{}, failing, []string{"a.example.org", "b.example.org"}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metricTLSProbeHosts); got != 2 {
		t.Fatalf("paddock_tls_probe_hosts %v, want 2", got)
	}
}
