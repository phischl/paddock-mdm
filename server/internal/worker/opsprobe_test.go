package worker

import (
	"context"
	"crypto/tls"
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

	NewOpsProbe(nil, DialCertExpiry(srv.Listener.Addr().String()), []string{"admin.example.org"}).ProbeCertificates(context.Background())
	if got := testutil.ToFloat64(metricTLSExpiry.WithLabelValues("admin.example.org")); got != float64(want.Unix()) {
		t.Fatalf("expiry %v, want %v", got, want.Unix())
	}
	if testutil.ToFloat64(metricTLSProbeSuccess.WithLabelValues("admin.example.org")) != 1 {
		t.Fatal("probe success must be 1")
	}

	failing := func(context.Context, string) (time.Time, error) { return time.Time{}, errors.New("refused") }
	NewOpsProbe(nil, failing, []string{"admin.example.org"}).ProbeCertificates(context.Background())
	if testutil.ToFloat64(metricTLSProbeSuccess.WithLabelValues("admin.example.org")) != 0 {
		t.Fatal("a failed probe must read 0")
	}
	if got := testutil.ToFloat64(metricTLSExpiry.WithLabelValues("admin.example.org")); got != float64(want.Unix()) {
		t.Fatal("a failed probe keeps the last expiry")
	}
}
