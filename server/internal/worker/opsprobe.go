package worker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Probe intervals of the operations probe.
const (
	openBaoProbeInterval = 30 * time.Second
	tlsProbeInterval     = 15 * time.Minute
)

var (
	metricOpenBaoSealed = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_openbao_sealed",
		Help: "1 while OpenBao reports sealed, 0 while unsealed; unchanged while it is unreachable.",
	})
	metricOpenBaoReachable = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_openbao_reachable",
		Help: "1 when the last health request to OpenBao succeeded, else 0.",
	})
	metricTLSExpiry = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "paddock_tls_certificate_expiry_timestamp_seconds",
		Help: "Expiry (notAfter) of the certificate each public hostname serves.",
	}, []string{"host"})
	metricTLSProbeSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "paddock_tls_probe_success",
		Help: "1 when the last TLS handshake with the public hostname returned a certificate that verifies for the hostname against the trust store, else 0.",
	}, []string{"host"})
	// metricTLSProbeHosts lets an alert notice expiries that are never exported (PaddockCertificateExpiryMissing).
	metricTLSProbeHosts = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_tls_probe_hosts",
		Help: "Number of public hostnames whose certificate expiry the worker probes.",
	})
)

// SealStatus reads OpenBao's seal status (bao.Client.Sealed).
type SealStatus interface {
	Sealed(ctx context.Context) (bool, error)
}

// CertExpiry returns the notAfter of the leaf certificate host serves.
type CertExpiry func(ctx context.Context, host string) (time.Time, error)

// OpsProbe exports the metrics the alerts of plan M6a decision 8 need beyond the roles' own: OpenBao's seal status
// and the expiry of the public certificates (decision 9; Caddy exports no certificate metrics).
type OpsProbe struct {
	bao    SealStatus
	expiry CertExpiry
	hosts  []string
}

// NewOpsProbe creates the probe; without hosts it probes no certificates.
func NewOpsProbe(bao SealStatus, expiry CertExpiry, hosts []string) *OpsProbe {
	return &OpsProbe{bao: bao, expiry: expiry, hosts: hosts}
}

// Run probes until ctx ends.
func (p *OpsProbe) Run(ctx context.Context) error {
	metricTLSProbeHosts.Set(float64(len(p.hosts)))
	baoTick := time.NewTicker(openBaoProbeInterval)
	defer baoTick.Stop()
	tlsTick := time.NewTicker(tlsProbeInterval)
	defer tlsTick.Stop()
	p.ProbeOpenBao(ctx)
	p.ProbeCertificates(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-baoTick.C:
			p.ProbeOpenBao(ctx)
		case <-tlsTick.C:
			p.ProbeCertificates(ctx)
		}
	}
}

// ProbeOpenBao sets paddock_openbao_sealed and paddock_openbao_reachable.
func (p *OpsProbe) ProbeOpenBao(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	sealed, err := p.bao.Sealed(ctx)
	if err != nil {
		metricOpenBaoReachable.Set(0)
		slog.WarnContext(ctx, "OpenBao health probe failed", "error", err)
		return
	}
	metricOpenBaoReachable.Set(1)
	if sealed {
		metricOpenBaoSealed.Set(1)
	} else {
		metricOpenBaoSealed.Set(0)
	}
}

// ProbeCertificates sets the expiry and success gauges of every host.
func (p *OpsProbe) ProbeCertificates(ctx context.Context) {
	for _, host := range p.hosts {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		notAfter, err := p.expiry(cctx, host)
		cancel()
		if err != nil {
			metricTLSProbeSuccess.WithLabelValues(host).Set(0)
			slog.WarnContext(ctx, "TLS probe failed", "host", host, "error", err)
			continue
		}
		metricTLSProbeSuccess.WithLabelValues(host).Set(1)
		metricTLSExpiry.WithLabelValues(host).Set(float64(notAfter.Unix()))
	}
}

// DialCertExpiry connects to addr (Caddy on the internal network) with host as SNI and returns the leaf's notAfter.
// The chain is verified for host against roots (nil: the system trust store), so a certificate that clients would
// reject — expired, untrusted or for another name — fails the probe (PaddockCertificateProbeFailing) instead of
// reporting a reassuring expiry.
func DialCertExpiry(addr string, roots *x509.CertPool) CertExpiry {
	return func(ctx context.Context, host string) (time.Time, error) {
		d := tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{
			ServerName: host,
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		}}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return time.Time{}, err
		}
		defer func() { _ = conn.Close() }()
		tc, ok := conn.(*tls.Conn)
		if !ok {
			return time.Time{}, errors.New("not a TLS connection")
		}
		certs := tc.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			return time.Time{}, errors.New("no certificate")
		}
		return certs[0].NotAfter, nil
	}
}
