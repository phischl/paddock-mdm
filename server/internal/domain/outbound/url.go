package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"
)

// DeniedPrefixes are the addresses a webhook never reaches (ADR 0031 decision 12 and its amendment of 2026-10-31):
// this host, private, shared, link-local, benchmark, documentation, multicast and reserved networks, IPv4-mapped IPv6,
// the IPv6 prefixes that embed an IPv4 address a translator reaches (NAT64, 6to4, Teredo) and the discard prefix.
var DeniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
}

// Transport limits of a webhook call (ADR 0031 decision 12).
const (
	ConnectTimeout = 10 * time.Second
	TotalTimeout   = 30 * time.Second
	// lookupTimeout bounds the name resolution of ValidateWebhookURL, which has no caller context.
	lookupTimeout = 5 * time.Second
)

// ErrInvalidURL is the cause of every refused webhook URL. Messages never repeat the URL: it is a secret.
var ErrInvalidURL = errors.New("invalid webhook URL")

// ErrDeniedAddress is returned by the dialer of SafeTransport for a host that resolves to a denied address.
var ErrDeniedAddress = errors.New("webhook host resolves to a denied address")

// Resolver resolves a host name; *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Policy is the webhook URL and transport policy. The zero value is the production policy. AllowPrivate admits plain
// http and denied addresses and is set only by the development stack (PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE).
type Policy struct {
	AllowPrivate bool
	// Resolver resolves host names; nil uses net.DefaultResolver.
	Resolver Resolver
}

func (p Policy) resolver() Resolver {
	if p.Resolver != nil {
		return p.Resolver
	}
	return net.DefaultResolver
}

// ValidateWebhookURL checks raw with the production policy.
func ValidateWebhookURL(raw string) error {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	return Policy{}.Validate(ctx, raw)
}

// Validate checks a webhook URL: scheme https, no userinfo, port 443 or 1024–65535, and a host that is a public IP
// literal or a name whose every address is outside DeniedPrefixes.
func (p Policy) Validate(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: not a URL", ErrInvalidURL)
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !p.AllowPrivate) {
		return fmt.Errorf("%w: the scheme must be https", ErrInvalidURL)
	}
	if u.User != nil {
		return fmt.Errorf("%w: user information is not allowed", ErrInvalidURL)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: the host is missing", ErrInvalidURL)
	}
	if err := checkPort(u); err != nil {
		return err
	}
	addrs, err := p.lookup(ctx, host)
	if err != nil {
		return fmt.Errorf("%w: the host does not resolve", ErrInvalidURL)
	}
	if !p.AllowPrivate && anyDenied(addrs) {
		return fmt.Errorf("%w: the host is not a public address", ErrInvalidURL)
	}
	return nil
}

func checkPort(u *url.URL) error {
	port := 443
	if u.Scheme == "http" {
		port = 80
	}
	if s := u.Port(); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("%w: the port is not a number", ErrInvalidURL)
		}
		port = n
	}
	if port != 443 && (port < 1024 || port > 65535) {
		return fmt.Errorf("%w: the port must be 443 or 1024–65535", ErrInvalidURL)
	}
	return nil
}

// lookup returns the addresses of host: the literal itself or every address the name resolves to.
func (p Policy) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" {
			return nil, errors.New("zoned address")
		}
		return []netip.Addr{a}, nil
	}
	addrs, err := p.resolver().LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("no address")
	}
	return addrs, nil
}

// Denied reports whether a is in DeniedPrefixes.
func Denied(a netip.Addr) bool {
	a = a.WithZone("")
	for _, p := range DeniedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func anyDenied(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if Denied(a) {
			return true
		}
	}
	return false
}

// SafeTransport returns the webhook transport of the policy with the given AllowPrivate.
func SafeTransport(allowPrivate bool) *http.Transport {
	return Policy{AllowPrivate: allowPrivate}.Transport()
}

// Transport returns an HTTP transport that resolves the host itself, refuses it when any address is denied (unless
// AllowPrivate), and dials a checked address; the request keeps the host name for SNI and the Host header, so a
// second resolution cannot rebind it. No proxy, TLS 1.2 minimum, 10 s to connect.
func (p Policy) Transport() *http.Transport {
	dialer := &net.Dialer{Timeout: ConnectTimeout}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			port, err := strconv.ParseUint(portText, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("outbound: port %q: %w", portText, err)
			}
			addrs, err := p.lookup(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("outbound: resolve: %w", err)
			}
			if !p.AllowPrivate && anyDenied(addrs) {
				return nil, ErrDeniedAddress
			}
			var last error
			for _, a := range addrs {
				conn, err := dialer.DialContext(ctx, network, netip.AddrPortFrom(a, uint16(port)).String())
				if err == nil {
					return conn, nil
				}
				last = err
			}
			return nil, last
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   ConnectTimeout,
		ResponseHeaderTimeout: TotalTimeout,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
	}
}

// ErrRedirect is returned by the client of Client for every redirect: a redirect is a failed delivery.
var ErrRedirect = errors.New("webhook answered with a redirect")

// Client returns an HTTP client over Transport that refuses redirects and ends every call after 30 s.
func (p Policy) Client() *http.Client {
	return &http.Client{
		Transport: p.Transport(),
		Timeout:   TotalTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrRedirect
		},
	}
}

// DisplayURL is what lists, responses and audit params show of a webhook URL (ADR 0031 decision 8): scheme and host,
// and "/…" in place of any path or query, which may carry the credential. It returns "" for an unparsable URL.
func DisplayURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	out := u.Scheme + "://" + u.Host
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Opaque != "" {
		out += "/…"
	}
	return out
}
