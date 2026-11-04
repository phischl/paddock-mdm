package outbound

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"regexp"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// Type is the transport of a destination.
type Type string

const (
	TypeWebhook Type = "webhook"
	TypeEmail   Type = "email"
	TypeSyslog  Type = "syslog"
)

// Limits of a destination (plan M9 decision 9).
const (
	MaxRecipients       = 20
	MaxCustomCodes      = 200
	MinHeartbeatSeconds = 60
	MaxHeartbeatSeconds = 3600
	MinEmailIntervalS   = 60
	MaxEmailIntervalS   = 3600
	// DefaultSyslogPort is the port of syslog over TLS (RFC 5425).
	DefaultSyslogPort = 6514
	// MaxSyslogCAPEM bounds the CA bundle of a syslog destination (plan M12 decision 17).
	MaxSyslogCAPEM = 16 << 10
)

// Validation errors.
var (
	ErrInvalidName       = errors.New("name must start with a letter or digit and have at most 64 characters of letters, digits, spaces, '.', '_' and '-'")
	ErrInvalidType       = errors.New("type must be webhook, email or syslog")
	ErrInvalidFilterMode = errors.New("filter_mode must be security, all or custom")
	ErrInvalidCodes      = errors.New("codes must hold 1 to 200 distinct registered audit codes")
	ErrInvalidHeartbeat  = errors.New("heartbeat_interval_s must be 0 or 60 to 3600")
	ErrInvalidRecipients = errors.New("recipients must hold 1 to 20 plain e-mail addresses")
	ErrInvalidInterval   = errors.New("email_min_interval_s must be 60 to 3600")
	ErrInvalidSyslogHost = errors.New("syslog_host must be a DNS name or an IP address")
	ErrSyslogHostDenied  = errors.New("syslog_host is not a public address")
	ErrSyslogHostLookup  = errors.New("syslog_host does not resolve")
	ErrInvalidSyslogPort = errors.New("syslog_port must be 1 to 65535")
	ErrInvalidSyslogCA   = errors.New("syslog_ca_pem must hold one or more PEM certificates and at most 16 KiB")
	ErrInvalidServerName = errors.New("syslog_server_name must be a DNS name")
	ErrSyslogOnly        = errors.New("syslog_host, syslog_port, syslog_ca_pem and syslog_server_name are only allowed for syslog destinations")
	ErrCheckpointsEmail  = errors.New("checkpoints are only allowed for webhook and syslog destinations")
)

// dnsNamePattern is a host name of letters, digits and hyphens in dot-separated labels of 1 to 63 characters.
var dnsNamePattern = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// namePattern is the name rule of API tokens (apitoken.ValidateName), which destination names share.
var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// Destination holds the administrator's settings of a destination; URL is the plaintext webhook URL. SyslogPort 0
// means DefaultSyslogPort.
type Destination struct {
	Type               Type
	Name               string
	FilterMode         FilterMode
	Codes              []audit.Code
	URL                string
	HeartbeatIntervalS int
	Recipients         []string
	EmailMinIntervalS  int
	SyslogHost         string
	SyslogPort         int
	SyslogCAPEM        string
	SyslogServerName   string
	Checkpoints        bool
}

// ValidateDestination checks d with the production URL policy.
func ValidateDestination(d Destination) error {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	return Policy{}.ValidateDestination(ctx, d)
}

// ValidateDestination checks d: the name, the filter (custom: 1–200 distinct registered codes) and, by type, the
// webhook URL under p and the heartbeat interval, the recipients and the e-mail interval, or the syslog receiver
// (its host resolved under p, plan M12 decision 17).
func (p Policy) ValidateDestination(ctx context.Context, d Destination) error {
	if err := ValidateSettings(d); err != nil {
		return err
	}
	switch d.Type {
	case TypeWebhook:
		return p.Validate(ctx, d.URL)
	case TypeSyslog:
		return p.ValidateSyslogHost(ctx, d.SyslogHost)
	}
	return nil
}

// ValidateSyslogHost checks that host resolves and, unless AllowPrivate, that none of its addresses is denied (the
// address rule of webhooks, ADR 0031 decision 12).
func (p Policy) ValidateSyslogHost(ctx context.Context, host string) error {
	addrs, err := p.lookup(ctx, host)
	if err != nil {
		return ErrSyslogHostLookup
	}
	if !p.AllowPrivate && anyDenied(addrs) {
		return ErrSyslogHostDenied
	}
	return nil
}

// ValidateSettings checks every rule of ValidateDestination except the webhook URL and the resolution of the syslog
// host: an update that keeps the stored URL cannot validate it, because the api can encrypt the URL but never
// decrypt it (plan M9 decision 16).
func ValidateSettings(d Destination) error {
	if !namePattern.MatchString(d.Name) {
		return ErrInvalidName
	}
	if err := validateFilter(d.FilterMode, d.Codes); err != nil {
		return err
	}
	if (d.Type == TypeWebhook || d.Type == TypeEmail) &&
		(d.SyslogHost != "" || d.SyslogPort != 0 || d.SyslogCAPEM != "" || d.SyslogServerName != "") {
		return ErrSyslogOnly
	}
	switch d.Type {
	case TypeWebhook:
		return validateHeartbeat(d.HeartbeatIntervalS)
	case TypeEmail:
		if d.Checkpoints {
			return ErrCheckpointsEmail
		}
		if err := validateRecipients(d.Recipients); err != nil {
			return err
		}
		if d.EmailMinIntervalS < MinEmailIntervalS || d.EmailMinIntervalS > MaxEmailIntervalS {
			return ErrInvalidInterval
		}
	case TypeSyslog:
		if err := validateSyslog(d); err != nil {
			return err
		}
		return validateHeartbeat(d.HeartbeatIntervalS)
	default:
		return ErrInvalidType
	}
	return nil
}

func validateHeartbeat(s int) error {
	if s != 0 && (s < MinHeartbeatSeconds || s > MaxHeartbeatSeconds) {
		return ErrInvalidHeartbeat
	}
	return nil
}

// validateSyslog checks the receiver of a syslog destination without resolving its host: a DNS name or an IP literal,
// the port, the CA bundle and the server name (plan M12 decision 17).
func validateSyslog(d Destination) error {
	if !validHost(d.SyslogHost) {
		return ErrInvalidSyslogHost
	}
	if d.SyslogPort < 0 || d.SyslogPort > 65535 {
		return ErrInvalidSyslogPort
	}
	if d.SyslogCAPEM != "" {
		if _, err := ParseCAPEM(d.SyslogCAPEM); err != nil {
			return err
		}
	}
	if d.SyslogServerName != "" && !validDNSName(d.SyslogServerName) {
		return ErrInvalidServerName
	}
	return nil
}

func validHost(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Zone() == ""
	}
	return validDNSName(host)
}

func validDNSName(name string) bool {
	return len(name) <= 253 && dnsNamePattern.MatchString(name)
}

// ParseCAPEM returns the certificates of a syslog destination's CA bundle: at most MaxSyslogCAPEM bytes of one or
// more PEM blocks, every one a parsable CERTIFICATE.
func ParseCAPEM(bundle string) ([]*x509.Certificate, error) {
	if len(bundle) > MaxSyslogCAPEM {
		return nil, ErrInvalidSyslogCA
	}
	var certs []*x509.Certificate
	rest := []byte(bundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, ErrInvalidSyslogCA
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrInvalidSyslogCA
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 || len(bytes.TrimSpace(rest)) > 0 {
		return nil, ErrInvalidSyslogCA
	}
	return certs, nil
}

func validateFilter(mode FilterMode, codes []audit.Code) error {
	switch mode {
	case FilterSecurity, FilterAll:
		return nil
	case FilterCustom:
	default:
		return ErrInvalidFilterMode
	}
	if len(codes) == 0 || len(codes) > MaxCustomCodes {
		return ErrInvalidCodes
	}
	seen := make(map[audit.Code]bool, len(codes))
	for _, c := range codes {
		if seen[c] || !c.Registered() {
			return fmt.Errorf("%w: %q", ErrInvalidCodes, c)
		}
		seen[c] = true
	}
	return nil
}

func validateRecipients(recipients []string) error {
	if len(recipients) == 0 || len(recipients) > MaxRecipients {
		return ErrInvalidRecipients
	}
	for _, r := range recipients {
		a, err := mail.ParseAddress(r)
		if err != nil || a.Name != "" || a.Address != r {
			return fmt.Errorf("%w: %q", ErrInvalidRecipients, r)
		}
	}
	return nil
}
