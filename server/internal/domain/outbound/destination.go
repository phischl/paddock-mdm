package outbound

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"regexp"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// Type is the transport of a destination.
type Type string

const (
	TypeWebhook Type = "webhook"
	TypeEmail   Type = "email"
)

// Limits of a destination (plan M9 decision 9).
const (
	MaxRecipients       = 20
	MaxCustomCodes      = 200
	MinHeartbeatSeconds = 60
	MaxHeartbeatSeconds = 3600
	MinEmailIntervalS   = 60
	MaxEmailIntervalS   = 3600
)

// Validation errors.
var (
	ErrInvalidName       = errors.New("name must start with a letter or digit and have at most 64 characters of letters, digits, spaces, '.', '_' and '-'")
	ErrInvalidType       = errors.New("type must be webhook or email")
	ErrInvalidFilterMode = errors.New("filter_mode must be security, all or custom")
	ErrInvalidCodes      = errors.New("codes must hold 1 to 200 distinct registered audit codes")
	ErrInvalidHeartbeat  = errors.New("heartbeat_interval_s must be 0 or 60 to 3600")
	ErrInvalidRecipients = errors.New("recipients must hold 1 to 20 plain e-mail addresses")
	ErrInvalidInterval   = errors.New("email_min_interval_s must be 60 to 3600")
)

// namePattern is the name rule of API tokens (apitoken.ValidateName), which destination names share.
var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// Destination holds the administrator's settings of a destination; URL is the plaintext webhook URL.
type Destination struct {
	Type               Type
	Name               string
	FilterMode         FilterMode
	Codes              []audit.Code
	URL                string
	HeartbeatIntervalS int
	Recipients         []string
	EmailMinIntervalS  int
}

// ValidateDestination checks d with the production URL policy.
func ValidateDestination(d Destination) error {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	return Policy{}.ValidateDestination(ctx, d)
}

// ValidateDestination checks d: the name, the filter (custom: 1–200 distinct registered codes) and, by type, the
// webhook URL under p and the heartbeat interval, or the recipients and the e-mail interval.
func (p Policy) ValidateDestination(ctx context.Context, d Destination) error {
	if err := ValidateSettings(d); err != nil {
		return err
	}
	if d.Type == TypeWebhook {
		return p.Validate(ctx, d.URL)
	}
	return nil
}

// ValidateSettings checks every rule of ValidateDestination except the webhook URL: an update that keeps the stored
// URL cannot validate it, because the api can encrypt the URL but never decrypt it (plan M9 decision 16).
func ValidateSettings(d Destination) error {
	if !namePattern.MatchString(d.Name) {
		return ErrInvalidName
	}
	if err := validateFilter(d.FilterMode, d.Codes); err != nil {
		return err
	}
	switch d.Type {
	case TypeWebhook:
		if d.HeartbeatIntervalS != 0 &&
			(d.HeartbeatIntervalS < MinHeartbeatSeconds || d.HeartbeatIntervalS > MaxHeartbeatSeconds) {
			return ErrInvalidHeartbeat
		}
	case TypeEmail:
		if err := validateRecipients(d.Recipients); err != nil {
			return err
		}
		if d.EmailMinIntervalS < MinEmailIntervalS || d.EmailMinIntervalS > MaxEmailIntervalS {
			return ErrInvalidInterval
		}
	default:
		return ErrInvalidType
	}
	return nil
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
