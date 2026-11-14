package policy

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// Name rules of the login resource. The server validates organization and group slugs with these patterns, so
// every name it derives from them passes ValidateLoginSpec (plan M12h decision 14, ADR 0051 decision 5).
const (
	// OrgSlugPattern is the slug of an organization (and its database constraint).
	OrgSlugPattern = `[a-z0-9][a-z0-9-]{1,30}[a-z0-9]`
	// GroupSlugPattern is the slug of a user group.
	GroupSlugPattern = `[a-z0-9][a-z0-9-]{0,40}[a-z0-9]`
	// MaxDomainLength is the longest DNS name.
	MaxDomainLength = 253
)

var (
	loginDomainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)
	loginAppPattern    = regexp.MustCompile(`^paddock-device-(` + OrgSlugPattern + `)$`)
	// paddock.<org>, paddock.<org>.g.<group>, paddock.<org>.s.<group>, paddock.<org>.d.<device id>.
	loginGroupPattern = regexp.MustCompile(`^paddock\.(` + OrgSlugPattern + `)(\.[gs]\.` + GroupSlugPattern +
		`|\.d\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?$`)
)

// ErrInvalidLoginSpec is the error of every ValidateLoginSpec refusal.
var ErrInvalidLoginSpec = errors.New("the login spec fails the bundle contract")

// ValidateLoginDomain checks the domain the device's login component accepts (an organization's domain).
func ValidateLoginDomain(domain string) error {
	if len(domain) > MaxDomainLength || !loginDomainPattern.MatchString(domain) {
		return fmt.Errorf("%w: domain %q", ErrInvalidLoginSpec, domain)
	}
	return nil
}

// ValidateLoginUser checks a directory user name (a UPN): every value ends up in a line-based file, so it has no
// whitespace, control characters, comment or list separators.
func ValidateLoginUser(name string) error {
	if name == "" || strings.ContainsFunc(name, lineUnsafe) {
		return fmt.Errorf("%w: user %q", ErrInvalidLoginSpec, name)
	}
	return nil
}

// ValidateLoginSpec checks the identity values of a login spec before the server signs it and before the agent
// renders himmelblau.conf from it: the domain, the device login application, its issuer URL, the allowed groups of
// the same organization, the locked users and the local accounts.
func ValidateLoginSpec(spec bundle.LoginSpec) error {
	h := spec.Himmelblau
	if err := ValidateLoginDomain(h.Domain); err != nil {
		return err
	}
	app := loginAppPattern.FindStringSubmatch(h.AppID)
	if app == nil {
		return fmt.Errorf("%w: app_id %q", ErrInvalidLoginSpec, h.AppID)
	}
	if err := validateIssuer(h.OIDCIssuerURL, h.AppID); err != nil {
		return err
	}
	for _, g := range h.PamAllowGroups {
		if m := loginGroupPattern.FindStringSubmatch(g); m == nil || m[1] != app[1] {
			return fmt.Errorf("%w: group %q", ErrInvalidLoginSpec, g)
		}
	}
	for _, u := range spec.LockedUsers {
		if err := ValidateLoginUser(u); err != nil {
			return err
		}
	}
	for _, a := range spec.BreakGlassAccounts {
		if ValidateOwner(a) != nil {
			return fmt.Errorf("%w: break-glass account %q", ErrInvalidLoginSpec, a)
		}
	}
	if spec.LocalAdmin != nil && ValidateOwner(spec.LocalAdmin.Username) != nil {
		return fmt.Errorf("%w: local administrator %q", ErrInvalidLoginSpec, spec.LocalAdmin.Username)
	}
	return nil
}

// validateIssuer checks the issuer URL of the device login application: <identity provider>/application/o/<app_id>/
// over http(s), without credentials, query or fragment.
func validateIssuer(issuer, appID string) error {
	u, err := url.Parse(issuer)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || strings.ContainsFunc(issuer, lineUnsafe) || !strings.HasSuffix(u.Path, "/application/o/"+appID+"/") {
		return fmt.Errorf("%w: oidc_issuer_url %q", ErrInvalidLoginSpec, issuer)
	}
	return nil
}

// lineUnsafe reports a rune that would break a value of a line-based file: whitespace, control characters, comment
// and list separators.
func lineUnsafe(r rune) bool { return r <= ' ' || r == 0x7f || r == '#' || r == ';' || r == ',' }
