package backupset

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// TargetType is the kind of place a target is (plan M15 §6.1).
type TargetType string

// Target types.
const (
	TypeLocal TargetType = "local"
	TypeSMB   TargetType = "smb"
	TypeNFS   TargetType = "nfs"
	TypeS3    TargetType = "s3"
)

// DefaultRegion is the S3 region of a target that names none.
const DefaultRegion = "us-east-1"

// MaxCAPEMBytes bounds the CA certificates of an S3 target.
const MaxCAPEMBytes = 16 << 10

// ErrInvalidTarget is the cause of every target ValidateTarget refuses. Messages name the field, never its value:
// some fields are credentials.
var ErrInvalidTarget = errors.New("invalid backup target")

// Target holds an administrator's settings of a target; only the group of its Type is read. SMB.Password,
// S3.AccessKey and S3.SecretKey are the plaintext credentials.
type Target struct {
	Name  string
	Type  TargetType
	Local Local
	SMB   SMB
	NFS   NFS
	S3    S3
}

// Local is a directory of the control-plane host.
type Local struct{ Path string }

// SMB is an SMB 3 share.
type SMB struct{ Host, Share, Path, Username, Password, Domain, Options string }

// NFS is an NFS 4 export.
type NFS struct{ Host, Export, Path, Options string }

// S3 is a bucket of an S3-compatible object store.
type S3 struct{ Endpoint, Bucket, Region, Prefix, AccessKey, SecretKey, CAPEM string }

// Policy is the target policy. The zero value is the production policy. AllowPrivate admits a plain-http S3 endpoint
// and a denied address and is set only by the development stack (PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE), like
// outbound.Policy.
type Policy struct {
	AllowPrivate bool
}

var (
	// namePattern is the name rule of API tokens (apitoken.ValidateName), which target names share.
	namePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
	dnsNamePattern  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
	sharePattern    = regexp.MustCompile(`^[A-Za-z0-9_$. -]{1,80}$`)
	bucketPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	smbOptionAllow  = regexp.MustCompile(`^(vers=(3\.0|3\.1\.1)|seal|noperm|cache=(none|strict)|actimeo=[0-9]{1,6})$`)
	nfsOptionAllow  = regexp.MustCompile(`^(vers=(4|4\.1|4\.2)|hard|timeo=[0-9]{1,6}|retrans=[0-9]{1,6}|nconnect=[0-9]{1,2})$`)
	ipv4LikePattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)
)

// ValidateTarget checks t with the production policy.
func ValidateTarget(t Target) error { return Policy{}.ValidateTarget(t) }

// ValidateTarget checks t against the rules of plan M15 §6.1. An S3 endpoint's host is checked against the deny list
// of ADR 0031 decision 12 when it is an IP literal; a host name needs a resolution, which is I/O and therefore the
// caller's. The uniqueness of the name is the database's.
func (p Policy) ValidateTarget(t Target) error {
	if !namePattern.MatchString(t.Name) {
		return invalidTarget("name", "must start with a letter or digit and have at most 64 characters of letters, "+
			"digits, spaces, '.', '_' and '-'")
	}
	switch t.Type {
	case TypeLocal:
		return validateLocal(t.Local)
	case TypeSMB:
		return validateSMB(t.SMB)
	case TypeNFS:
		return validateNFS(t.NFS)
	case TypeS3:
		return p.validateS3(t.S3)
	default:
		return invalidTarget("type", "must be local, smb, nfs or s3")
	}
}

// validateLocal accepts a subpath of the host's local backup root (PADDOCK_BACKUP_LOCAL_ROOT, plan M15 decision 36). The
// root is host configuration the server does not know, so the host step resolves the subpath below it and refuses a
// symlink component; here only what can never be right is refused, so no portal input names another directory.
func validateLocal(l Local) error {
	if err := LocalSubpath(l.Path); err != nil {
		return invalidTarget("local.path", err.Error())
	}
	return nil
}

// LocalSubpath checks a local target's path: a relative subpath of at most 256 bytes whose elements are neither empty,
// '.' nor '..'. It is shared with the host step that joins the path to the local root.
func LocalSubpath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || len(p) > 256 || hasControl(p) || strings.Contains(p, "\\") {
		return errLocalSubpath
	}
	for el := range strings.SplitSeq(p, "/") {
		if el == "" || el == "." || el == ".." {
			return errLocalSubpath
		}
	}
	return nil
}

// DefaultLocalRoot is the base directory of local targets when PADDOCK_BACKUP_LOCAL_ROOT is not set (plan M15
// decision 36).
const DefaultLocalRoot = "/srv/paddock-backup"

// ErrLocalRoot marks a configured local root that cannot confine local targets.
var ErrLocalRoot = errors.New("PADDOCK_BACKUP_LOCAL_ROOT must be a clean absolute path of at least two elements")

// LocalRoot checks the configured base directory of local targets. It is shared by the host step and ./paddock check,
// so both refuse the same roots: a relative or unclean path, "/" (every host directory would be a subpath) and a
// first-level directory (./paddock check reads the root through a read-only mount of its parent, which "/" cannot be).
func LocalRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Dir(root) == "/" {
		return ErrLocalRoot
	}
	return nil
}

var errLocalSubpath = errors.New("must be a relative subpath of the local backup root without '..', '.' or empty " +
	"elements and with at most 256 bytes")

func validateSMB(s SMB) error {
	if err := host("smb.host", s.Host); err != nil {
		return err
	}
	if !sharePattern.MatchString(s.Share) {
		return invalidTarget("smb.share", "must be 1 to 80 letters, digits, spaces and '_$.-'")
	}
	if err := relativePath("smb.path", s.Path); err != nil {
		return err
	}
	if err := text("smb.username", s.Username, 1, 104); err != nil {
		return err
	}
	if err := text("smb.password", s.Password, 1, 256); err != nil {
		return err
	}
	if err := text("smb.domain", s.Domain, 0, 64); err != nil {
		return err
	}
	return options("smb.options", s.Options, smbOptionAllow,
		"vers=3.0|3.1.1, seal, noperm, cache=none|strict and actimeo=N")
}

func validateNFS(n NFS) error {
	if err := host("nfs.host", n.Host); err != nil {
		return err
	}
	if err := absolutePath("nfs.export", n.Export); err != nil {
		return err
	}
	if err := relativePath("nfs.path", n.Path); err != nil {
		return err
	}
	return options("nfs.options", n.Options, nfsOptionAllow,
		"vers=4|4.1|4.2, hard, timeo=N, retrans=N and nconnect=N")
}

func (p Policy) validateS3(s S3) error {
	if err := p.endpoint(s.Endpoint); err != nil {
		return err
	}
	if !bucketPattern.MatchString(s.Bucket) || strings.Contains(s.Bucket, "..") ||
		ipv4LikePattern.MatchString(s.Bucket) || strings.HasPrefix(s.Bucket, "xn--") ||
		strings.HasSuffix(s.Bucket, "-s3alias") || strings.HasSuffix(s.Bucket, "--ol-s3") {
		return invalidTarget("s3.bucket", "must follow the S3 bucket naming rules")
	}
	if s.Region != "" && !regionPattern.MatchString(s.Region) {
		return invalidTarget("s3.region", "must be 1 to 64 letters, digits, '_' and '-'")
	}
	if s.Prefix != "" {
		if strings.HasPrefix(s.Prefix, "/") || len(s.Prefix) > 128 || hasControl(s.Prefix) ||
			hasDotDot(s.Prefix) {
			return invalidTarget("s3.prefix", "must not start with '/', must hold no '..' and at most 128 bytes")
		}
	}
	if err := text("s3.access_key", s.AccessKey, 1, 128); err != nil {
		return err
	}
	if err := text("s3.secret_key", s.SecretKey, 1, 256); err != nil {
		return err
	}
	return caPEM(s.CAPEM)
}

func (p Policy) endpoint(raw string) error {
	const field = "s3.endpoint"
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		return invalidTarget(field, "must be a URL")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !p.AllowPrivate) {
		return invalidTarget(field, "the scheme must be https")
	}
	if u.User != nil {
		return invalidTarget(field, "user information is not allowed")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return invalidTarget(field, "a query or fragment is not allowed")
	}
	h := u.Hostname()
	if a, err := netip.ParseAddr(h); err == nil {
		if a.Zone() != "" {
			return invalidTarget(field, "a zoned address is not allowed")
		}
		if outbound.Denied(a) && !p.AllowPrivate {
			return invalidTarget(field, "the host is not a public address")
		}
		return nil
	}
	if len(h) > 253 || !dnsNamePattern.MatchString(h) {
		return invalidTarget(field, "the host must be a DNS name or an IP address")
	}
	return nil
}

func caPEM(s string) error {
	const field = "s3.ca_pem"
	if s == "" {
		return nil
	}
	if len(s) > MaxCAPEMBytes {
		return invalidTarget(field, "must be at most 16 KiB")
	}
	rest, certs := []byte(s), 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return invalidTarget(field, "must hold certificates only")
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return invalidTarget(field, "holds a certificate that does not parse")
		}
		certs++
	}
	if certs == 0 || strings.TrimSpace(string(rest)) != "" {
		return invalidTarget(field, "must be PEM-encoded certificates")
	}
	return nil
}

func host(field, h string) error {
	if a, err := netip.ParseAddr(h); err == nil {
		if a.Zone() != "" {
			return invalidTarget(field, "a zoned address is not allowed")
		}
		return nil
	}
	if len(h) > 253 || !dnsNamePattern.MatchString(h) {
		return invalidTarget(field, "must be a DNS name or an IP address of at most 253 characters")
	}
	return nil
}

func absolutePath(field, p string) error {
	if !strings.HasPrefix(p, "/") || len(p) > 256 || hasControl(p) || hasDotDot(p) {
		return invalidTarget(field, "must be an absolute path without '..' of at most 256 bytes")
	}
	return nil
}

func relativePath(field, p string) error {
	if p == "" {
		return nil
	}
	if strings.HasPrefix(p, "/") || len(p) > 256 || hasControl(p) || hasDotDot(p) {
		return invalidTarget(field, "must be a relative path without '..' of at most 256 bytes")
	}
	return nil
}

// text checks the length in characters of a free-text field, which must hold no control characters: the host renders
// the settings into Compose files and mount options, where a line break would add its own.
func text(field, s string, minLen, maxLen int) error {
	n := utf8.RuneCountInString(s)
	if !utf8.ValidString(s) || n < minLen || n > maxLen || hasControl(s) {
		if minLen == 0 {
			return invalidTarget(field, fmt.Sprintf("must hold at most %d characters and no control characters", maxLen))
		}
		return invalidTarget(field, fmt.Sprintf("must hold %d to %d characters and no control characters", minLen, maxLen))
	}
	return nil
}

func options(field, s string, allow *regexp.Regexp, allowed string) error {
	if s == "" {
		return nil
	}
	if len(s) > 256 {
		return invalidTarget(field, "must be at most 256 characters")
	}
	for item := range strings.SplitSeq(s, ",") {
		if !allow.MatchString(item) {
			return invalidTarget(field, "only "+allowed+" are allowed")
		}
	}
	return nil
}

func hasControl(s string) bool { return strings.ContainsFunc(s, unicode.IsControl) }

func hasDotDot(p string) bool {
	for el := range strings.SplitSeq(p, "/") {
		if el == ".." {
			return true
		}
	}
	return false
}

func invalidTarget(field, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidTarget, field, reason)
}
