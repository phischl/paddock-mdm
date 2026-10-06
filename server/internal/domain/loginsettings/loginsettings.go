// Package loginsettings holds the rules of an organization's login settings (plan M3a decision 8): Hello PIN,
// the session action of a user lock, break-glass accounts, the sudoers.d allow list, the sudo lecture text and the
// managed local administrator (plan M4a decision 13).
package loginsettings

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/policy"
)

// Settings are the login settings of one organization.
type Settings struct {
	HelloEnabled          bool
	HelloPinMinLength     int
	UserLockSessionAction string
	BreakGlassAccounts    []string
	SudoersDAllowlist     []string
	SudoLectureText       string
	// LocalAdminUsername is the managed local administrator account; it cannot change once a device has an active
	// password for it.
	LocalAdminUsername     string
	LocalAdminRotationDays int
	// RotateAfterRevealHours schedules a rotation that many hours after a reveal; nil: no rotation after a reveal.
	RotateAfterRevealHours *int
	// NoticeText is the login notice of the devices (plan M4a decision 19); "" shows none.
	NoticeText string
}

// Bounds of the settings.
const (
	MinPinLength    = 6
	MaxPinLength    = 32
	MaxListEntries  = 50
	MaxLectureChars = 2000

	DefaultLocalAdminUsername     = "paddock-admin"
	DefaultLocalAdminRotationDays = 30
	MaxRotationDays               = 365
	MaxRotateAfterRevealHours     = 168
	MaxNoticeChars                = 2000
)

// Validation errors.
var (
	ErrPinLength     = errors.New("hello_pin_min_length must be 6 to 32")
	ErrSessionAction = errors.New("user_lock_session_action must be lock_screen or terminate")
	ErrBreakGlass    = errors.New("break_glass_accounts must be at most 50 distinct local account names matching ^[a-z_][a-z0-9_-]{0,31}$")
	ErrAllowlist     = errors.New("sudoers_d_allowlist must be at most 50 distinct file names matching ^[A-Za-z0-9_-]{1,64}$ that do not start with paddock-")
	ErrLecture       = errors.New("sudo_lecture_text must be 1 to 2000 characters")
	ErrLocalAdmin    = errors.New("local_admin_username must match ^[a-z_][a-z0-9_-]{0,31}$")
	ErrRotationDays  = errors.New("local_admin_rotation_days must be 1 to 365")
	ErrRevealHours   = errors.New("rotate_after_reveal_hours must be empty or 1 to 168")
	ErrNotice        = errors.New("notice_text must be plain text of at most 2000 characters (line breaks and tabs allowed)")
)

// allowlistPattern matches the file names sudo reads from an includedir (no "." and no trailing "~").
var allowlistPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Normalize trims the lecture text and the list entries.
func Normalize(s Settings) Settings {
	s.SudoLectureText = strings.TrimSpace(s.SudoLectureText)
	s.LocalAdminUsername = strings.TrimSpace(s.LocalAdminUsername)
	s.NoticeText = strings.TrimSpace(strings.ReplaceAll(s.NoticeText, "\r\n", "\n"))
	s.BreakGlassAccounts = trimAll(s.BreakGlassAccounts)
	s.SudoersDAllowlist = trimAll(s.SudoersDAllowlist)
	return s
}

func trimAll(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = strings.TrimSpace(v)
	}
	return out
}

// Validate checks normalized settings.
func Validate(s Settings) error {
	if s.HelloPinMinLength < MinPinLength || s.HelloPinMinLength > MaxPinLength {
		return ErrPinLength
	}
	if s.UserLockSessionAction != bundle.SessionActionLockScreen && s.UserLockSessionAction != bundle.SessionActionTerminate {
		return ErrSessionAction
	}
	if !distinct(s.BreakGlassAccounts) {
		return ErrBreakGlass
	}
	for _, a := range s.BreakGlassAccounts {
		if policy.ValidateOwner(a) != nil {
			return ErrBreakGlass
		}
	}
	if !distinct(s.SudoersDAllowlist) {
		return ErrAllowlist
	}
	for _, f := range s.SudoersDAllowlist {
		// Files named paddock-* belong to Paddock; allow-listing them would let a foreign file pass as Paddock's.
		if !allowlistPattern.MatchString(f) || strings.HasPrefix(f, "paddock-") {
			return ErrAllowlist
		}
	}
	if n := utf8.RuneCountInString(s.SudoLectureText); n < 1 || n > MaxLectureChars {
		return ErrLecture
	}
	if policy.ValidateOwner(s.LocalAdminUsername) != nil {
		return ErrLocalAdmin
	}
	if s.LocalAdminRotationDays < 1 || s.LocalAdminRotationDays > MaxRotationDays {
		return ErrRotationDays
	}
	if h := s.RotateAfterRevealHours; h != nil && (*h < 1 || *h > MaxRotateAfterRevealHours) {
		return ErrRevealHours
	}
	if utf8.RuneCountInString(s.NoticeText) > MaxNoticeChars || !utf8.ValidString(s.NoticeText) {
		return ErrNotice
	}
	for _, r := range s.NoticeText {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f {
			return ErrNotice
		}
	}
	return nil
}

func distinct(list []string) bool {
	if len(list) > MaxListEntries {
		return false
	}
	sorted := slices.Sorted(slices.Values(list))
	return len(slices.Compact(sorted)) == len(list)
}
