package audit

import "sort"

// MaxMsgIDLen is the length limit of the RFC 5424 MSGID header field (section 6).
const MaxMsgIDLen = 32

// msgIDAliases is the fixed MSGID of every registered code longer than MaxMsgIDLen (ADR 0031 amendment 2026-11-04,
// MSGID aliases). The table is add-only: an alias never changes and is never reused, because SIEM rules match on it.
var msgIDAliases = map[Code]string{
	CodeDeviceDiskConversionCompletedAfterCancel: "device.conversion_after_cancel",
	CodeDeviceDiskConversionNeutralizeFailed:     "device.disk_neutralize_failed",
	CodeDeviceDiskConversionUnlockRestoreFailed:  "device.unlock_restore_failed",
	CodeDeviceTamperProtectedFileChanged:         "device.tamper_file_changed",
	CodeDeviceTamperLocalAdminChanged:            "device.tamper_admin_changed",
	CodeDeviceRevocationTrustPinnedTOFU:          "device.revoke_trust_tofu",
	CodePermissionProfileRootGrantConfirmed:      "permission_profile.root_grant_ok",
	CodeOrganizationSecurityReviewRequired:       "organization.sec_review_required",
	CodeNotificationDestinationSecretRotated:     "notification.dest_secret_rotated",
}

// MsgID returns the RFC 5424 MSGID of c: the code itself when it fits MaxMsgIDLen, its alias otherwise.
func (c Code) MsgID() string {
	if a, ok := msgIDAliases[c]; ok {
		return a
	}
	return string(c)
}

// MsgIDAlias is one row of the alias table.
type MsgIDAlias struct {
	Code  Code
	MsgID string
}

// MsgIDAliases returns the alias table sorted by code.
func MsgIDAliases() []MsgIDAlias {
	out := make([]MsgIDAlias, 0, len(msgIDAliases))
	for c, a := range msgIDAliases {
		out = append(out, MsgIDAlias{Code: c, MsgID: a})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}
