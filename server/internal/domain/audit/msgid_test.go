package audit

import (
	"strings"
	"testing"
)

// TestMsgIDFitsRFC5424: every registered code's MSGID is at most 32 printable US-ASCII characters (RFC 5424
// section 6), so a code added later that is longer than 32 characters fails here until it has an alias.
func TestMsgIDFitsRFC5424(t *testing.T) {
	for _, d := range Definitions() {
		id := d.Code.MsgID()
		if id == "" || len(id) > MaxMsgIDLen {
			t.Errorf("%s: MSGID %q is empty or longer than %d characters; add an alias", d.Code, id, MaxMsgIDLen)
		}
		for _, c := range []byte(id) {
			if c < 33 || c > 126 {
				t.Errorf("%s: MSGID %q has a non-printable character", d.Code, id)
				break
			}
		}
		_, aliased := msgIDAliases[d.Code]
		if len(d.Code) > MaxMsgIDLen && !aliased {
			t.Errorf("%s is longer than %d characters and has no alias", d.Code, MaxMsgIDLen)
		}
		if len(d.Code) <= MaxMsgIDLen && id != string(d.Code) {
			t.Errorf("%s fits the MSGID and must stay unchanged, got %q", d.Code, id)
		}
	}
}

// TestMsgIDsUnique: no two codes share a MSGID, and no alias equals any registered code.
func TestMsgIDsUnique(t *testing.T) {
	seen := map[string]Code{}
	for _, d := range Definitions() {
		id := d.Code.MsgID()
		if other, ok := seen[id]; ok {
			t.Errorf("MSGID %q is shared by %s and %s", id, other, d.Code)
		}
		seen[id] = d.Code
	}
	for c, a := range msgIDAliases {
		if _, ok := Lookup(Code(a)); ok {
			t.Errorf("alias %q of %s equals a registered code", a, c)
		}
	}
}

// TestMsgIDAliasTableIsAddOnly: the published aliases never change, because SIEM rules match on them; only codes
// longer than 32 characters have one.
func TestMsgIDAliasTableIsAddOnly(t *testing.T) {
	published := map[Code]string{
		"device.disk_conversion_completed_after_cancel": "device.conversion_after_cancel",
		"device.disk_conversion_neutralize_failed":      "device.disk_neutralize_failed",
		"device.disk_conversion_unlock_restore_failed":  "device.unlock_restore_failed",
		"device.tamper_protected_file_changed":          "device.tamper_file_changed",
		"device.tamper_local_admin_changed":             "device.tamper_admin_changed",
		"device.revocation_trust_pinned_tofu":           "device.revoke_trust_tofu",
		"permission_profile.root_grant_confirmed":       "permission_profile.root_grant_ok",
		"organization.security_review_required":         "organization.sec_review_required",
		"notification.destination_secret_rotated":       "notification.dest_secret_rotated", //nolint:gosec // an audit code, not a credential
		"software_repository.credential_rotated":        "software_repository.cred_rotated", //nolint:gosec // an audit code, not a credential
	}
	for c, want := range published {
		if got := msgIDAliases[c]; got != want {
			t.Errorf("alias of %s changed: got %q, published %q", c, got, want)
		}
	}
	for c := range msgIDAliases {
		if _, ok := Lookup(c); !ok {
			t.Errorf("alias for unregistered code %s", c)
		}
		if len(c) <= MaxMsgIDLen {
			t.Errorf("alias for %s, which fits the MSGID", c)
		}
		ns, _, _ := strings.Cut(string(c), ".")
		if !strings.HasPrefix(msgIDAliases[c], ns+".") {
			t.Errorf("alias %q leaves the namespace %q of %s", msgIDAliases[c], ns+".", c)
		}
	}
	if got := MsgIDAliases(); len(got) != len(msgIDAliases) || got[0].Code > got[len(got)-1].Code {
		t.Errorf("MsgIDAliases() = %v", got)
	}
}

// TestControlMsgIDsReserved: the MSGIDs of the syslog control messages (package outbound: heartbeat, checkpoint, test,
// and paddock.missing for a replayed event the index retention purged, alpha.9 decision 14d) fit RFC 5424 and never
// equal a code or an alias, so a receiver tells them from events by MSGID alone. They are literals here because
// outbound imports this package; its TestSyslogMsgIDsDistinct checks the frames.
func TestControlMsgIDsReserved(t *testing.T) {
	ids := map[string]Code{}
	for _, d := range Definitions() {
		ids[d.Code.MsgID()] = d.Code
		ids[string(d.Code)] = d.Code
	}
	for _, id := range []string{"paddock.heartbeat", "paddock.checkpoint", "paddock.test", "paddock.missing"} {
		if len(id) > MaxMsgIDLen {
			t.Errorf("control MSGID %q is longer than %d characters", id, MaxMsgIDLen)
		}
		for _, r := range id {
			if r < 33 || r > 126 {
				t.Errorf("control MSGID %q has a non-printable character", id)
			}
		}
		if c, ok := ids[id]; ok {
			t.Errorf("control MSGID %q collides with %s", id, c)
		}
	}
}
