package outbound

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// PseudonymPrefix starts every pseudonym.
const PseudonymPrefix = "u_"

// pseudonymHexLength is the number of hex characters of the HMAC a pseudonym keeps.
const pseudonymHexLength = 24

// pseudonymParams are the params that carry user names (ADR 0031 decision 8); the list is closed.
var pseudonymParams = []string{
	"username", "user", "display_name", "requested_by", "approved_by", "created_by", "members", "users",
}

// Pseudonym returns "u_" and the first 24 hex characters of HMAC-SHA256 with key over the lower-cased user name.
func Pseudonym(key []byte, username string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(strings.ToLower(username)))
	return PseudonymPrefix + hex.EncodeToString(m.Sum(nil))[:pseudonymHexLength]
}

// Pseudonymize returns a copy of ev with every user name of ADR 0031 decision 8 replaced by its pseudonym under key:
// actor.display of administrators, target.display of users and administrator accounts, and the user-name params
// (a string or a list of strings; other values such as a member count stay). It drops actor.id and actor.ip of
// administrators, which identify the person as well. ev is not modified.
func Pseudonymize(key []byte, ev audit.Event) audit.Event {
	out := ev
	if ev.Actor.Type == audit.ActorAdmin || ev.Actor.Type == audit.ActorPlatformAdmin {
		out.Actor.Display = pseudonymOf(key, ev.Actor.Display)
		out.Actor.ID = ""
		out.Actor.IP = ""
	}
	if ev.Target != nil {
		t := *ev.Target
		if t.Type == "user" || t.Type == "admin_account" {
			t.Display = pseudonymOf(key, t.Display)
		}
		out.Target = &t
	}
	if ev.Params != nil {
		out.Params = maps.Clone(ev.Params)
		for _, name := range pseudonymParams {
			if v, ok := out.Params[name]; ok {
				out.Params[name] = pseudonymValue(key, v)
			}
		}
	}
	return out
}

func pseudonymOf(key []byte, name string) string {
	if name == "" {
		return ""
	}
	return Pseudonym(key, name)
}

func pseudonymValue(key []byte, v any) any {
	switch t := v.(type) {
	case string:
		return pseudonymOf(key, t)
	case []string:
		out := slices.Clone(t)
		for i, s := range out {
			out[i] = pseudonymOf(key, s)
		}
		return out
	case []any:
		out := slices.Clone(t)
		for i, e := range out {
			if s, ok := e.(string); ok {
				out[i] = pseudonymOf(key, s)
			}
		}
		return out
	}
	return v
}
