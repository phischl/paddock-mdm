package prodcheck

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

// BrokerPermissionsItem is the checklist item of the RabbitMQ permissions.
const BrokerPermissionsItem = "rabbitmq: permissions match the definitions"

// BrokerVhost is the virtual host of every Paddock user.
const BrokerVhost = "paddock"

// BrokerPermission is one user's permissions on the vhost (the definitions' permissions entry, or a line of
// `rabbitmqctl list_permissions --formatter json`).
type BrokerPermission struct {
	User      string `json:"user"`
	Vhost     string `json:"vhost"`
	Configure string `json:"configure"`
	Write     string `json:"write"`
	Read      string `json:"read"`
}

// BrokerPermissions are the permissions the definitions grant (Want) and those the running broker has (Got).
type BrokerPermissions struct {
	Want, Got []BrokerPermission
}

// ParseBrokerDefinitions reads the permissions of the vhost from the definitions template
// (rabbitmq/definitions.json.tmpl). The passwords' placeholders are not read.
func ParseBrokerDefinitions(r io.Reader) ([]BrokerPermission, error) {
	var defs struct {
		Permissions []BrokerPermission `json:"permissions"`
	}
	if err := json.NewDecoder(r).Decode(&defs); err != nil {
		return nil, fmt.Errorf("rabbitmq definitions: %w", err)
	}
	var out []BrokerPermission
	for _, p := range defs.Permissions {
		if p.Vhost == BrokerVhost {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("rabbitmq definitions: no permissions on vhost %s", BrokerVhost)
	}
	return out, nil
}

// ParseBrokerPermissions reads `rabbitmqctl list_permissions -p paddock --formatter json`: the permissions of the
// vhost's users.
func ParseBrokerPermissions(r io.Reader) ([]BrokerPermission, error) {
	var got []BrokerPermission
	if err := json.NewDecoder(r).Decode(&got); err != nil {
		return nil, fmt.Errorf("rabbitmq permissions: %w", err)
	}
	for i := range got {
		got[i].Vhost = BrokerVhost
	}
	return got, nil
}

// CheckBrokerPermissions compares the broker's permissions with the definitions (PDK-1017, main §44): a user of the
// definitions without its permissions, with other patterns, or a user the definitions do not name is a finding. Only
// user names and permission patterns are compared and printed; the definitions' passwords never are.
func CheckBrokerPermissions(p BrokerPermissions) Result {
	got := map[string]BrokerPermission{}
	for _, g := range p.Got {
		got[g.User] = g
	}
	var f []string
	for _, w := range p.Want {
		g, ok := got[w.User]
		delete(got, w.User)
		switch {
		case !ok:
			f = append(f, fmt.Sprintf("%s: missing (want configure %q write %q read %q); run ./paddock bootstrap broker",
				w.User, w.Configure, w.Write, w.Read))
		case g.Configure != w.Configure || g.Write != w.Write || g.Read != w.Read:
			f = append(f, fmt.Sprintf("%s: configure %q write %q read %q, want configure %q write %q read %q; run ./paddock bootstrap broker",
				w.User, g.Configure, g.Write, g.Read, w.Configure, w.Write, w.Read))
		}
	}
	extra := make([]string, 0, len(got))
	for user := range got {
		extra = append(extra, user)
	}
	slices.Sort(extra)
	for _, user := range extra {
		f = append(f, fmt.Sprintf("%s: has permissions on vhost %s that the definitions do not grant", user, BrokerVhost))
	}
	return result(BrokerPermissionsItem, f)
}
