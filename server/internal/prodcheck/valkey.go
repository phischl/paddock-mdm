package prodcheck

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Valkey ACL users (plan M12h §14): one user per role with a client, each with its own secret
// valkey_<user>_password; healthcheck is the container health check's user.
const (
	valkeyService      = "valkey"
	fleetRedisService  = "fleet-redis"
	valkeyEntrypoint   = "/usr/local/bin/paddock-entrypoint.sh"
	valkeyTemplate     = "/etc/valkey/users.acl.tmpl"
	valkeyDevTemplate  = "/etc/valkey/users.acl.dev.tmpl"
	valkeyACLDir       = "/run/valkey"
	valkeyConfTarget   = "/etc/valkey/valkey.conf"
	valkeyDevUser      = "acceptance"
	fleetRedisConfFile = "fleet-redis.conf"
)

// valkeyUsers maps each role service to its Valkey user (plan M12h §14.6.2).
var valkeyUsers = map[string]string{
	"paddock-api":               "api",
	"paddock-gateway":           "gateway",
	"paddock-worker":            "worker",
	"paddock-compiler":          "compiler",
	"paddock-escrow-reader":     "escrow_reader",
	"paddock-revocation-issuer": "revocation_issuer",
}

// retiredValkeySecrets are the shared credential of the single-password Valkey; no service may mount them any more.
var retiredValkeySecrets = []string{"valkey_password", "valkey_auth_conf"}

func valkeySecret(user string) string { return "valkey_" + user + "_password" }

// valkeyPasswordSecrets returns the valkey_<user>_password secrets a service mounts, by source.
func valkeyPasswordSecrets(s Service) []string {
	var out []string
	for _, sec := range s.Secrets {
		if strings.HasPrefix(sec.Source, "valkey_") && strings.HasSuffix(sec.Source, "_password") &&
			!slices.Contains(retiredValkeySecrets, sec.Source) {
			out = append(out, sec.Source)
		}
	}
	slices.Sort(out)
	return out
}

func mountSource(s Service, target string) (string, bool) {
	for _, v := range s.Volumes {
		if v.Target == target {
			return v.Source, true
		}
	}
	return "", false
}

// firstUserLine returns the first line of an ACL template that defines a user.
func firstUserLine(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // operator configuration
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.Join(strings.Fields(sc.Text()), " "); strings.HasPrefix(line, "user ") {
			return line, nil
		}
	}
	return "", sc.Err()
}

// checkValkeyACL: the valkey service renders its ACL file through Paddock's entrypoint from the mounted template into
// a tmpfs, and the template switches the default user off before any other user.
func checkValkeyACL(c Config) Result {
	var f []string
	s := c.Services[valkeyService]
	if !slices.Equal(s.Entrypoint, []string{valkeyEntrypoint}) {
		f = append(f, fmt.Sprintf("entrypoint is %v, not %s", s.Entrypoint, valkeyEntrypoint))
	}
	if !slices.Contains(s.Tmpfs, valkeyACLDir) {
		f = append(f, "no tmpfs at "+valkeyACLDir)
	}
	if src, ok := mountSource(s, valkeyTemplate); !ok {
		f = append(f, valkeyTemplate+" is not mounted")
	} else if line, err := firstUserLine(src); err != nil {
		f = append(f, "ACL template unreadable: "+src)
	} else if line != "user default off" {
		f = append(f, fmt.Sprintf("the first user of %s is %q, not \"user default off\"", src, line))
	}
	return result("valkey: ACL entrypoint and default user off", f)
}

// checkValkeyUsers: every Valkey client authenticates as its role's user with exactly its own secret, the valkey
// service holds every role's secret, and the shared password of earlier releases is gone.
func checkValkeyUsers(c Config) Result {
	var f []string
	for _, name := range sortedServices(c) {
		s := c.Services[name]
		for _, sec := range s.Secrets {
			if slices.Contains(retiredValkeySecrets, sec.Source) {
				f = append(f, fmt.Sprintf("%s: mounts the retired secret %s", name, sec.Source))
			}
		}
		if name == valkeyService {
			want := []string{valkeySecret("healthcheck")}
			for _, u := range valkeyUsers {
				want = append(want, valkeySecret(u))
			}
			slices.Sort(want)
			got := slices.DeleteFunc(valkeyPasswordSecrets(s), func(n string) bool { return n == valkeySecret(valkeyDevUser) })
			if !slices.Equal(got, want) {
				f = append(f, fmt.Sprintf("%s: mounts %v, want %v", name, got, want))
			}
			continue
		}
		if env(s, "PADDOCK_VALKEY_ADDR") == "" {
			continue
		}
		user, known := valkeyUsers[name]
		if !known {
			f = append(f, name+": connects to Valkey but has no Valkey user")
			continue
		}
		if got := env(s, "PADDOCK_VALKEY_USER"); got != user {
			f = append(f, fmt.Sprintf("%s: PADDOCK_VALKEY_USER is %q, not %q", name, got, user))
		}
		if got := valkeyPasswordSecrets(s); !slices.Equal(got, []string{valkeySecret(user)}) {
			f = append(f, fmt.Sprintf("%s: mounts %v, want exactly %s", name, got, valkeySecret(user)))
		}
	}
	return result("valkey: one user per role", f)
}

// checkValkeyNoDevUser: the development and CI user acceptance (users.acl.dev.tmpl, ~* with SCAN) never reaches a
// production host.
func checkValkeyNoDevUser(c Config) Result {
	var f []string
	s := c.Services[valkeyService]
	if slices.Contains(valkeyPasswordSecrets(s), valkeySecret(valkeyDevUser)) {
		f = append(f, "mounts "+valkeySecret(valkeyDevUser))
	}
	if _, ok := mountSource(s, valkeyDevTemplate); ok {
		f = append(f, "mounts "+valkeyDevTemplate)
	}
	return result("valkey: no development user", f)
}

// checkFleetRedisConf: Fleet's Redis keeps the requirepass configuration in its own file, so the ACL configuration of
// Paddock's Valkey never applies to it (plan M12h §14.2 A7).
func checkFleetRedisConf(c Config) Result {
	var f []string
	src, ok := mountSource(c.Services[fleetRedisService], valkeyConfTarget)
	switch {
	case !ok:
		f = append(f, valkeyConfTarget+" is not mounted")
	case filepath.Base(src) != fleetRedisConfFile:
		f = append(f, fmt.Sprintf("%s is mounted from %s, not from valkey/%s", valkeyConfTarget, src, fleetRedisConfFile))
	}
	return result("fleet-redis: own configuration file", f)
}
