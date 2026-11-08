package acceptance

import (
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// valkeyACLUsers are the Valkey users of the development and CI stack (plan M12h §14.2 A1 and §14.6.4).
func valkeyACLUsers() []string {
	return []string{"api", "gateway", "worker", "compiler", "escrow_reader", "revocation_issuer", "healthcheck", "acceptance"}
}

// TestValkeyACL is gate C2 of plan M12h §14.13 against the running stack: one user per role with key permissions by
// direction, no administrative command for any user, the default user off, and only hashes of the passwords in the
// rendered ACL file and nowhere in Valkey's log.
func TestValkeyACL(t *testing.T) {
	denied := func(t *testing.T, user, args string) {
		t.Helper()
		out, _ := valkeyCLIResult(t, user, args)
		if !strings.Contains(out, "NOPERM") {
			t.Errorf("--user %s %s answered %q, want NOPERM", user, args, strings.TrimSpace(out))
		}
	}

	t.Run("C2a gateway reads device keys and writes nothing it only reads", func(t *testing.T) {
		denied(t, "gateway", "GET stepup:x")
		denied(t, "gateway", "HSET dk:x f v")
		denied(t, "gateway", "HSET cmd:x f v")
		if got := valkeyCLI(t, "gateway", "HGETALL dk:x"); got != "" {
			t.Errorf("--user gateway HGETALL dk:x = %q, want an empty hash", got)
		}
	})
	t.Run("C2b api keeps step-up tokens, no device keys, no revocation claims", func(t *testing.T) {
		denied(t, "api", "HGETALL dk:x")
		denied(t, "api", "GET revocation-jti:x")
		if got := valkeyCLI(t, "api", "GET stepup:x"); got != "" {
			t.Errorf("--user api GET stepup:x = %q, want nil", got)
		}
	})
	t.Run("C2c escrow_reader counts uses only", func(t *testing.T) {
		denied(t, "escrow_reader", "GET stepup:x")
		key := "stepup-uses:acl-" + uniqueSuffix()
		t.Cleanup(func() { valkeyCLI(t, "acceptance", "DEL "+key) })
		if got := valkeyCLI(t, "escrow_reader", "INCR "+key); got != "1" {
			t.Errorf("--user escrow_reader INCR %s = %q, want 1", key, got)
		}
	})
	t.Run("C2d compiler and revocation_issuer stay in their keys", func(t *testing.T) {
		denied(t, "compiler", "HGETALL cmd:x")
		denied(t, "revocation_issuer", "GET stepup:x")
	})
	t.Run("C2e no administrative command, default user off", func(t *testing.T) {
		for _, u := range valkeyACLUsers() {
			for _, args := range []string{"CONFIG GET maxmemory", "KEYS '*'", "FLUSHALL", "ACL LIST"} {
				denied(t, u, args)
			}
		}
		out, _ := stack.Compose(testContext(t, time.Minute), nil, "exec", "-T", "valkey", "sh", "-c",
			`REDISCLI_AUTH=x valkey-cli --no-auth-warning --user default PING`)
		if strings.Contains(out, "PONG") || !strings.Contains(out, "WRONGPASS") {
			t.Errorf("--user default PING answered %q, want an authentication failure", strings.TrimSpace(out))
		}
	})
	t.Run("only password hashes in the ACL file and none in the log", func(t *testing.T) {
		acl, err := stack.Compose(testContext(t, time.Minute), nil, "exec", "-T", "valkey", "cat", "/run/valkey/users.acl")
		if err != nil {
			t.Fatalf("read users.acl: %v", err)
		}
		logs, err := stack.Compose(testContext(t, time.Minute), nil, "logs", "--no-color", "valkey")
		if err != nil {
			t.Fatalf("valkey logs: %v", err)
		}
		for _, u := range valkeyACLUsers() {
			pw, err := stack.Compose(testContext(t, time.Minute), nil, "exec", "-T", "valkey", "cat", "/run/secrets/valkey_"+u+"_password")
			if err != nil || strings.TrimSpace(pw) == "" {
				t.Fatalf("read the password of %s: %v", u, err)
			}
			pw = strings.TrimSpace(pw)
			if strings.Contains(acl, pw) {
				t.Errorf("users.acl holds the plaintext password of %s", u)
			}
			if strings.Contains(logs, pw) {
				t.Errorf("Valkey's log holds the password of %s", u)
			}
			line := ""
			for _, l := range strings.Split(acl, "\n") {
				if strings.HasPrefix(l, "user "+u+" ") {
					line = l
				}
			}
			if f := strings.Fields(line); len(f) < 4 || f[2] != "on" || len(f[3]) != 65 || f[3][0] != '#' {
				t.Errorf("users.acl line of %s is not 'user %s on #<sha256>'", u, u)
			}
		}
		if !strings.Contains(acl, "user default off") {
			t.Error("users.acl does not switch the default user off")
		}
	})
}
