package valkey_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	vk "github.com/valkey-io/valkey-go"

	"github.com/phischl/paddock-mdm/server/internal/allowlistcache"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
	"github.com/phischl/paddock-mdm/server/internal/platform/ratelimit"
	"github.com/phischl/paddock-mdm/server/internal/platform/valkey"
	"github.com/phischl/paddock-mdm/server/internal/revocationissuer"
	"github.com/phischl/paddock-mdm/server/internal/sessions"
	"github.com/phischl/paddock-mdm/server/internal/stepupproof"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
)

// step is one call of a role's real client code under that role's Valkey user.
type step struct {
	name string
	run  func(ctx context.Context) error
}

// want turns a result check into an error, so that every step reads as "no error".
func want(ok bool, format string) error {
	if ok {
		return nil
	}
	return errors.New(format)
}

// TestACLRoleMatrix runs the methods of plan M12h §14.5 per role under that role's user against the real entrypoint,
// template and configuration (valkeytest.StartACL), in an order in which each reader finds what its writer stored.
// The server is fresh, so the first call of every Lua script takes valkey-go's EVAL fallback after NOSCRIPT. Then it
// probes that denied keys and commands answer NOPERM and that the default user cannot authenticate.
func TestACLRoleMatrix(t *testing.T) {
	srv := valkeytest.StartACL(t)
	ctx := context.Background()
	now := time.Now()

	api, gateway, worker := srv.Client(t, "api"), srv.Client(t, "gateway"), srv.Client(t, "worker")
	compiler, escrowReader, revocationIssuer := srv.Client(t, "compiler"), srv.Client(t, "escrow_reader"), srv.Client(t, "revocation_issuer")

	apiCache, gwCache, wkCache := devicecache.New(api), devicecache.New(gateway), devicecache.New(worker)
	cpCache, riCache := devicecache.New(compiler), devicecache.New(revocationIssuer)
	apiSessions, wkSessions := sessions.NewStore(api), sessions.NewStore(worker)
	apiAllow, wkAllow := allowlistcache.NewVersion(api), allowlistcache.NewVersion(worker)
	limits := map[ratelimit.Class]int{ratelimit.Auth: 10}
	apiLimiter := ratelimit.New(ratelimit.NewValkeyStore(api), nil, limits)
	gwLimiter := ratelimit.New(ratelimit.NewValkeyStore(gateway), nil, limits)

	org, dev, account := uuid.New(), uuid.New(), uuid.New()
	enrollment, escrow, cmdID, riCmdID, apiCmdID, diagID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	keyID, tokenHash, otherHash := "key-"+dev.String(), bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	cmd := devicecache.Command{ExpiresAt: now.Add(time.Hour), Envelope: json.RawMessage(`{}`)}
	offer := agentrelease.Offer{Version: "1.2.3", Status: "running"}
	sid, mcpSID := sessions.NewID(), "mcp:"+strings.Repeat("ab", 32)
	rec := sessions.Record{AccountID: account, Kind: "portal", Role: "org_admin", Org: org, CreatedAt: now.Unix()}
	binding := sessions.Binding{AccountID: account, Kind: "portal", Role: "org_admin", Org: org}
	jti := uuid.NewString()

	roles := []struct {
		user  string
		steps []step
	}{
		{"worker", []step{
			{"PutDeviceKey", func(ctx context.Context) error {
				return wkCache.PutDeviceKey(ctx, keyID, devicecache.DeviceKey{DeviceID: dev, OrganizationID: org, Status: "active",
					PublicKey: []byte{1}}, 5)
			}},
			{"PutEnrollment", func(ctx context.Context) error {
				return wkCache.PutEnrollment(ctx, enrollment, devicecache.Enrollment{KeyID: keyID, OrganizationID: org, Status: "pending"}, now)
			}},
			{"PutToken", func(ctx context.Context) error {
				return wkCache.PutToken(ctx, tokenHash, devicecache.Token{OrganizationID: org, ExpiresAt: now.Add(time.Hour)}, now)
			}},
			{"PutUpdateRequest", func(ctx context.Context) error { return wkCache.PutUpdateRequest(ctx, dev, "1.2.3", now, now) }},
			{"PutEscrowStatus", func(ctx context.Context) error { return wkCache.PutEscrowStatus(ctx, escrow, dev, "stored") }},
			{"PutCommand", func(ctx context.Context) error { return wkCache.PutCommand(ctx, dev, cmdID, cmd) }},
			{"HasCommand", func(ctx context.Context) error {
				ok, err := wkCache.HasCommand(ctx, dev, cmdID)
				return errors.Join(err, want(ok, "command missing"))
			}},
			{"ClaimHeartbeat", func(ctx context.Context) error {
				ok, err := wkCache.ClaimHeartbeat(ctx, dev)
				return errors.Join(err, want(ok, "heartbeat not claimed"))
			}},
			{"ReleaseHeartbeat", func(ctx context.Context) error { return wkCache.ReleaseHeartbeat(ctx, dev) }},
			{"PutOffer", func(ctx context.Context) error { return wkCache.PutOffer(ctx, &offer) }},
			{"MarkDelivered", func(ctx context.Context) error { return wkCache.MarkDelivered(ctx, dev, 5) }},
		}},
		{"compiler", []step{
			{"PutBundlePointer", func(ctx context.Context) error {
				return cpCache.PutBundlePointer(ctx, dev, devicecache.BundlePointer{Version: 1, SHA256: "aa", ObjectKey: "o1"})
			}},
			{"PutBundlePointer over an existing pointer", func(ctx context.Context) error {
				return cpCache.PutBundlePointer(ctx, dev, devicecache.BundlePointer{Version: 2, SHA256: "bb", ObjectKey: "o2"})
			}},
			{"PutTimeTicket", func(ctx context.Context) error { return cpCache.PutTimeTicket(ctx, org, []byte("ticket")) }},
		}},
		{"revocation_issuer", []step{
			{"JTIClaims.Claim", func(ctx context.Context) error {
				ok, err := revocationissuer.NewJTIClaims(revocationIssuer).Claim(ctx, jti, enrollment)
				return errors.Join(err, want(ok, "first claim refused"))
			}},
			{"JTIClaims.Claim for another request", func(ctx context.Context) error {
				ok, err := revocationissuer.NewJTIClaims(revocationIssuer).Claim(ctx, jti, escrow)
				return errors.Join(err, want(!ok, "second request claimed the same jti"))
			}},
			{"PutCommand", func(ctx context.Context) error { return riCache.PutCommand(ctx, dev, riCmdID, cmd) }},
			{"HasCommand", func(ctx context.Context) error {
				ok, err := riCache.HasCommand(ctx, dev, riCmdID)
				return errors.Join(err, want(ok, "command missing"))
			}},
			{"DeleteCommand", func(ctx context.Context) error { return riCache.DeleteCommand(ctx, dev, riCmdID) }},
		}},
		{"gateway", []step{
			{"DeviceKey", func(ctx context.Context) error {
				k, ok, err := gwCache.DeviceKey(ctx, keyID)
				return errors.Join(err, want(ok && k.DeviceID == dev, "device key missing"))
			}},
			{"NextSeq", func(ctx context.Context) error {
				n, err := gwCache.NextSeq(ctx, dev)
				return errors.Join(err, want(n == 6, "seq not restored by PutDeviceKey"))
			}},
			{"ReleaseSeq", func(ctx context.Context) error {
				ok, err := gwCache.ReleaseSeq(ctx, dev, 6)
				return errors.Join(err, want(ok, "seq not released"))
			}},
			{"MarkDelivered", func(ctx context.Context) error { return gwCache.MarkDelivered(ctx, dev, 6) }},
			{"LastDelivered", func(ctx context.Context) error {
				n, ok, err := gwCache.LastDelivered(ctx, dev)
				return errors.Join(err, want(ok && n == 6, "delivered seq wrong"))
			}},
			{"BundlePointer", func(ctx context.Context) error {
				p, ok, err := gwCache.BundlePointer(ctx, dev)
				return errors.Join(err, want(ok && p.Version == 2, "bundle pointer wrong"))
			}},
			{"Enrollment", func(ctx context.Context) error {
				_, ok, err := gwCache.Enrollment(ctx, enrollment)
				return errors.Join(err, want(ok, "enrollment missing"))
			}},
			{"PutEnrollment", func(ctx context.Context) error {
				return gwCache.PutEnrollment(ctx, uuid.New(), devicecache.Enrollment{KeyID: "k", OrganizationID: org, Status: "processing"}, now)
			}},
			{"Token", func(ctx context.Context) error {
				_, ok, err := gwCache.Token(ctx, tokenHash)
				return errors.Join(err, want(ok, "token missing"))
			}},
			{"Commands", func(ctx context.Context) error {
				m, err := gwCache.Commands(ctx, dev, now)
				_, ok := m[cmdID]
				return errors.Join(err, want(ok, "command missing"))
			}},
			{"HasCommand", func(ctx context.Context) error {
				ok, err := gwCache.HasCommand(ctx, dev, cmdID)
				return errors.Join(err, want(ok, "command missing"))
			}},
			{"UseNonce", func(ctx context.Context) error {
				first, err1 := gwCache.UseNonce(ctx, dev.String(), "n1")
				second, err2 := gwCache.UseNonce(ctx, dev.String(), "n1")
				return errors.Join(err1, err2, want(first && !second, "nonce not single-use"))
			}},
			{"Allow", func(ctx context.Context) error {
				ok, _, err := gwLimiter.Allow(ctx, ratelimit.Auth, "gw")
				return errors.Join(err, want(ok, "rate limited"))
			}},
			{"ClaimResult", func(ctx context.Context) error { _, _, err := gwCache.ClaimResult(ctx, dev, cmdID, "done"); return err }},
			{"ClaimResult of a claimed command", func(ctx context.Context) error {
				_, status, err := gwCache.ClaimResult(ctx, dev, cmdID, "failed")
				return errors.Join(err, want(status == "done", "claim overwritten"))
			}},
			{"Result", func(ctx context.Context) error {
				_, _, ok, err := gwCache.Result(ctx, cmdID)
				return errors.Join(err, want(ok, "result missing"))
			}},
			{"ClaimDiagnostics", func(ctx context.Context) error {
				ok, err := gwCache.ClaimDiagnostics(ctx, dev, diagID)
				return errors.Join(err, want(ok, "diagnostics not claimed"))
			}},
			{"ReleaseDiagnostics", func(ctx context.Context) error { return gwCache.ReleaseDiagnostics(ctx, dev, diagID) }},
			{"EscrowStatus", func(ctx context.Context) error {
				_, _, ok, err := gwCache.EscrowStatus(ctx, escrow)
				return errors.Join(err, want(ok, "escrow status missing"))
			}},
			{"TimeTicket", func(ctx context.Context) error {
				b, err := gwCache.TimeTicket(ctx, org)
				return errors.Join(err, want(string(b) == "ticket", "time ticket missing"))
			}},
			{"Offer", func(ctx context.Context) error {
				_, ok, err := gwCache.Offer(ctx)
				return errors.Join(err, want(ok, "offer missing"))
			}},
			{"UpdateRequest", func(ctx context.Context) error {
				v, _, _, err := gwCache.UpdateRequest(ctx, dev)
				return errors.Join(err, want(v == "1.2.3", "update request missing"))
			}},
		}},
		{"api", []step{
			{"PutToken", func(ctx context.Context) error {
				return apiCache.PutToken(ctx, otherHash, devicecache.Token{OrganizationID: org, ExpiresAt: now.Add(time.Hour)}, now)
			}},
			{"DeleteCommand", func(ctx context.Context) error { return apiCache.DeleteCommand(ctx, dev, cmdID) }},
			{"ClaimResult", func(ctx context.Context) error {
				_, _, err := apiCache.ClaimResult(ctx, dev, apiCmdID, "done")
				return err
			}},
			{"ReleaseResult", func(ctx context.Context) error {
				ok, err := apiCache.ReleaseResult(ctx, dev, apiCmdID, "done")
				return errors.Join(err, want(ok, "result not released"))
			}},
			{"Result", func(ctx context.Context) error { _, _, _, err := apiCache.Result(ctx, cmdID); return err }},
			{"Offer", func(ctx context.Context) error {
				_, ok, err := apiCache.Offer(ctx)
				return errors.Join(err, want(ok, "offer missing"))
			}},
			{"stepupproof Put and Get", func(ctx context.Context) error {
				s := stepupproof.NewStore(api)
				raw, ok, err := s.Get(ctx, jti)
				return errors.Join(s.Put(ctx, jti, "raw-token", time.Minute), err, want(!ok && raw == "", "token before Put"))
			}},
			{"stepupproof Get", func(ctx context.Context) error {
				raw, ok, err := stepupproof.NewStore(api).Get(ctx, jti)
				return errors.Join(err, want(ok && raw == "raw-token", "token missing"))
			}},
			{"allowlistcache Bump and Get", func(ctx context.Context) error {
				err1 := apiAllow.Bump(ctx)
				n, err2 := apiAllow.Get(ctx)
				return errors.Join(err1, err2, want(n == 1, "version not bumped"))
			}},
			{"Allow", func(ctx context.Context) error {
				ok, _, err := apiLimiter.Allow(ctx, ratelimit.Auth, "api")
				return errors.Join(err, want(ok, "rate limited"))
			}},
			{"sessions Create", func(ctx context.Context) error { _, err := apiSessions.Create(ctx, sid, rec, time.Hour); return err }},
			{"sessions Get", func(ctx context.Context) error {
				_, _, found, err := apiSessions.Get(ctx, sid)
				return errors.Join(err, want(found, "session missing"))
			}},
			{"sessions Touch", func(ctx context.Context) error { return apiSessions.Touch(ctx, sid, account, time.Hour) }},
			{"sessions CreateMCP", func(ctx context.Context) error {
				_, err := apiSessions.CreateMCP(ctx, mcpSID, rec, time.Hour, sessions.Chain{Sub: "sub-a", AuthTime: 100, TTL: time.Hour})
				return err
			}},
			{"sessions Bind", func(ctx context.Context) error {
				_, err := apiSessions.Bind(ctx, mcpSID, "sub-a", 100, binding, time.Hour)
				return err
			}},
			{"sessions renewal CreateMCP", func(ctx context.Context) error {
				_, err := apiSessions.CreateMCP(ctx, "mcp:"+strings.Repeat("cd", 32), rec, time.Hour,
					sessions.Chain{Sub: "sub-a", AuthTime: 100, TTL: time.Hour, Renewal: true})
				return err
			}},
			{"sessions Binding", func(ctx context.Context) error {
				_, _, found, err := apiSessions.Binding(ctx, "sub-a", 100)
				return errors.Join(err, want(found, "binding missing"))
			}},
			{"sessions UseLoginToken", func(ctx context.Context) error {
				ok, err := apiSessions.UseLoginToken(ctx, "identity", time.Minute)
				return errors.Join(err, want(ok, "login token refused"))
			}},
			{"sessions Unbind", func(ctx context.Context) error { return apiSessions.Unbind(ctx, "sub-a", 100, account) }},
			{"sessions Delete", func(ctx context.Context) error { return apiSessions.Delete(ctx, sid, account) }},
			{"sessions Create again", func(ctx context.Context) error { _, err := apiSessions.Create(ctx, sid, rec, time.Hour); return err }},
			{"sessions CountAccount", func(ctx context.Context) error {
				n, err := apiSessions.CountAccount(ctx, account)
				return errors.Join(err, want(n == 1, "session not counted"))
			}},
			{"sessions RevokeAccount", func(ctx context.Context) error { _, err := apiSessions.RevokeAccount(ctx, account); return err }},
			{"sessions EndAll", func(ctx context.Context) error { _, err := apiSessions.EndAll(ctx); return err }},
		}},
		{"escrow_reader", []step{
			{"stepupproof Use", func(ctx context.Context) error {
				n, err := stepupproof.NewStore(escrowReader).Use(ctx, jti, now.Add(time.Minute))
				return errors.Join(err, want(n == 1, "first use not counted"))
			}},
		}},
		{"worker", []step{
			{"sessions Create (fixture) as api", func(ctx context.Context) error {
				_, err := apiSessions.Create(ctx, sessions.NewID(), rec, time.Hour)
				return err
			}},
			{"sessions CountAccount", func(ctx context.Context) error {
				n, err := wkSessions.CountAccount(ctx, account)
				return errors.Join(err, want(n == 1, "session not counted"))
			}},
			{"sessions RevokeAccount", func(ctx context.Context) error {
				n, err := wkSessions.RevokeAccount(ctx, account)
				return errors.Join(err, want(n == 1, "session not revoked"))
			}},
			{"sessions EndAll (admin end-sessions)", func(ctx context.Context) error { _, err := wkSessions.EndAll(ctx); return err }},
			{"allowlistcache Bump and Get (admin allowlist)", func(ctx context.Context) error {
				err1 := wkAllow.Bump(ctx)
				n, err2 := wkAllow.Get(ctx)
				return errors.Join(err1, err2, want(n == 2, "version not bumped"))
			}},
			{"DeleteUpdateRequest", func(ctx context.Context) error { return wkCache.DeleteUpdateRequest(ctx, dev) }},
			{"DeleteCommand", func(ctx context.Context) error { return wkCache.DeleteCommand(ctx, dev, cmdID) }},
			{"PutOffer nil", func(ctx context.Context) error { return wkCache.PutOffer(ctx, nil) }},
		}},
	}
	for _, r := range roles {
		for _, s := range r.steps {
			if err := s.run(ctx); err != nil {
				t.Errorf("%s %s: %v", r.user, s.name, err)
			}
		}
	}

	denied := []struct {
		user string
		args []string
	}{
		{"gateway", []string{"HSET", "dk:x", "f", "v"}},
		{"gateway", []string{"GET", "stepup:x"}},
		{"gateway", []string{"HSET", "cmd:x", "f", "v"}},
		{"api", []string{"HGETALL", "dk:x"}},
		{"api", []string{"GET", "revocation-jti:x"}},
		{"worker", []string{"GET", "stepup:x"}},
		{"compiler", []string{"HGETALL", "cmd:x"}},
		{"escrow_reader", []string{"GET", "stepup:x"}},
		{"escrow_reader", []string{"SET", "stepup:x", "v"}},
		{"revocation_issuer", []string{"GET", "stepup:x"}},
		{"healthcheck", []string{"GET", "sess-gen"}},
	}
	for _, u := range valkeytest.ACLUsers() {
		for _, args := range [][]string{{"CONFIG", "GET", "maxmemory"}, {"KEYS", "*"}, {"FLUSHALL"}, {"ACL", "LIST"}} {
			denied = append(denied, struct {
				user string
				args []string
			}{u, args})
		}
	}
	clients := map[string]vk.Client{}
	for _, d := range denied {
		c, ok := clients[d.user]
		if !ok {
			c = srv.Client(t, d.user)
			clients[d.user] = c
		}
		err := c.Do(ctx, c.B().Arbitrary(d.args...).Build()).Error()
		if err == nil || !strings.Contains(err.Error(), "NOPERM") {
			t.Errorf("%s %v: err %v, want NOPERM", d.user, d.args, err)
		}
	}

	for _, pw := range []string{"", "x", srv.Passwords["api"]} {
		cfg := srv.Config("api")
		cfg.Username, cfg.Password = "default", pw
		if c, err := valkey.New(cfg); err == nil {
			c.Close()
			t.Errorf("the default user authenticated with password %q", pw)
		}
	}
}

// aclLines returns the user lines of an ACL template of deploy/compose/valkey, split into fields.
func aclLines(t *testing.T, name string) [][]string {
	t.Helper()
	root, err := pgtest.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(root, "deploy", "compose", "valkey", name)) //nolint:gosec // fixed repository path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var lines [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) > 0 {
			if fields[0] != "user" || len(fields) < 3 {
				t.Fatalf("%s: not a user line: %q", name, sc.Text())
			}
			lines = append(lines, fields)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

// clientKeys are the key prefixes and fixed keys the client packages use (literal list, plan M12h §14.10.1 (5)):
// devicecache (tokenKey, deviceKeyKey, enrollmentKey, seqKey, deliveredKey, "nonce:", bundleKey, heartbeatKey,
// commandsKey, resultKey, diagnosticsKey, escrowKey, updateRequestKey, ticketKey, offerKey), stepupproof (tokenKey,
// usesKey), revocationissuer ("revocation-jti:"), sessions (sessionKey, accountKey, genKey, bindingKey,
// accountBindingsKey, chainKey, "mcp-used:"), allowlistcache (key) and platform/ratelimit (Prefix). A prefix ends in
// ':'; anything else is a fixed key.
var clientKeys = []string{
	"et:", "dk:", "enr:", "seq:", "sd:", "nonce:", "bp:", "hb:", "cmd:", "cres:", "diag:", "esc:", "au:", "tt:",
	"ar:current", "stepup:", "stepup-uses:", "revocation-jti:", "sess:", "acct-sess:", "sess-gen", "mcp-bind:",
	"acct-mcp-bind:", "mcp-chain:", "mcp-used:", "ipal:ver", ratelimit.Prefix,
}

// TestACLTemplateComplete checks the templates against plan M12h §14.2 and §14.10.1: the default user is off first,
// the user set is exact, only the development user holds ~*, no user is granted an administrative or dangerous
// command, and every key the client packages use is in some user's patterns.
func TestACLTemplateComplete(t *testing.T) {
	prod, dev := aclLines(t, "users.acl.tmpl"), aclLines(t, "users.acl.dev.tmpl")
	if len(prod) == 0 || strings.Join(prod[0], " ") != "user default off" {
		t.Fatalf("first user line is %v, want user default off", prod[0])
	}
	var users, devUsers []string
	for _, l := range prod {
		users = append(users, l[1])
	}
	for _, l := range dev {
		devUsers = append(devUsers, l[1])
	}
	if want := []string{"default", "api", "gateway", "worker", "compiler", "escrow_reader", "revocation_issuer", "healthcheck"}; !slices.Equal(users, want) {
		t.Errorf("users = %v, want %v", users, want)
	}
	if !slices.Equal(devUsers, []string{"acceptance"}) {
		t.Errorf("development users = %v, want [acceptance]", devUsers)
	}
	forbidden := []string{"+@all", "+@admin", "+@dangerous", "+config", "+flushall", "+flushdb", "+keys", "+debug", "+module",
		"+acl", "+shutdown", "+migrate", "allkeys", "allcommands", "nopass"}
	var patterns []string
	for _, l := range append(slices.Clone(prod), dev...) {
		for _, f := range l[2:] {
			lower := strings.ToLower(f)
			if slices.Contains(forbidden, lower) || slices.ContainsFunc(forbidden, func(p string) bool { return strings.HasPrefix(lower, p+"|") }) {
				t.Errorf("user %s is granted %s", l[1], f)
			}
		}
	}
	for _, l := range prod {
		for _, f := range l[2:] {
			if f == "~*" || f == "%R~*" || f == "%RW~*" {
				t.Errorf("production user %s holds %s", l[1], f)
			}
			if strings.HasPrefix(f, "+@") {
				t.Errorf("production user %s is granted the category %s", l[1], f)
			}
			if p, ok := strings.CutPrefix(f, "~"); ok {
				patterns = append(patterns, p)
			} else if p, ok := strings.CutPrefix(f, "%R~"); ok {
				patterns = append(patterns, p)
			}
		}
	}
	for _, k := range clientKeys {
		pattern := k
		if strings.HasSuffix(k, ":") {
			pattern = k + "*"
		}
		if !slices.Contains(patterns, pattern) {
			t.Errorf("no user has a pattern %s for the client key %s", pattern, k)
		}
	}
}
