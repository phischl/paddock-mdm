package acceptance

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// TestEscrowReaderIsolation is gate ER of plan M4b.1 (AC3): the api holds no credential that decrypts escrows, no
// other role reaches the escrow-reader, and even with the api's own bearer secret, called directly from a container on the escrow network (code execution in
// the api), the escrow-reader decrypts nothing without a fresh step-up token of an administrator of the
// organization: a forged token, a stale one and one of another organization's request are refused; a fresh one of
// alice decrypts alice's organization's escrow (the positive control).
func TestEscrowReaderIsolation(t *testing.T) {
	ctx := testContext(t, 5*time.Minute)
	t.Run("compose", func(t *testing.T) {
		out, err := stack.ComposeProduction(ctx, nil, "config", "--format", "json")
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Services map[string]struct {
				Environment map[string]*string        `json:"environment"`
				Secrets     []struct{ Source string } `json:"secrets"`
				Networks    map[string]any            `json:"networks"`
				Ports       []any                     `json:"ports"`
			} `json:"services"`
		}
		if err := json.Unmarshal([]byte(out), &cfg); err != nil {
			t.Fatal(err)
		}
		for name, svc := range cfg.Services {
			var secrets []string
			for _, s := range svc.Secrets {
				secrets = append(secrets, s.Source)
			}
			holds := slices.Contains(secrets, "approle_escrow_reader_role_id") || slices.Contains(secrets, "approle_escrow_reader_secret_id")
			if holds != (name == "paddock-escrow-reader") {
				t.Errorf("%s: escrow-reader AppRole secrets %v", name, secrets)
			}
			for k := range svc.Environment {
				if strings.HasPrefix(k, "PADDOCK_OPENBAO_ESCROW_") {
					t.Errorf("%s: %s", name, k)
				}
			}
			if _, on := svc.Networks["escrow"]; on != (name == "paddock-api" || name == "paddock-escrow-reader") {
				t.Errorf("%s on network escrow: %v", name, on)
			}
		}
		if er := cfg.Services["paddock-escrow-reader"]; len(er.Ports) != 0 {
			t.Errorf("paddock-escrow-reader publishes ports %v", er.Ports)
		}
	})

	t.Run("not reachable from the control-plane network", func(t *testing.T) {
		image, err := stack.Image("GO_BUILD_IMAGE")
		if err != nil {
			t.Fatal(err)
		}
		// The service name resolves on cp, but the escrow-reader listens on its escrow address only.
		out, err := stack.Docker(ctx, nil, "run", "--rm", "--network", "paddock_cp", image, "sh", "-c",
			"curl -sS -m 5 -o /dev/null -X POST http://paddock-escrow-reader:8080/internal/v1/decrypt; echo exit=$?")
		if err != nil || !strings.Contains(out, "exit=7") {
			t.Fatalf("from network cp: %q %v, want connection refused (curl exit 7)", out, err)
		}
	})

	alice := login(t, env.Alice)
	d := v2Device(t, alice, "", 1, 2)
	b := latestBundle(t, d, time.Minute, func(b *bundle.Bundle) bool { return b.Keys != nil && b.Keys.EscrowWrap != nil })
	password := "er-" + uniqueSuffix()
	escrowID, stored := escrowUpload(t, d, b, 1, password)
	if stored != escrow.StatusStored {
		t.Fatalf("escrow upload %s", stored)
	}
	acme := orgOf(t, alice)
	globex := orgOf(t, login(t, env.Carol))
	request := func(org uuid.UUID, token string) map[string]any {
		return map[string]any{"organization_id": org, "device_id": d.DeviceID, "escrow_ids": []string{escrowID},
			"stepup_id_token": token, "purpose": "local_admin_reveal"}
	}

	stepUp(t, alice, env.Alice, true)
	fresh := latestStepUpToken(t)
	status, body := callEscrowReader(t, mustSecret(t, "escrow_reader_token"), request(acme, fresh))
	var plain struct {
		Plaintexts map[string][]byte `json:"plaintexts"`
	}
	if err := json.Unmarshal(body, &plain); status != http.StatusOK || err != nil || string(plain.Plaintexts[escrowID]) != password {
		t.Fatalf("positive control: HTTP %d (%v), the plaintext matches: %v", status, err, string(plain.Plaintexts[escrowID]) == password)
	}

	for name, c := range map[string]struct {
		secret string
		req    map[string]any
		status int
		code   string
	}{
		"without the bearer secret": {secret: "guessed", req: request(acme, fresh), status: http.StatusUnauthorized},
		"forged token":              {req: request(acme, forgedStepUpToken(t, fresh)), status: http.StatusForbidden, code: "stepup_invalid"},
		"another organization":      {req: request(globex, fresh), status: http.StatusForbidden, code: "not_org_admin"},
	} {
		secret := c.secret
		if secret == "" {
			secret = mustSecret(t, "escrow_reader_token")
		}
		status, body := callEscrowReader(t, secret, c.req)
		if status != c.status || c.code != "" && !strings.Contains(string(body), `"`+c.code+`"`) || strings.Contains(string(body), "plaintexts") {
			t.Errorf("%s: HTTP %d %s", name, status, body)
		}
	}

	// Stale: the same token once the step-up window (development: 30 s) has passed since its authentication.
	window := serverStepUp(t, alice).Window
	time.Sleep(time.Until(stepUpAuthTime(t, fresh).Add(window + expirySlack)))
	if status, body := callEscrowReader(t, mustSecret(t, "escrow_reader_token"), request(acme, fresh)); status != http.StatusForbidden ||
		!strings.Contains(string(body), `"stepup_invalid"`) {
		t.Errorf("stale token: HTTP %d %s", status, body)
	}
}

// callEscrowReader posts req to the escrow-reader from a throwaway container on the escrow network, as code in the
// api container could. The secret and the body travel on stdin.
func callEscrowReader(t *testing.T, secret string, req map[string]any) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	image, err := stack.Image("GO_BUILD_IMAGE")
	if err != nil {
		t.Fatal(err)
	}
	script := `IFS= read -r auth; curl -sS -o /tmp/body -w '%{http_code}' -H "Authorization: Bearer $auth" ` +
		`-H 'Content-Type: application/json' --data-binary @- http://escrow-reader:8080/internal/v1/decrypt; echo; cat /tmp/body`
	out, err := stack.Docker(testContext(t, 2*time.Minute), strings.NewReader(secret+"\n"+string(body)),
		"run", "--rm", "-i", "--network", "paddock_escrow", image, "sh", "-c", script)
	if err != nil {
		t.Fatalf("call from the escrow network: %v", err)
	}
	code, rest, _ := strings.Cut(out, "\n")
	status, err := strconv.Atoi(strings.TrimSpace(code))
	if err != nil {
		t.Fatalf("curl answered %q", code)
	}
	return status, []byte(rest)
}

// latestStepUpToken returns the newest step-up ID token of alice that the api keeps in Valkey (stepup:<jti>).
func latestStepUpToken(t *testing.T) string {
	t.Helper()
	valkey := func(args string) string {
		out, err := stack.Compose(testContext(t, time.Minute), nil, "exec", "-T", "valkey", "sh", "-c",
			`REDISCLI_AUTH="$(cat /run/secrets/valkey_password)" valkey-cli --no-auth-warning `+args)
		if err != nil {
			t.Fatalf("valkey-cli: %v", err)
		}
		return out
	}
	var newest string
	var newestAt time.Time
	for _, key := range strings.Fields(valkey(`--scan --pattern 'stepup:*'`)) {
		raw := strings.TrimSpace(valkey("GET " + key))
		claims := stepUpClaims(t, raw)
		if claims.PreferredUsername == env.Alice && time.Unix(claims.AuthTime, 0).After(newestAt) {
			newest, newestAt = raw, time.Unix(claims.AuthTime, 0)
		}
	}
	if newest == "" {
		t.Fatal("no step-up token of alice in Valkey")
	}
	return newest
}

type idTokenClaims struct {
	PreferredUsername string `json:"preferred_username"`
	AuthTime          int64  `json:"auth_time"`
}

// stepUpClaims decodes the payload of an ID token without verifying it.
func stepUpClaims(t *testing.T, raw string) idTokenClaims {
	t.Helper()
	parts := strings.Split(raw, ".")
	var c idTokenClaims
	if len(parts) != 3 {
		return c
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err == nil {
		err = json.Unmarshal(payload, &c)
	}
	if err != nil {
		t.Fatalf("ID token payload: %v", err)
	}
	return c
}

func stepUpAuthTime(t *testing.T, raw string) time.Time {
	return time.Unix(stepUpClaims(t, raw).AuthTime, 0)
}

// forgedStepUpToken copies the header and claims of a real token, with a fresh auth_time, and signs it with a key of
// its own.
func forgedStepUpToken(t *testing.T, real string) string {
	t.Helper()
	parts := strings.Split(real, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims["auth_time"], claims["jti"] = time.Now().Unix(), "forged-"+uniqueSuffix()
	payload, _ = json.Marshal(claims)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signed := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s.%s", signed, base64.RawURLEncoding.EncodeToString(sig))
}
