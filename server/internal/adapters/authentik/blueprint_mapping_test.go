package authentik

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// mappingHarness runs a scope mapping's expression the way Authentik 2026.8 does (lib/expression/evaluator.py:
// wrap_expression and evaluate): the expression becomes the body of handler(<context keys>), and request is always a
// PolicyRequest whose context holds the evaluation's keyword arguments. authentik.events.signals is a stub whose
// get_login_event returns the session's login event. Input on stdin: {"expression", "token": null | {"session": null |
// {"mfa_devices": [...]}}}; output: the mapping's result as JSON, or {"error": "<type>: <message>"}.
const mappingHarness = `
import json, sys, types

class Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)

def get_login_event(session):
    return session.login_event

signals = types.ModuleType("authentik.events.signals")
signals.get_login_event = get_login_event
for name in ("authentik", "authentik.events"):
    sys.modules[name] = types.ModuleType(name)
sys.modules["authentik.events.signals"] = signals

spec = json.load(sys.stdin)
kwargs = {"provider": Obj(name="paddock-portal")}
if spec.get("with_token"):
    session = None
    if spec.get("session") is not None:
        event = Obj(context={"auth_method_args": {"mfa_devices": spec["session"]["mfa_devices"]}})
        session = Obj(login_event=event)
    kwargs["token"] = Obj(session=session)
context = {"user": Obj(username="admin"), "request": Obj(context=dict(kwargs)), **kwargs}
params = ",".join(context)
body = "\n".join("    " + line for line in spec["expression"].splitlines())
source = "def handler(%s):\n%s\nresult = handler(%s)" % (params, body, params)
scope = dict(context)
try:
    exec(compile(source, "mapping", "exec"), {}, scope)
    print(json.dumps(scope["result"]))
except Exception as exc:
    print(json.dumps({"error": "%s: %s" % (type(exc).__name__, exc)}))
`

// blueprintExpression returns the expression of the scope mapping named name in a blueprint of
// deploy/compose/authentik/blueprints, read as text: the blueprints use Authentik's custom YAML tags.
func blueprintExpression(t *testing.T, file, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "deploy", "compose", "authentik", "blueprints", file))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var lines []string
	found, inExpr, indent := false, false, ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case !found:
			found = strings.TrimSpace(line) == `name: "`+name+`"`
		case !inExpr:
			if strings.TrimSpace(line) == "expression: |" {
				inExpr = true
			}
		case indent == "" && strings.TrimSpace(line) != "":
			indent = line[:len(line)-len(strings.TrimLeft(line, " "))]
			lines = append(lines, strings.TrimPrefix(line, indent))
		case strings.TrimSpace(line) == "":
			lines = append(lines, "")
		case strings.HasPrefix(line, indent):
			lines = append(lines, strings.TrimPrefix(line, indent))
		default:
			return strings.TrimRight(strings.Join(lines, "\n"), "\n")
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(lines) == 0 {
		t.Fatalf("%s: no expression for mapping %q", file, name)
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

// TestAuthenticatorClassMappings (PDK-618): the authenticator classes mappings of the sign-in and of the step-up name
// the classes of the login event's MFA devices when Authentik evaluates them for a token (token endpoint, userinfo),
// and evaluate without error to an empty list without one: Authentik's discovery endpoint evaluates every scope mapping
// without a token for claims_supported, and an exception there is a property_mapping_exception event.
func TestAuthenticatorClassMappings(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed:", err)
	}
	webauthn := map[string]string{"app": "authentik_stages_authenticator_webauthn", "model_name": "webauthndevice"}
	totp := map[string]string{"app": "authentik_stages_authenticator_totp", "model_name": "totpdevice"}
	cases := []struct {
		name      string
		withToken bool
		session   any
		want      string
	}{
		{"discovery without a token", false, nil, `{"paddock_mfa_classes": []}`},
		{"token without a session", true, nil, `{"paddock_mfa_classes": []}`},
		{"login without MFA devices", true, map[string]any{"mfa_devices": nil}, `{"paddock_mfa_classes": []}`},
		{"WebAuthn and TOTP", true, map[string]any{"mfa_devices": []any{webauthn, totp, map[string]string{"app": "x"}}},
			`{"paddock_mfa_classes": ["authentik_stages_authenticator_webauthn.webauthndevice", "authentik_stages_authenticator_totp.totpdevice"]}`},
	}
	for _, m := range []struct{ file, name string }{
		{"paddock-portal.yaml", "Paddock: sign-in authenticator classes"},
		{"paddock-stepup.yaml", "Paddock: step-up authenticator classes"},
	} {
		expr := blueprintExpression(t, m.file, m.name)
		for _, c := range cases {
			t.Run(m.name+"/"+c.name, func(t *testing.T) {
				in, err := json.Marshal(map[string]any{"expression": expr, "with_token": c.withToken, "session": c.session})
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.CommandContext(t.Context(), python, "-I", "-c", mappingHarness)
				cmd.Stdin = strings.NewReader(string(in))
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("python3: %v: %s", err, out)
				}
				if got := strings.TrimSpace(string(out)); got != c.want {
					t.Errorf("result %s, want %s", got, c.want)
				}
			})
		}
	}
}
