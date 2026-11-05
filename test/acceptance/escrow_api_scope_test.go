package acceptance

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// TestEscrowAPICredentialScope checks the RustFS policy paddock-escrow-api (ADR 0048, amendment 2026-11-05): the api's
// escrow credential deletes and lists diagnostics bundles only; it cannot delete a header, read an object outside the
// header and diagnostics prefixes, or list any other prefix of the escrow bucket.
func TestEscrowAPICredentialScope(t *testing.T) {
	base := "org/" + uuid.NewString() + "/devices/" + uuid.NewString()
	header := base + "/luks-header/" + uuid.NewString()
	other := base + "/other/" + uuid.NewString()
	diagnostics := base + "/diagnostics/" + uuid.NewString()
	for _, key := range []string{header, other, diagnostics} {
		escrowPutRoot(t, key, 16)
	}

	denied := map[string][]string{
		"delete a header":            {"delete-object", "--bucket", "paddock-escrow", "--key", header},
		"read another prefix":        {"get-object", "--bucket", "paddock-escrow", "--key", other, "/tmp/out"},
		"list the whole bucket":      {"list-object-versions", "--bucket", "paddock-escrow"},
		"list the headers of a host": {"list-object-versions", "--bucket", "paddock-escrow", "--prefix", base + "/luks-header/"},
		"list objects of the org":    {"list-objects-v2", "--bucket", "paddock-escrow", "--prefix", "org/"},
	}
	for name, args := range denied {
		// stack.Docker puts the container's stderr, where the aws CLI prints the error, into err, not into the output.
		if out, err := escrowAPICall(t, args...); err == nil || !strings.Contains(out+err.Error(), "AccessDenied") {
			t.Errorf("%s: err %v, output %s; want AccessDenied", name, err, out)
		}
	}

	if out, err := escrowAPICall(t, "list-object-versions", "--bucket", "paddock-escrow", "--prefix", diagnostics); err != nil {
		t.Errorf("list a diagnostics bundle: %v %s", err, out)
	}
	if out, err := escrowAPICall(t, "delete-object", "--bucket", "paddock-escrow", "--key", diagnostics); err != nil {
		t.Errorf("delete a diagnostics bundle: %v %s", err, out)
	}
}

// escrowAPICall runs one s3api call with the api's escrow credential from a container on the control-plane network.
func escrowAPICall(t *testing.T, args ...string) (string, error) {
	t.Helper()
	image, err := stack.Image("AWS_CLI_IMAGE")
	if err != nil {
		t.Fatal(err)
	}
	creds := mustSecret(t, "rustfs_escrow_api_access_key") + "\n" + mustSecret(t, "rustfs_escrow_api_secret_key") + "\n"
	script := `read -r AWS_ACCESS_KEY_ID; read -r AWS_SECRET_ACCESS_KEY; export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY; ` +
		`aws --endpoint-url http://rustfs:9000 s3api "$@" --output json`
	dockerArgs := append([]string{"run", "--rm", "-i", "--network", stack.Network("cp"), "-e", "AWS_DEFAULT_REGION=us-east-1",
		"-e", "AWS_PAGER=", "--entrypoint", "sh", image, "-c", script, "sh"}, args...)
	out, err := stack.Docker(testContext(t, 2*time.Minute), strings.NewReader(creds), dockerArgs...)
	return string(out), err
}
