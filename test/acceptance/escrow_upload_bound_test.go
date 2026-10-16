package acceptance

import (
	"bytes"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// TestEscrowUploadBound is gate S14 of plan M8s (decisions 29–31): the presigned URL of a header binds its announced
// size, so N+1 bytes are refused and leave no object; an object of another size that reaches the bucket anyway (as
// with a store that ignored the signed length) fails the escrow unread and is audited once, and the read-only worker
// leaves it in place for the operator; exactly N bytes are stored; and the edge refuses a body above 33 MiB on the
// escrow path.
func TestEscrowUploadBound(t *testing.T) {
	alice := login(t, env.Alice)
	org := orgOf(t, alice)
	idx := auditIndex(t)
	d := v2Device(t, alice, "", 1, 2)
	b := latestBundle(t, d, time.Minute, func(b *bundle.Bundle) bool { return b.Keys != nil && b.Keys.EscrowWrap != nil })
	header := testHeader(t)

	var announced int
	id, uploadURL, status := escrowHeader(t, d, b, 1, header, func(o []byte) []byte {
		announced = len(o)
		return append(o, 0)
	})
	if status < 400 || status > 499 {
		t.Fatalf("N+1 bytes to the presigned URL: HTTP %d, want 4xx", status)
	}
	key := escrowObjectKey(t, uploadURL)
	if n := escrowVersions(t, key); n != 0 {
		t.Fatalf("refused upload left %d versions of %s", n, key)
	}

	escrowPutRoot(t, key, announced+1)
	if status := waitEscrow(t, d, id, 2*time.Minute); status != escrow.StatusFailed {
		t.Fatalf("object of another size: %s", status)
	}
	if n := escrowVersions(t, key); n != 1 {
		t.Fatalf("%d versions of the object of another size, want it left in place", n)
	}
	ev := expectOneIndexEvent(t, idx, org, "code = 'device.header_object_rejected' AND actor->>'id' = $1", d.DeviceID,
		"device.header_object_rejected", "failure", auditPollTimeout)
	for name, want := range map[string]float64{"generation": 1, "declared_size": float64(announced), "object_size": float64(announced + 1)} {
		if got, _ := ev.Params[name].(float64); got != want {
			t.Errorf("param %s = %v, want %v", name, ev.Params[name], want)
		}
	}

	id, _, status = escrowHeader(t, d, b, 2, header, nil)
	if status != http.StatusOK {
		t.Fatalf("exactly N bytes: HTTP %d", status)
	}
	if status := waitEscrow(t, d, id, time.Minute); status != escrow.StatusStored {
		t.Fatalf("exactly N bytes: %s", status)
	}

	code := edgeSend(t, http.MethodPut, stack.BundlesURL()+"/paddock-escrow/org/x", 34<<20)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("34 MiB to the escrow path: HTTP %d, want 413", code)
	}
}

// escrowObjectKey is the object key of a presigned escrow URL.
func escrowObjectKey(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := strings.CutPrefix(u.Path, "/paddock-escrow/")
	if !ok {
		t.Fatalf("upload URL %s is not in the escrow bucket", raw)
	}
	return key
}

// escrowPutRoot writes size zero bytes to key in the escrow bucket with the root credential, from a container on the
// control-plane network (the bucket has no published port).
func escrowPutRoot(t *testing.T, key string, size int) {
	t.Helper()
	image, err := stack.Image("AWS_CLI_IMAGE")
	if err != nil {
		t.Fatal(err)
	}
	creds := mustSecret(t, "rustfs_root_user") + "\n" + mustSecret(t, "rustfs_root_password") + "\n"
	script := `read -r AWS_ACCESS_KEY_ID; read -r AWS_SECRET_ACCESS_KEY; export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY; ` +
		`head -c "$2" /dev/zero >/tmp/object && ` +
		`aws --endpoint-url http://rustfs:9000 s3api put-object --bucket paddock-escrow --key "$1" --body /tmp/object --output json`
	out, err := stack.Docker(testContext(t, 2*time.Minute), strings.NewReader(creds), "run", "--rm", "-i", "--network", "paddock_cp",
		"-e", "AWS_DEFAULT_REGION=us-east-1", "-e", "AWS_PAGER=", "--entrypoint", "sh", image, "-c", script, "sh", key, strconv.Itoa(size))
	if err != nil {
		t.Fatalf("put object: %v %s", err, out)
	}
}

// edgeSend sends size zero bytes through Caddy and returns the HTTP status.
func edgeSend(t *testing.T, method, target string, size int) int {
	t.Helper()
	req, err := http.NewRequestWithContext(testContext(t, time.Minute), method, target, bytes.NewReader(make([]byte, size)))
	if err != nil {
		t.Fatal(err)
	}
	client, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res.StatusCode
}
