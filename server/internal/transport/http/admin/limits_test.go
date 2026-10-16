package admin_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/releasesig"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// padded returns doc as JSON preceded by whitespace to exactly size bytes, so that the decoder reads the whole body.
func padded(t *testing.T, doc any, size int) string {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > size {
		t.Fatalf("document of %d bytes exceeds %d", len(b), size)
	}
	return strings.Repeat(" ", size-len(b)) + string(b)
}

// TestBodyLimits covers plan M8s decision 32: a body above 256 KiB is refused while it is read and recorded once, a
// body of exactly 256 KiB and a declarative document of exactly app.MaxDocumentBytes reach the use case, and the
// artifact uploads are not cut by the default limit.
func TestBodyLimits(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)

	r := e.do(call{method: "POST", path: "/api/v1/device-groups", cookie: alice,
		rawBody: padded(t, map[string]any{"name": "too big"}, 300<<10), skipReqCheck: true})
	if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
		t.Fatalf("300 KiB body: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "device_group.created:failure:invalid_request")

	r = e.do(call{method: "POST", path: "/api/v1/device-groups", cookie: alice,
		rawBody: padded(t, map[string]any{"name": "at the limit"}, 256<<10), skipReqCheck: true})
	if r.status != http.StatusCreated {
		t.Fatalf("256 KiB body: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "device_group.created:success:")

	doc := map[string]any{"api_version": "paddock/v1", "kind": "OrganizationConfig"}
	r = e.do(call{method: "PUT", path: "/api/v1/config?dry_run=true", cookie: alice,
		rawBody: padded(t, doc, app.MaxDocumentBytes), skipReqCheck: true})
	if r.status != http.StatusOK {
		t.Fatalf("declarative document of MaxDocumentBytes: %d %s", r.status, r.body)
	}

	root := e.platformSession()
	v := "2.0.0-limits" + uuid.NewString()[:6]
	base := "/api/platform/v1/agent-releases/" + v
	if r := e.do(call{method: "POST", path: "/api/platform/v1/agent-releases", body: map[string]string{"version": v}, cookie: root}); r.status != http.StatusCreated {
		t.Fatalf("create release: %d %s", r.status, r.body)
	}
	bin := append([]byte("\x7fELF paddockd"), bytes.Repeat([]byte{0}, 1<<20)...)
	sig := base64.StdEncoding.EncodeToString(minisign.SignWithComments(e.release, bin, releasesig.Comment(v, "amd64"), ""))
	r = e.do(call{method: "PUT", path: base + "/artifacts/amd64", rawBody: string(bin), contentType: "application/octet-stream",
		headers: map[string]string{"X-Paddock-Minisig": sig}, cookie: root})
	var art struct {
		Size int64 `json:"size"`
	}
	r.decode(t, &art)
	if r.status != http.StatusOK || art.Size != int64(len(bin)) {
		t.Fatalf("1 MiB artifact: %d %s", r.status, r.body)
	}
}

// deadlineRecorder is a response writer whose connection deadlines the handler can set, as on a real connection.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	read, write time.Time
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.read = t
	return nil
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.write = t
	return nil
}

// observedBody notes the read deadline of rec when the handler first reads the body.
type observedBody struct {
	io.Reader
	rec      *deadlineRecorder
	read     bool
	deadline time.Time
}

func (b *observedBody) Read(p []byte) (int, error) {
	if !b.read {
		b.read, b.deadline = true, b.rec.read
	}
	return b.Reader.Read(p)
}

// TestUploadDeadlines covers plan M8s decision 33: the agent release uploads extend the read and write deadlines to
// ten minutes before they read the body; other requests keep the server's timeouts.
func TestUploadDeadlines(t *testing.T) {
	e := newEnv(t)
	root := e.platformSession()
	v := "2.0.0-deadline" + uuid.NewString()[:6]
	if r := e.do(call{method: "POST", path: "/api/platform/v1/agent-releases", body: map[string]string{"version": v}, cookie: root}); r.status != http.StatusCreated {
		t.Fatalf("create release: %d %s", r.status, r.body)
	}
	bin := []byte("\x7fELF paddockd")
	deb := []byte("!<arch>\ndebian-binary")
	send := func(path string, body []byte, sig []byte) (*deadlineRecorder, *observedBody) {
		rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		ob := &observedBody{Reader: bytes.NewReader(body), rec: rec}
		req := httptest.NewRequest(http.MethodPut, "https://admin.test"+path, ob)
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-Paddock-CSRF", "1")
		if sig != nil {
			req.Header.Set("X-Paddock-Minisig", base64.StdEncoding.EncodeToString(sig))
		}
		req.AddCookie(root)
		e.handler.ServeHTTP(rec, req)
		return rec, ob
	}
	base := "/api/platform/v1/agent-releases/" + v
	for name, c := range map[string]struct {
		path string
		body []byte
		sig  []byte
	}{
		"artifact": {base + "/artifacts/amd64", bin, minisign.SignWithComments(e.release, bin, releasesig.Comment(v, "amd64"), "")},
		"package":  {base + "/packages/paddock-agent/amd64", deb, minisign.Sign(e.release, deb)},
	} {
		start := time.Now()
		rec, ob := send(c.path, c.body, c.sig)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s upload: %d %s", name, rec.Code, rec.Body)
		}
		if !ob.read || ob.deadline.Before(start.Add(9*time.Minute)) {
			t.Fatalf("%s: read deadline %v when the body was first read, want about ten minutes after %v", name, ob.deadline, start)
		}
		if rec.write.Sub(start) < 9*time.Minute || rec.write.Sub(start) > 11*time.Minute {
			t.Fatalf("%s: write deadline %v, want about ten minutes after %v", name, rec.write, start)
		}
	}

	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodGet, "https://admin.test"+base, nil)
	req.AddCookie(root)
	e.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !rec.read.IsZero() || !rec.write.IsZero() {
		t.Fatalf("other request: %d, deadlines %v %v", rec.Code, rec.read, rec.write)
	}
}
