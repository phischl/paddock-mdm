package admin_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
)

type unusedRepoKeys struct{}

func (unusedRepoKeys) Encrypt(context.Context, string, uuid.UUID, bao.ContextField, []byte) (string, error) {
	return "vault:v1:x", nil
}

type unusedPackageStore struct{}

func (unusedPackageStore) PutReader(context.Context, string, io.ReadSeeker, int64) error {
	return errors.New("not expected")
}
func (unusedPackageStore) Delete(context.Context, string) error { return errors.New("not expected") }
func (unusedPackageStore) Size(context.Context, string) (int64, bool, error) {
	return 0, false, errors.New("not expected")
}

type unusedPresigner struct{}

func (unusedPresigner) PresignGet(context.Context, string, time.Duration) (string, error) {
	return "", errors.New("not expected")
}

// countingBody counts the bytes read from it.
type countingBody struct {
	r    io.Reader
	read int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.read += int64(n)
	return n, err
}

// preambleLine is a line of a multipart preamble, which the reader skips.
var preambleLine = []byte(strings.Repeat("x", 1022) + "\n")

// preamble repeats preambleLine endlessly without holding more than one line in memory.
type preamble struct{ pos int }

func (r *preamble) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = preambleLine[r.pos]
		r.pos = (r.pos + 1) % len(preambleLine)
	}
	return len(p), nil
}

// TestUploadSoftwarePackageRefusals (plan M13c decision 12; root CLAUDE.md, Audit): a caller without the role or the
// step-up is refused before the body is read, and a form that cannot be read (unknown field, a body above the
// limit) is refused; each attempt leaves exactly one audit event.
func TestUploadSoftwarePackageRefusals(t *testing.T) {
	e := newEnvWith(t, func(d *admin.Deps) {
		pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		d.SoftwarePackages = app.NewSoftwarePackages(d.Runner, pool, unusedRepoKeys{}, unusedPackageStore{}, unusedPresigner{},
			"https://bundles.test")
	})
	orgAdmin := e.session(e.acme, principal.RoleOrgAdmin)
	steppedUp := e.steppedUp(orgAdmin, time.Now())
	auditor := e.session(e.acme, principal.RoleOrgAuditor)

	form := func(fields map[string]string) (string, string) {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		part, _ := w.CreateFormFile("file", "x.deb")
		_, _ = part.Write([]byte("!<arch>\n"))
		for k, v := range fields {
			_ = w.WriteField(k, v)
		}
		_ = w.Close()
		return b.String(), w.FormDataContentType()
	}
	upload := func(cookie *http.Cookie, body io.Reader, contentType string) (int, string, string) {
		req := httptest.NewRequest(http.MethodPost, "https://admin.test/api/v1/software-packages", body)
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("X-Paddock-CSRF", "1")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		e.handler.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String(), rec.Header().Get(httpx.HeaderRequestID)
	}

	valid, contentType := form(nil)
	for name, c := range map[string]struct {
		cookie *http.Cookie
		event  string
	}{
		"auditor":            {auditor, "software_package.uploaded:denied:forbidden"},
		"admin without step": {orgAdmin, "software_package.uploaded:denied:step_up_required"},
	} {
		body := &countingBody{r: strings.NewReader(valid)}
		status, out, id := upload(c.cookie, body, contentType)
		if status != http.StatusForbidden || body.read != 0 {
			t.Errorf("%s: HTTP %d %s, %d bytes read", name, status, out, body.read)
		}
		e.expectEvent(result{header: http.Header{httpx.HeaderRequestID: {id}}}, c.event)
	}

	unknown, contentType := form(map[string]string{"note": "x"})
	status, out, id := upload(steppedUp, strings.NewReader(unknown), contentType)
	if status != http.StatusBadRequest || !strings.Contains(out, "unknown form field") {
		t.Fatalf("unknown field: HTTP %d %s", status, out)
	}
	e.expectEvent(result{header: http.Header{httpx.HeaderRequestID: {id}}}, "software_package.uploaded:failure:invalid_request")

	pre := io.LimitReader(&preamble{}, int64(len(preambleLine))*((software.MaxPackageBytes+1<<20)/int64(len(preambleLine))))
	status, out, id = upload(steppedUp, io.MultiReader(pre, strings.NewReader(valid)), contentType)
	if status != http.StatusBadRequest || !strings.Contains(out, "the request body exceeds") {
		t.Fatalf("oversize body: HTTP %d %s", status, out)
	}
	e.expectEvent(result{header: http.Header{httpx.HeaderRequestID: {id}}}, "software_package.uploaded:failure:invalid_request")
}
