package acceptance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

const (
	softwarePackages   = "/api/v1/software-packages"
	softwareRepository = "/api/v1/software-repository"
	// gateFakeSigningKey marks a signing key this gate set itself because no worker generated one (PDK-813 not yet
	// deployed); the gate removes it again.
	gateFakeSigningKey = "acceptance-gate-fake-key"
)

// gateDeb builds a binary package with a gzip control archive; controlName replaces control.tar.gz.
func gateDeb(pkg, version, arch, controlName string) []byte {
	control := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Paddock Gates <gates@example.invalid>\n"+
		"Description: a package of the acceptance gates\n", pkg, version, arch)
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	_ = tw.WriteHeader(&tar.Header{Name: "./control", Mode: 0o644, Size: int64(len(control)), Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte(control))
	_ = tw.Close()
	gz := func(data []byte) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		_, _ = w.Write(data)
		_ = w.Close()
		return b.Bytes()
	}
	var out bytes.Buffer
	out.WriteString("!<arch>\n")
	for _, m := range []struct {
		name string
		data []byte
	}{{"debian-binary", []byte("2.0\n")}, {controlName, gz(tb.Bytes())}, {"data.tar.gz", gz(nil)}} {
		fmt.Fprintf(&out, "%-16s%-12s%-6s%-6s%-8s%-10d`\n", m.name, "0", "0", "0", "100644", len(m.data))
		out.Write(m.data)
		if len(m.data)%2 == 1 {
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}

// uploadStoredPackage posts deb as the multipart form of POST /api/v1/software-packages with the optional fields.
func uploadStoredPackage(t *testing.T, p *env.Portal, deb []byte, fields map[string]string) env.Response {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("file", "package.deb")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(deb)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	_ = w.Close()
	req, err := http.NewRequestWithContext(testContext(t, time.Minute), http.MethodPost, stack.AdminURL()+softwarePackages, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("X-Paddock-CSRF", "1")
	resp, err := p.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return env.Response{Status: resp.StatusCode, Header: resp.Header, Body: data, RequestID: resp.Header.Get("X-Request-Id")}
}

// aptAnswer is the status and headers of a repository request; the body is read and closed.
type aptAnswer struct {
	StatusCode int
	Header     http.Header
}

// aptGet requests a repository path as apt does, with basic auth when secret is set, without following redirects.
func aptGet(t *testing.T, hc *http.Client, url, secret string) aptAnswer {
	t.Helper()
	req, err := http.NewRequestWithContext(testContext(t, time.Minute), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" {
		req.SetBasicAuth("paddock", secret)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return aptAnswer{StatusCode: resp.StatusCode, Header: resp.Header}
}

type gateRepository struct {
	State       string  `json:"state"`
	URL         string  `json:"url"`
	Fingerprint *string `json:"fingerprint"`
	Generation  int64   `json:"generation"`
	Source      any     `json:"source"`
}

func getRepository(t *testing.T, p *env.Portal) gateRepository {
	t.Helper()
	res := call(t, p, http.MethodGet, softwareRepository, nil)
	expectStatus(t, res, http.StatusOK, "")
	var r gateRepository
	if err := res.JSON(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestSoftwarePackages is the gate of PDK-812 (plan M13c decisions 11, 12 and 14, §3.8 L6, L7 and L9; ADR 0050;
// architect decision A10-21): the first visit creates the repository, uploads wait for its signing key
// (repository_not_ready, nothing published), an upload needs org_admin with a step-up, a gzip control archive is
// stored with its control fields and audited with its SHA-256, an xz control archive is 415 unsupported_compression,
// a mismatching Package 400 and a duplicate 409; on the bundles host apt gets 401 without the credential, 302 to a
// presigned GET with it, also with the previous credential after a rotation, and 429 beyond 60 requests a minute from
// one address.
func TestSoftwarePackages(t *testing.T) {
	alice := login(t, env.Alice)
	admin := adminUser(t, "sw-pkg")
	s := adminStepper(admin)
	org := orgOf(t, alice)
	hc, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	repo := getRepository(t, alice)
	if !strings.HasPrefix(repo.URL, stack.BundlesURL()+"/apt/") || !strings.HasSuffix(repo.URL, "/") {
		t.Fatalf("repository url %q", repo.URL)
	}
	if repo.Fingerprint == nil {
		if repo.State != "disabled" || repo.Source != nil {
			t.Fatalf("repository without a key: %+v", repo)
		}
		s.stepUp(t)
		expectRefusal(t, alice, uploadStoredPackage(t, admin.Portal, gateDeb("gate-pkg-"+uniqueSuffix(), "1.0", "amd64", "control.tar.gz"), nil),
			http.StatusConflict, "repository_not_ready", "software_package.uploaded")
		s.stepUp(t)
		res := call(t, admin.Portal, http.MethodPost, softwareRepository+"/rotate-credential", nil)
		expectStatus(t, res, http.StatusOK, "")
		var cred struct{ Secret string }
		if err := res.JSON(&cred); err != nil {
			t.Fatal(err)
		}
		if resp := aptGet(t, hc, repo.URL+"dists/paddock/InRelease", cred.Secret); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("InRelease without a signing key: HTTP %d, want 404", resp.StatusCode)
		}
		repo = awaitSigningKey(t, alice, org)
	}

	t.Run("upload", func(t *testing.T) {
		pkg := "gate-pkg-" + uniqueSuffix()
		deb := gateDeb(pkg, "1.0-1", "amd64", "control.tar.gz")
		token := tokenPortal(t, createAPIToken(t, login(t, env.Alice), env.Alice, "org_admin").Secret)
		expectRefusal(t, alice, uploadStoredPackage(t, token, deb, nil), http.StatusForbidden, "step_up_required", "software_package.uploaded")
		expectRefusal(t, alice, uploadStoredPackage(t, withoutStepUp(t, admin), deb, nil), http.StatusForbidden, "step_up_required",
			"software_package.uploaded")

		s.stepUp(t)
		res := uploadStoredPackage(t, admin.Portal, deb, map[string]string{"package": "other"})
		expectStatus(t, res, http.StatusBadRequest, "invalid_request")
		expectOneEvent(t, alice, res.RequestID, "software_package.uploaded", "failure")
		res = uploadStoredPackage(t, admin.Portal, gateDeb(pkg, "1.0-1", "amd64", "control.tar.xz"), nil)
		expectStatus(t, res, http.StatusUnsupportedMediaType, "unsupported_compression")

		res = uploadStoredPackage(t, admin.Portal, deb, map[string]string{"package": pkg, "version": "1.0-1", "architecture": "amd64"})
		expectStatus(t, res, http.StatusCreated, "")
		var stored struct {
			ID       string            `json:"id"`
			Sha256   string            `json:"sha256"`
			Filename string            `json:"filename"`
			Control  map[string]string `json:"control"`
		}
		if err := res.JSON(&stored); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			s.stepUp(t)
			call(t, admin.Portal, http.MethodDelete, softwarePackages+"/"+stored.ID, nil)
		})
		sum := sha256.Sum256(deb)
		if stored.Sha256 != hex.EncodeToString(sum[:]) || stored.Control["Package"] != pkg ||
			stored.Filename != "pool/main/g/"+pkg+"/"+pkg+"_1.0-1_amd64.deb" {
			t.Fatalf("stored %s", res.Body)
		}
		if ev := expectOneEvent(t, alice, res.RequestID, "software_package.uploaded", "success"); ev.Params["sha256"] != stored.Sha256 {
			t.Fatalf("uploaded event params %v", ev.Params)
		}
		res = uploadStoredPackage(t, admin.Portal, deb, nil)
		expectStatus(t, res, http.StatusConflict, "already_exists")

		t.Run("apt access", func(t *testing.T) {
			s.stepUp(t)
			res := call(t, admin.Portal, http.MethodPost, softwareRepository+"/rotate-credential", nil)
			expectStatus(t, res, http.StatusOK, "")
			var first struct{ Secret string }
			_ = res.JSON(&first)
			s.stepUp(t)
			res = call(t, admin.Portal, http.MethodPost, softwareRepository+"/rotate-credential", nil)
			expectStatus(t, res, http.StatusOK, "")
			var second struct{ Secret string }
			_ = res.JSON(&second)
			if ev := expectOneEvent(t, alice, res.RequestID, "software_repository.credential_rotated", "success"); strings.Contains(
				fmt.Sprint(ev.Params), second.Secret) {
				t.Fatal("the secret is in the audit event")
			}

			url := repo.URL + stored.Filename
			resp := aptGet(t, hc, url, "")
			if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != `Basic realm="paddock"` {
				t.Fatalf("without credential: HTTP %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
			}
			if resp := aptGet(t, hc, url, "wrong"); resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("wrong credential: HTTP %d", resp.StatusCode)
			}
			for name, secret := range map[string]string{"current": second.Secret, "previous": first.Secret} {
				resp := aptGet(t, hc, url, secret)
				loc := resp.Header.Get("Location")
				if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, stack.BundlesURL()+"/paddock-bundles/apt/"+org.String()+"/") {
					t.Fatalf("%s credential: HTTP %d Location %q", name, resp.StatusCode, loc)
				}
				got := aptGet(t, hc, loc, "")
				if got.StatusCode != http.StatusOK {
					t.Fatalf("presigned GET: HTTP %d", got.StatusCode)
				}
			}
			if resp := aptGet(t, hc, repo.URL+"pool/main/g/none/none_1_amd64.deb", second.Secret); resp.StatusCode != http.StatusNotFound {
				t.Fatalf("unknown path: HTTP %d", resp.StatusCode)
			}
		})
	})

	t.Run("rate limit per address", func(t *testing.T) {
		limited, err := env.HeaderClient(map[string]string{"X-Forwarded-For": docPrefix(t) + "::1"})
		if err != nil {
			t.Fatal(err)
		}
		limited.CheckRedirect = hc.CheckRedirect
		awayFromWindowEdge()
		for i := 1; i <= 61; i++ {
			resp := aptGet(t, limited, repo.URL+"dists/paddock/InRelease", "")
			if i <= 60 && resp.StatusCode == http.StatusTooManyRequests {
				t.Fatalf("request %d refused", i)
			}
			if i == 61 && resp.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("request 61: HTTP %d, want 429", resp.StatusCode)
			}
		}
	})
}

// awaitSigningKey waits for the worker to generate the repository's signing key (PDK-813). Without that worker the
// gate sets a placeholder key, which it removes again, so that the upload and access cases still run.
func awaitSigningKey(t *testing.T, p *env.Portal, org fmt.Stringer) gateRepository {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if r := getRepository(t, p); r.Fingerprint != nil {
			return r
		}
		time.Sleep(3 * time.Second)
	}
	dsn, err := stack.PaddockOwnerDSN()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(testContext(t, time.Minute), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(testContext(t, time.Minute), `UPDATE software_repository SET signing_public_key = $2,
		signing_fingerprint = $3, signing_private_ciphertext = $2 WHERE organization_id = $1 AND signing_fingerprint IS NULL`,
		org.String(), gateFakeSigningKey, strings.Repeat("0A", 20)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close(context.Background()) }()
		if _, err := conn.Exec(context.Background(), `UPDATE software_repository SET signing_public_key = NULL,
			signing_fingerprint = NULL, signing_private_ciphertext = NULL WHERE organization_id = $1 AND signing_private_ciphertext = $2`,
			org.String(), gateFakeSigningKey); err != nil {
			t.Error(err)
		}
	})
	return getRepository(t, p)
}
