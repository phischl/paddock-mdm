package acceptance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/openpgpkey"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

const (
	softwarePackages   = "/api/v1/software-packages"
	softwareRepository = "/api/v1/software-repository"
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
	State               string  `json:"state"`
	URL                 string  `json:"url"`
	Fingerprint         *string `json:"fingerprint"`
	PreviousFingerprint *string `json:"previous_fingerprint"`
	Generation          int64   `json:"generation"`
	Source              any     `json:"source"`
}

// sourceID is the ID of the repository's system source.
func (r gateRepository) sourceID(t *testing.T) string {
	t.Helper()
	src, _ := r.Source.(map[string]any)
	id, _ := src["id"].(string)
	if id == "" {
		t.Fatalf("repository without a system source: %+v", r)
	}
	return id
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
		repo = awaitSigningKey(t, alice)
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

		// PDK-813 (plan M13c decision 13, §3.8 L5; ADR 0050 decision 3): the upload is published within a round, signed
		// with the key of the system source; a key rotation re-signs before the devices receive the new key, so a device
		// whose bundle carries the new keyring finds InRelease signed with it and its keyring matches its fingerprint
		// (never software.apply_failed fingerprint_mismatch); the old key stays as previous_fingerprint and signs InRelease
		// too for 30 days, so a device that has not received the new key yet keeps verifying it.
		t.Run("signing key rotation", func(t *testing.T) {
			s.stepUp(t)
			res := call(t, admin.Portal, http.MethodPost, softwareRepository+"/rotate-credential", nil)
			expectStatus(t, res, http.StatusOK, "")
			var cred struct{ Secret string }
			if err := res.JSON(&cred); err != nil {
				t.Fatal(err)
			}
			awaitRepository(t, alice, func(r gateRepository) bool { return r.State == "built" })
			list := string(aptFetch(t, hc, repo.URL+"dists/paddock/main/binary-amd64/Packages", cred.Secret))
			if !strings.Contains(list, "Package: "+pkg+"\n") || !strings.Contains(list, "SHA256: "+stored.Sha256+"\n") ||
				!strings.Contains(list, "Filename: "+stored.Filename+"\n") {
				t.Fatalf("the uploaded package is not in the published list:\n%s", list)
			}
			sourceKey := func(fingerprint string) string {
				t.Helper()
				res := call(t, alice, http.MethodGet, softwareSources+"/"+getRepository(t, alice).sourceID(t), nil)
				expectStatus(t, res, http.StatusOK, "")
				var got struct {
					Kind        string `json:"kind"`
					SigningKey  string `json:"signing_key"`
					Fingerprint string `json:"fingerprint"`
				}
				if err := res.JSON(&got); err != nil {
					t.Fatal(err)
				}
				if got.Kind != "paddock" || got.Fingerprint != fingerprint {
					t.Fatalf("system source %s %s, want paddock %s", got.Kind, got.Fingerprint, fingerprint)
				}
				return got.SigningKey
			}
			before := getRepository(t, alice)
			oldKey := sourceKey(*before.Fingerprint)
			if err := verifyInRelease(t, aptFetch(t, hc, repo.URL+"dists/paddock/InRelease", cred.Secret), oldKey); err != nil {
				t.Fatalf("InRelease does not verify with the source's key: %v", err)
			}

			// The device that receives the new bundle: its software section names the system source.
			group := namedGroup(t, alice, "sw-repo-key")
			d := activeDevice(t, alice, group, "sw-repo-key-"+uniqueSuffix())
			d.SchemaVersions = []int{bundle.SchemaVersion, bundle.SchemaVersion2}
			entry := gateEntry(t, admin.Portal, before.sourceID(t), packageRef("ubuntu", "*", pkg))
			res = call(t, admin.Portal, http.MethodPost, softwareAssignments, map[string]any{
				"catalog_entry_id": entry, "device_group_id": group, "intent": "required",
			})
			expectStatus(t, res, http.StatusCreated, "")
			deleteOnCleanup(t, admin.Portal, softwareAssignments+"/"+responseID(t, res).String())
			paddockSource := func(b *bundle.Bundle) *bundle.SoftwareSource {
				if b.Software == nil {
					return nil
				}
				for i, src := range b.Software.Sources {
					if src.Slug == "paddock" {
						return &b.Software.Sources[i]
					}
				}
				return nil
			}
			latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool {
				src := paddockSource(b)
				return src != nil && src.Fingerprint == *before.Fingerprint
			})

			expectRefusal(t, alice, call(t, withoutStepUp(t, admin), http.MethodPost, softwareRepository+"/rotate-key", nil),
				http.StatusForbidden, "step_up_required", "software_repository.key_rotated")
			s.stepUp(t)
			res = call(t, admin.Portal, http.MethodPost, softwareRepository+"/rotate-key", nil)
			expectStatus(t, res, http.StatusAccepted, "")
			if ev := expectOneEvent(t, alice, res.RequestID, "software_repository.key_rotated", "success"); ev.Params["previous_fingerprint"] != *before.Fingerprint {
				t.Fatalf("key_rotated params %v", ev.Params)
			}
			after := awaitRepository(t, alice, func(r gateRepository) bool {
				return r.Fingerprint != nil && *r.Fingerprint != *before.Fingerprint && r.State == "built"
			})
			if after.PreviousFingerprint == nil || *after.PreviousFingerprint != *before.Fingerprint {
				t.Fatalf("previous_fingerprint %v, want %s", after.PreviousFingerprint, *before.Fingerprint)
			}
			newKey := sourceKey(*after.Fingerprint)
			b := latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool {
				src := paddockSource(b)
				return src != nil && src.Fingerprint == *after.Fingerprint
			})
			keyring, err := base64.StdEncoding.DecodeString(paddockSource(b).Keyring)
			if err != nil {
				t.Fatal(err)
			}
			if fp, err := openpgpkey.FingerprintBinary(keyring); err != nil || fp != *after.Fingerprint {
				t.Fatalf("the bundle's keyring has the fingerprint %s (%v), want %s: the agent would report fingerprint_mismatch",
					fp, err, *after.Fingerprint)
			}
			inRelease := aptFetch(t, hc, repo.URL+"dists/paddock/InRelease", cred.Secret)
			if err := verifyInRelease(t, inRelease, newKey); err != nil {
				t.Fatalf("a device with the new bundle cannot verify InRelease: %v", err)
			}
			if err := verifyInRelease(t, inRelease, oldKey); err != nil {
				t.Fatalf("during the 30-day overlap a device that still has the old key cannot verify InRelease: %v", err)
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

// awaitSigningKey waits for the worker to generate the repository's signing key and publish the first build (PDK-813).
func awaitSigningKey(t *testing.T, p *env.Portal) gateRepository {
	t.Helper()
	return awaitRepository(t, p, func(r gateRepository) bool { return r.Fingerprint != nil && r.Generation > 0 })
}

// awaitRepository polls the repository until cond holds; the worker's round runs every 60 s.
func awaitRepository(t *testing.T, p *env.Portal, cond func(gateRepository) bool) gateRepository {
	t.Helper()
	deadline := time.Now().Add(150 * time.Second)
	for {
		r := getRepository(t, p)
		if cond(r) {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("repository %+v: the worker did not build in time", r)
		}
		time.Sleep(3 * time.Second)
	}
}

// aptFetch reads a repository file as apt does: basic auth on the bundles host, then the presigned redirect.
func aptFetch(t *testing.T, hc *http.Client, url, secret string) []byte {
	t.Helper()
	resp := aptGet(t, hc, url, secret)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET %s: HTTP %d, want 302", url, resp.StatusCode)
	}
	req, err := http.NewRequestWithContext(testContext(t, time.Minute), http.MethodGet, resp.Header.Get("Location"), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = got.Body.Close() }()
	body, err := io.ReadAll(got.Body)
	if err != nil || got.StatusCode != http.StatusOK {
		t.Fatalf("presigned GET of %s: HTTP %d (%v)", url, got.StatusCode, err)
	}
	return body
}

// verifyInRelease checks the clearsigned InRelease with the ASCII-armored public key, as apt does with Signed-By.
func verifyInRelease(t *testing.T, inRelease []byte, publicKey string) error {
	t.Helper()
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := clearsign.Decode(inRelease)
	if block == nil {
		t.Fatalf("InRelease is not clearsigned:\n%s", inRelease)
	}
	_, err = block.VerifySignature(keyring, nil)
	return err
}
