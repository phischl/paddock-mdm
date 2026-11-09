package compiler_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/compiler"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
)

// fakeCredentials plays Transit for the repository credential: it decrypts what names the organization and field.
type fakeCredentials struct{ err error }

func (f fakeCredentials) DecryptContext(_ context.Context, key string, org uuid.UUID, field bao.ContextField, ciphertext string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	prefix := "ct:" + key + ":" + org.String() + ":" + string(field) + ":"
	secret, ok := strings.CutPrefix(ciphertext, prefix)
	if !ok {
		return nil, errors.New("bound to another context")
	}
	return []byte(secret), nil
}

const repoSecret = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCd"

// paddockRepository inserts the organization's repository with its credential and its system source (the worker's,
// PDK-813), and an entry of that source assigned to group.
func (w *world) paddockRepository(k softwareKey, group uuid.UUID) {
	w.t.Helper()
	w.exec(`INSERT INTO software_repository (organization_id, signing_public_key, signing_fingerprint, signing_private_ciphertext,
		credential_ciphertext, credential_sha256) VALUES ($1, $2, $3, 'x', $4, decode(repeat('00', 32), 'hex'))`,
		w.org, k.armored, k.fingerprint, "ct:software-repo-credential:"+w.org.String()+":repository_credential:"+repoSecret)
	src := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO software_source (id, organization_id, kind, slug, name, uris, suites, components, signing_key, fingerprint)
		VALUES ($1, $2, 'paddock', 'paddock', 'Paddock', '{https://bundles.example.com:8443/apt/acme/}', '{paddock}', '{main}', $3, $4)`,
		src, w.org, k.armored, k.fingerprint)
	e := w.entry("Acme tool", src, [4]string{"ubuntu", "*", "*", "acme-tool"})
	w.assign(e, group, "required", "latest", nil)
}

// TestSoftwarePaddockRepository (plan M13c decision 15): a device whose section names the Paddock repository gets its
// source like an APT source and the read credential for its host and path; a device without a package from it gets no
// credential, and without a decryptable credential the source is left out, never rendered without one.
func TestSoftwarePaddockRepository(t *testing.T) {
	key := loadSoftwareKey(t, "ed25519.asc")
	w := newWorldConfig(t, func(c *compiler.Config) { c.Credentials = fakeCredentials{} })
	w.paddockRepository(key, w.g1)
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	other := w.v2Device("{1,2}", w.g2)
	w.ubuntu(other, "amd64")
	nano := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
	w.assign(nano, w.g2, "required", "latest", nil)
	w.mustCompile(statechange.ScopeOrg, w.org)

	s := w.fetch(d).Software
	if s == nil || len(s.Sources) != 1 || s.Sources[0].Slug != "paddock" || s.Sources[0].Kind != "" || s.Sources[0].Fingerprint != key.fingerprint {
		t.Fatalf("section %+v", s)
	}
	if r := s.Repository; r == nil || r.Host != "bundles.example.com:8443/apt/acme/" || r.Username != "paddock" || r.Password != repoSecret {
		t.Fatalf("repository credential %+v", s.Repository)
	}
	if s := w.fetch(other).Software; s == nil || s.Repository != nil {
		t.Fatalf("a device without the Paddock source got the credential: %+v", s)
	}

	failing := newWorldConfig(t, func(c *compiler.Config) { c.Credentials = fakeCredentials{err: errors.New("sealed")} })
	failing.paddockRepository(key, failing.g1)
	fd := failing.v2Device("{1,2}", failing.g1)
	failing.ubuntu(fd, "amd64")
	failing.mustCompile(statechange.ScopeOrg, failing.org)
	if s := failing.fetch(fd).Software; s != nil && (len(s.Sources) != 0 || s.Repository != nil) {
		t.Fatalf("source without its credential rendered: %+v", s)
	}
}
