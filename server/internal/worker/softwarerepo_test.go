package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/openpgpkey"
	"github.com/phischl/paddock-mdm/server/internal/adapters/aptsign"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// fakeVault plays Transit for software-repo-wrap: a ciphertext names the key, organization and field it is bound to.
// It keeps every plaintext it handed out or received, so the test can see that the build zeroed them.
type fakeVault struct {
	mu          sync.Mutex
	failDecrypt bool
	plaintexts  [][]byte
}

func (v *fakeVault) Encrypt(_ context.Context, key string, org uuid.UUID, field bao.ContextField, plaintext []byte) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.plaintexts = append(v.plaintexts, plaintext)
	return "vault:v1:" + key + ":" + org.String() + ":" + string(field) + ":" + base64.StdEncoding.EncodeToString(plaintext), nil
}

func (v *fakeVault) DecryptContext(_ context.Context, key string, org uuid.UUID, field bao.ContextField, ciphertext string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.failDecrypt {
		return nil, errors.New("bao: decrypt: Vault is sealed")
	}
	prefix := "vault:v1:" + key + ":" + org.String() + ":" + string(field) + ":"
	if !strings.HasPrefix(ciphertext, prefix) {
		return nil, errors.New("bao: decrypt: wrong key, organization or field")
	}
	out, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ciphertext, prefix))
	v.plaintexts = append(v.plaintexts, out)
	return out, err
}

// fakeIndexStore is the bundles bucket; onPut runs before each write and fails it with its error.
type fakeIndexStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	order   []string
	onPut   func(key string) error
}

func (s *fakeIndexStore) PutReader(_ context.Context, key string, body io.ReadSeeker, _ int64) error {
	if s.onPut != nil {
		if err := s.onPut(key); err != nil {
			return err
		}
	}
	data, err := io.ReadAll(body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key], s.order = data, append(s.order, key)
	return err
}

// s3Error is an object-store error as the AWS SDK returns it: an API error code and an HTTP status, and a message with
// a request ID that differs on every request.
type s3Error struct {
	requestID string
}

func (e *s3Error) Error() string {
	return "operation error S3: PutObject, https response error StatusCode: 403, RequestID: " + e.requestID +
		", HostID: " + e.requestID + ", api error AccessDenied: Access Denied"
}

func (e *s3Error) ErrorCode() string { return "AccessDenied" }

func (e *s3Error) HTTPStatusCode() int { return 403 }

// TestSoftwareRepositoryBuild (plan M13c decision 13, §3.7, §3.8 L5 and L8; ADR 0050 decision 3), as the worker's
// database role: the first build generates the key, publishes the index (InRelease last) signed with it and creates the
// system source; a failed build keeps the previous InRelease and is recorded once, also when the object store's
// errors differ only in their request ID, and one that fails after overwriting a list leaves the previous generation
// readable by hash; a rotation signs with the new key before the source carries it and signs with both keys for 30
// days from its publication, then with the new key alone; a rotation retried after a failed build keeps the published
// key; the private key is zeroed and never logged.
func TestSoftwareRepositoryBuild(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	vault := &fakeVault{}
	store := &fakeIndexStore{objects: map[string][]byte{}}
	now := time.Now().Add(-time.Minute).Truncate(time.Second)
	builds := app.NewSoftwareRepositoryBuilds(app.NewActionRunner(f.pool, platform, httpx.RequestID), f.pool, vault,
		aptsign.Signer{}, store, "https://bundles.example.com/").WithClock(func() time.Time { return now })
	octx := systemContext(ctx, f.org, "software-repository-test")
	build := func() error {
		err := builds.Build(octx)
		if err != nil {
			slog.WarnContext(ctx, "software repository round failed; retrying next round", "error", err)
		}
		return err
	}
	var slug string
	if err := f.super.QueryRow(ctx, "SELECT slug FROM organization WHERE id = $1", f.org).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	if err := build(); err != nil {
		t.Fatalf("an organization without a repository: %v", err)
	}
	if _, err := f.super.Exec(ctx, `INSERT INTO software_repository (organization_id, credential_ciphertext, credential_sha256,
		rebuild_requested_at) VALUES ($1, 'vault:v1:c', $2, now())`, f.org, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct{ name, arch string }{{"acme-tool", "amd64"}, {"acme-docs", "all"}} {
		sum := sha256.Sum256([]byte(p.name))
		if _, err := f.super.Exec(ctx, `INSERT INTO software_package (id, organization_id, package, version, architecture,
			size, sha256, object_key, control, uploaded_by) VALUES ($1, $2, $3, '1.0', $4, 10, $5, $6, $7, 'a')`,
			uuid.Must(uuid.NewV7()), f.org, p.name, p.arch, hex.EncodeToString(sum[:]), "apt/"+p.name,
			`{"Package":"`+p.name+`","Description":"tool\n more"}`); err != nil {
			t.Fatal(err)
		}
	}
	dists := "apt/" + f.org.String() + "/dists/paddock/"
	type repoRow struct {
		fingerprint, publicKey, ciphertext string
		previous, previousCiphertext       *string
		lastError                          *string
		retired, requested                 *time.Time
		generation                         int64
		source, sourceKey, sourceURI       string
	}
	read := func() repoRow {
		t.Helper()
		var r repoRow
		var fp, pub, ct *string
		if err := f.super.QueryRow(ctx, `SELECT signing_fingerprint, signing_public_key, signing_private_ciphertext,
			previous_fingerprint, previous_private_ciphertext, previous_retired_at, last_error, rebuild_requested_at, generation
			FROM software_repository WHERE organization_id = $1`, f.org).Scan(&fp, &pub, &ct, &r.previous,
			&r.previousCiphertext, &r.retired, &r.lastError, &r.requested, &r.generation); err != nil {
			t.Fatal(err)
		}
		if fp != nil {
			r.fingerprint, r.publicKey, r.ciphertext = *fp, *pub, *ct
		}
		_ = f.super.QueryRow(ctx, `SELECT fingerprint, signing_key, uris[1] FROM software_source WHERE organization_id = $1
			AND kind = 'paddock'`, f.org).Scan(&r.source, &r.sourceKey, &r.sourceURI)
		return r
	}
	verify := func(publicKey string) error {
		keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(publicKey))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := clearsign.Decode(store.objects[dists+"InRelease"])
		if block == nil {
			t.Fatal("InRelease is not clearsigned")
		}
		if !bytes.Equal(bytes.TrimSuffix(store.objects[dists+"Release"], []byte("\n")), block.Plaintext) {
			t.Fatal("InRelease does not sign the published Release")
		}
		if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(store.objects[dists+"Release"]),
			bytes.NewReader(store.objects[dists+"Release.gpg"]), nil); err != nil {
			return err
		}
		_, err = block.VerifySignature(keyring, nil)
		return err
	}
	// gpgvVerifies checks the published InRelease with gpgv, the verifier apt uses, independent of the library that
	// signed it: a valid signature of publicKey and no bad one is what apt accepts. Its checks are left out where gpgv is
	// not installed.
	gpgv, _ := exec.LookPath("gpgv")
	gpgvVerifies := func(publicKey string) bool {
		t.Helper()
		parsed, err := openpgpkey.ParseArmored([]byte(publicKey))
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		ring, in := filepath.Join(dir, "paddock.gpg"), filepath.Join(dir, "InRelease")
		if err := os.WriteFile(ring, parsed.Keyring, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(in, store.objects[dists+"InRelease"], 0o600); err != nil {
			t.Fatal(err)
		}
		status, _ := exec.Command(gpgv, "--homedir", dir, "--keyring", ring, "--status-fd", "1", in).Output()
		return strings.Contains(string(status), "[GNUPG:] VALIDSIG "+parsed.Fingerprint) &&
			!strings.Contains(string(status), "[GNUPG:] BADSIG")
	}
	events := func(code string) int {
		return f.count(t, "SELECT count(*) FROM action WHERE organization_id = $1 AND code = $2", f.org, code)
	}

	// First build: the key, the index, the source (A10-21: nothing is published before the key exists).
	if err := build(); err != nil {
		t.Fatal(err)
	}
	first := read()
	if fp, err := openpgpkey.ParseArmored([]byte(first.publicKey)); err != nil || fp.Fingerprint != first.fingerprint {
		t.Fatalf("stored fingerprint %s, the stored key reads %v (%v)", first.fingerprint, fp, err)
	}
	if !strings.HasPrefix(first.ciphertext, "vault:v1:"+app.SoftwareRepoWrapKey+":"+f.org.String()+":repository_signing_key:") {
		t.Fatalf("private key ciphertext %.60s…", first.ciphertext)
	}
	if first.generation != 1 || first.requested != nil || first.lastError != nil || first.source != first.fingerprint ||
		first.sourceKey != first.publicKey || first.sourceURI != "https://bundles.example.com/apt/"+slug+"/" {
		t.Fatalf("after the first build %+v", first)
	}
	if err := verify(first.publicKey); err != nil {
		t.Fatalf("InRelease does not verify with the stored key: %v", err)
	}
	if got := store.order[len(store.order)-1]; got != dists+"InRelease" || !slices.Contains(store.order[:len(store.order)-1], dists+"Release") {
		t.Fatalf("write order %v, want InRelease last", store.order)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		list := string(store.objects[dists+"main/binary-"+arch+"/Packages"])
		if !strings.Contains(list, "Package: acme-docs\n") || strings.Contains(list, "acme-tool") != (arch == "amd64") {
			t.Fatalf("%s list:\n%s", arch, list)
		}
	}
	if n := events("software_repository.built"); n != 1 {
		t.Fatalf("%d built events, want 1", n)
	}
	var params string
	if err := f.super.QueryRow(ctx, `SELECT params::text FROM action WHERE organization_id = $1 AND code = 'software_repository.built'`,
		f.org).Scan(&params); err != nil || !strings.Contains(params, first.fingerprint) || !strings.Contains(params, `"key_generated": true`) {
		t.Fatalf("built params %s (%v)", params, err)
	}
	if n := f.count(t, `SELECT count(*) FROM outbox WHERE payload ->> 'scope' = 'org' AND payload ->> 'id' = $1`, f.org.String()); n < 1 {
		t.Fatal("the new source did not change the organization's bundles")
	}

	// Nothing due: nothing is written.
	writes := len(store.order)
	if err := build(); err != nil || len(store.order) != writes || read().generation != 1 {
		t.Fatalf("an idle round wrote %d files (%v)", len(store.order)-writes, err)
	}

	// L8: OpenBao sealed. The previous InRelease stays, the failure is recorded once and retried.
	published := bytes.Clone(store.objects[dists+"InRelease"])
	if _, err := f.super.Exec(ctx, "UPDATE software_repository SET rebuild_requested_at = now() WHERE organization_id = $1", f.org); err != nil {
		t.Fatal(err)
	}
	vault.failDecrypt = true
	for range 2 {
		if err := build(); err == nil {
			t.Fatal("a build without the key succeeded")
		}
	}
	if failed := read(); failed.lastError == nil || !strings.Contains(*failed.lastError, "sealed") || failed.generation != 1 ||
		!bytes.Equal(store.objects[dists+"InRelease"], published) {
		t.Fatalf("after a failed build %+v", failed)
	}
	if n := events("software_repository.build_failed"); n != 1 {
		t.Fatalf("%d build_failed events over two failed rounds, want 1", n)
	}
	vault.failDecrypt = false
	if err := build(); err != nil {
		t.Fatal(err)
	}
	if r := read(); r.lastError != nil || r.generation != 2 || r.fingerprint != first.fingerprint {
		t.Fatalf("after the retry %+v", r)
	}

	// §3.7: the object store refuses a write after the amd64 Packages list was overwritten. Its errors differ only in
	// the request ID: the failure is recorded once, as its step and class. The previous InRelease stays, and apt reads
	// the lists it names by their hash, while Packages at its name is already the next build's.
	published = bytes.Clone(store.objects[dists+"InRelease"])
	sum := sha256.Sum256([]byte("acme-new"))
	if _, err := f.super.Exec(ctx, `INSERT INTO software_package (id, organization_id, package, version, architecture,
		size, sha256, object_key, control, uploaded_by) VALUES ($1, $2, 'acme-new', '1.0', 'amd64', 10, $3, 'apt/acme-new',
		'{"Package":"acme-new"}', 'a')`, uuid.Must(uuid.NewV7()), f.org, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if _, err := f.super.Exec(ctx, "UPDATE software_repository SET rebuild_requested_at = now() WHERE organization_id = $1", f.org); err != nil {
		t.Fatal(err)
	}
	failures := 0
	store.onPut = func(key string) error {
		if key == dists+"main/binary-amd64/Packages.gz" {
			failures++
			return fmt.Errorf("put %s: %w", key, &s3Error{requestID: fmt.Sprintf("REQ%d", failures)})
		}
		return nil
	}
	for range 2 {
		if err := build(); err == nil || !strings.Contains(err.Error(), "RequestID") {
			t.Fatalf("a refused upload: %v", err)
		}
	}
	store.onPut = nil
	refused := read()
	if want := "upload main/binary-amd64/Packages.gz: AccessDenied, HTTP 403"; refused.lastError == nil || *refused.lastError != want {
		t.Fatalf("last_error %v, want %q", refused.lastError, want)
	}
	if n := events("software_repository.build_failed"); n != 2 {
		t.Fatalf("%d build_failed events, want 2 (sealed, refused upload)", n)
	}
	if !bytes.Equal(store.objects[dists+"InRelease"], published) || refused.generation != 2 {
		t.Fatal("a failed build replaced InRelease")
	}
	if !strings.Contains(string(store.objects[dists+"main/binary-amd64/Packages"]), "acme-new") {
		t.Fatal("the test did not overwrite the Packages list before the failure")
	}
	block, _ := clearsign.Decode(published)
	for _, line := range strings.Split(string(block.Plaintext), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || !strings.HasPrefix(line, " ") {
			continue
		}
		dir := fields[2][:strings.LastIndex(fields[2], "/")]
		data, ok := store.objects[dists+dir+"/by-hash/SHA256/"+fields[0]]
		got := sha256.Sum256(data)
		if !ok || hex.EncodeToString(got[:]) != fields[0] {
			t.Fatalf("the previous InRelease names %s, which is not readable by its hash", fields[2])
		}
	}
	if err := build(); err != nil {
		t.Fatal(err)
	}
	if r := read(); r.lastError != nil || r.generation != 3 {
		t.Fatalf("after the retry %+v", r)
	}

	// L5: rotation. InRelease is signed with the new key while the source still carries the old one; the source gets the
	// new key afterwards. The old key stays as previous and signs InRelease too, so a device that has only the old key
	// keeps verifying the repository.
	if _, err := f.super.Exec(ctx, `UPDATE software_repository SET key_rotation_requested_at = now(), rebuild_requested_at = now()
		WHERE organization_id = $1`, f.org); err != nil {
		t.Fatal(err)
	}
	var sourceAtInRelease string
	store.onPut = func(key string) error {
		if key == dists+"InRelease" {
			sourceAtInRelease = read().source
		}
		return nil
	}
	if err := build(); err != nil {
		t.Fatal(err)
	}
	store.onPut = nil
	rotated := read()
	if rotated.fingerprint == first.fingerprint || rotated.previous == nil || *rotated.previous != first.fingerprint ||
		rotated.retired == nil || rotated.source != rotated.fingerprint || rotated.generation != 4 ||
		rotated.previousCiphertext == nil || *rotated.previousCiphertext != first.ciphertext {
		t.Fatalf("after the rotation %+v", rotated)
	}
	if sourceAtInRelease != first.fingerprint {
		t.Fatalf("the source carried %s while the new InRelease was written, want the old key", sourceAtInRelease)
	}
	if err := verify(rotated.publicKey); err != nil {
		t.Fatalf("InRelease does not verify with the new key: %v", err)
	}
	if err := verify(first.publicKey); err != nil {
		t.Fatalf("during the overlap InRelease does not verify with the old key: %v", err)
	}
	if gpgv != "" && (!gpgvVerifies(first.publicKey) || !gpgvVerifies(rotated.publicKey)) {
		t.Fatal("during the overlap gpgv does not accept InRelease with the old key alone or the new key alone")
	}
	if n := f.count(t, "SELECT count(*) FROM software_repository WHERE organization_id = $1 AND key_rotation_requested_at IS NULL", f.org); n != 1 {
		t.Fatal("the rotation request was not cleared")
	}

	// The previous key signs for 30 days; then it is dropped and the index is signed with the new key alone.
	if _, err := f.super.Exec(ctx, `UPDATE software_repository SET previous_retired_at = now() - interval '29 days' WHERE organization_id = $1`, f.org); err != nil {
		t.Fatal(err)
	}
	if err := build(); err != nil || read().previous == nil {
		t.Fatalf("the previous key was dropped before 30 days (%v)", err)
	}
	if _, err := f.super.Exec(ctx, `UPDATE software_repository SET previous_retired_at = now() - interval '31 days' WHERE organization_id = $1`, f.org); err != nil {
		t.Fatal(err)
	}
	if err := build(); err != nil {
		t.Fatal(err)
	}
	if r := read(); r.previous != nil || r.previousCiphertext != nil || r.generation != 5 {
		t.Fatalf("the previous key outlived 30 days, or the index was not rebuilt without it: %+v", r)
	}
	if err := verify(first.publicKey); err == nil {
		t.Fatal("after the overlap InRelease still verifies with the old key")
	}
	if gpgv != "" && (gpgvVerifies(first.publicKey) || !gpgvVerifies(rotated.publicKey)) {
		t.Fatal("after the overlap gpgv accepts InRelease with the old key, or not with the new one")
	}

	// L5, a rotation retried after a failed build (Review 2 of PDK-813): devices hold only the published key, so a key
	// that never reached the source is replaced, not retired, and the published key keeps signing. Its 30 days start
	// with the publication of its successor, so builds failing for longer than that never drop it.
	rotate := func() {
		t.Helper()
		if _, err := f.super.Exec(ctx, `UPDATE software_repository SET key_rotation_requested_at = now(), rebuild_requested_at = now()
			WHERE organization_id = $1`, f.org); err != nil {
			t.Fatal(err)
		}
	}
	oldest := read()
	store.onPut = func(key string) error {
		if key == dists+"InRelease" {
			return &s3Error{requestID: "REQ-ROTATE"}
		}
		return nil
	}
	rotate()
	if err := build(); err == nil {
		t.Fatal("a refused upload did not fail the build")
	}
	stranded := read()
	if stranded.fingerprint == oldest.fingerprint || stranded.previous == nil || *stranded.previous != oldest.fingerprint ||
		stranded.retired != nil || stranded.source != oldest.fingerprint {
		t.Fatalf("after a rotation whose build failed %+v", stranded)
	}
	clock := now
	now = clock.Add(app.RepositoryKeyRetention + 24*time.Hour)
	if err := build(); err == nil || read().previous == nil {
		t.Fatalf("the published key was dropped 30 days after a rotation that was never published (%v)", err)
	}
	now = clock
	rotate()
	if err := build(); err == nil {
		t.Fatal("a refused upload did not fail the build")
	}
	if r := read(); r.fingerprint == stranded.fingerprint || r.previous == nil || *r.previous != oldest.fingerprint ||
		r.previousCiphertext == nil || *r.previousCiphertext != oldest.ciphertext || r.retired != nil {
		t.Fatalf("a second rotation before the first was published retired an unpublished key or dropped the published one: %+v", r)
	}
	store.onPut = nil
	if err := build(); err != nil {
		t.Fatal(err)
	}
	recovered := read()
	if recovered.source != recovered.fingerprint || recovered.previous == nil || *recovered.previous != oldest.fingerprint ||
		recovered.retired == nil || recovered.generation != 6 {
		t.Fatalf("after the recovered build %+v", recovered)
	}
	if err := verify(oldest.publicKey); err != nil {
		t.Fatalf("a device with only the published key does not verify the build after two rotations: %v", err)
	}
	if gpgv != "" && (!gpgvVerifies(oldest.publicKey) || !gpgvVerifies(recovered.publicKey)) {
		t.Fatal("after two rotations gpgv does not accept InRelease with the published key alone or the new key alone")
	}

	// The private key: zeroed after every use, never in the log.
	if len(vault.plaintexts) < 4 {
		t.Fatalf("%d plaintext keys seen, want generation and decryption", len(vault.plaintexts))
	}
	for i, p := range vault.plaintexts {
		if len(p) == 0 || slices.ContainsFunc(p, func(b byte) bool { return b != 0 }) {
			t.Fatalf("plaintext key %d was not zeroed", i)
		}
	}
	if logs.Len() == 0 {
		t.Fatal("nothing logged; the logger test saw no failure")
	}
	for _, r := range []repoRow{first, rotated} {
		raw, _ := base64.StdEncoding.DecodeString(r.ciphertext[strings.LastIndex(r.ciphertext, ":")+1:])
		for _, form := range []string{base64.StdEncoding.EncodeToString(raw), hex.EncodeToString(raw), string(raw[len(raw)-32:]),
			r.ciphertext, "PRIVATE KEY"} {
			if strings.Contains(logs.String(), form) {
				t.Fatal("the private key reached the log")
			}
		}
	}

	// The round builds as the worker of every organization.
	if _, err := f.super.Exec(ctx, "UPDATE software_repository SET rebuild_requested_at = now() WHERE organization_id = $1", f.org); err != nil {
		t.Fatal(err)
	}
	round := NewSoftwareRepositories(builds, f.pool, platform)
	if err := round.Round(ctx); err != nil && strings.Contains(err.Error(), f.org.String()) {
		t.Fatal(err)
	}
	if r := read(); r.generation != 7 {
		t.Fatalf("the round did not build: generation %d", r.generation)
	}
}
