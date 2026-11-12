package aptsign_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/phischl/paddock-mdm/pkg/openpgpkey"
	"github.com/phischl/paddock-mdm/server/internal/adapters/aptsign"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
)

// now is in the past, so gpgv does not see a key created in the future.
var now = time.Now().Add(-time.Hour).Truncate(time.Second)

const release = "Origin: Paddock\nSuite: paddock\nSHA256:\n 00 0 main/binary-amd64/Packages\n- a line starting with a dash\n"

type key struct {
	PublicKey, Fingerprint string
	Private                []byte
}

func generate(t *testing.T, slug string) key {
	t.Helper()
	pub, fp, priv, err := aptsign.Signer{}.GenerateKey(slug, now)
	if err != nil {
		t.Fatal(err)
	}
	return key{PublicKey: pub, Fingerprint: fp, Private: priv}
}

// TestGenerateKey (ADR 0050 decision 3): an Ed25519 v4 key "Paddock <slug>" whose fingerprint pkg/openpgpkey reads
// as the stored one, accepted by the policy of software sources, so the system source carries it unchanged.
func TestGenerateKey(t *testing.T) {
	k := generate(t, "acme")
	parsed, err := openpgpkey.ParseArmored([]byte(k.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Fingerprint != k.Fingerprint || len(k.Fingerprint) != 40 || strings.ToUpper(k.Fingerprint) != k.Fingerprint {
		t.Fatalf("fingerprint %s, openpgpkey reads %s", k.Fingerprint, parsed.Fingerprint)
	}
	if len(parsed.UserIDs) != 1 || parsed.UserIDs[0] != "Paddock <acme>" || len(parsed.Subkeys) != 0 ||
		parsed.Algorithm != openpgpkey.EdDSA {
		t.Fatalf("key %+v", parsed)
	}
	if _, err := software.ValidateSource(software.SourceInput{Kind: software.SourceKindAPT, Slug: "paddock", Name: "Paddock",
		URIs: []string{"https://bundles.example.com/apt/acme/"}, Suites: []string{"paddock"}, Components: []string{"main"},
		SigningKey: k.PublicKey, Fingerprint: k.Fingerprint}); err != nil {
		t.Fatalf("the source policy refuses the key: %v", err)
	}
	if bytes.Contains([]byte(k.PublicKey), k.Private) || len(k.Private) == 0 {
		t.Fatal("no private key, or it is part of the public one")
	}
	if other := generate(t, "acme"); other.Fingerprint == k.Fingerprint {
		t.Fatal("two keys share a fingerprint")
	}
}

// TestSignVerifies: InRelease and Release.gpg verify with the public key through the library's verifier and not with
// another key; the signed text of InRelease is the Release file.
func TestSignVerifies(t *testing.T) {
	k := generate(t, "acme")
	in, detached, err := aptsign.Signer{}.Sign([][]byte{k.Private}, []byte(release), now)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(k.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	block, rest := clearsign.Decode(in)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("InRelease is not one clearsigned block:\n%s", in)
	}
	if string(block.Plaintext) != strings.TrimSuffix(release, "\n") && string(block.Plaintext) != release {
		t.Fatalf("signed text %q", block.Plaintext)
	}
	if _, err := block.VerifySignature(keyring, nil); err != nil {
		t.Fatalf("InRelease: %v", err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring, strings.NewReader(release), bytes.NewReader(detached), nil); err != nil {
		t.Fatalf("Release.gpg: %v", err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring, strings.NewReader(release+"x"), bytes.NewReader(detached), nil); err == nil {
		t.Fatal("Release.gpg verifies a changed Release")
	}
	other, err := openpgp.ReadArmoredKeyRing(strings.NewReader(generate(t, "other").PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := block.VerifySignature(other, nil); err == nil {
		t.Fatal("InRelease verifies with another key")
	}
	if _, _, err := (aptsign.Signer{}).Sign([][]byte{[]byte("not a key")}, []byte(release), now); err == nil {
		t.Fatal("signed with garbage as the key")
	}
	if _, _, err := (aptsign.Signer{}).Sign(nil, []byte(release), now); err == nil {
		t.Fatal("signed without a key")
	}
}

// TestSignWithTwoKeys (plan M13c §3.8 L5, the overlap of a rotation): InRelease and Release.gpg carry one signature per
// key; each key alone verifies both files, another key does not.
func TestSignWithTwoKeys(t *testing.T) {
	current, previous := generate(t, "acme"), generate(t, "acme")
	in, detached, err := aptsign.Signer{}.Sign([][]byte{current.Private, previous.Private}, []byte(release), now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := clearsign.Decode(in)
	if block == nil {
		t.Fatalf("InRelease is not clearsigned:\n%s", in)
	}
	for _, k := range []key{current, previous} {
		keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(k.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := block.VerifySignature(keyring, nil); err != nil {
			t.Fatalf("InRelease does not verify with %s: %v", k.Fingerprint, err)
		}
		if _, err := openpgp.CheckArmoredDetachedSignature(keyring, strings.NewReader(release), bytes.NewReader(detached), nil); err != nil {
			t.Fatalf("Release.gpg does not verify with %s: %v", k.Fingerprint, err)
		}
	}
	other, err := openpgp.ReadArmoredKeyRing(strings.NewReader(generate(t, "other").PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := block.VerifySignature(other, nil); err == nil {
		t.Fatal("InRelease verifies with another key")
	}
	if _, _, err := (aptsign.Signer{}).Sign([][]byte{current.Private, []byte("not a key")}, []byte(release), now); err == nil {
		t.Fatal("signed with garbage as the second key")
	}
}

// TestSignVerifiesWithGPGV checks the signatures with gpgv, the verifier apt uses on Ubuntu 24.04, independent of the
// library that made them. It is skipped where gpgv is not installed.
func TestSignVerifiesWithGPGV(t *testing.T) {
	gpgv, err := exec.LookPath("gpgv")
	if err != nil {
		t.Skip("gpgv not installed")
	}
	k, previous := generate(t, "acme"), generate(t, "acme")
	for _, c := range []struct {
		name    string
		signers [][]byte
		ring    key
	}{
		{"one key", [][]byte{k.Private}, k},
		{"two keys, verified with the current one", [][]byte{k.Private, previous.Private}, k},
		{"two keys, verified with the previous one", [][]byte{k.Private, previous.Private}, previous},
	} {
		t.Run(c.name, func(t *testing.T) { gpgvAccepts(t, gpgv, c.signers, c.ring) })
	}
}

// gpgvAccepts checks with gpgv that the files signed by signers verify with the keyring of ring alone.
func gpgvAccepts(t *testing.T, gpgv string, signers [][]byte, ring key) {
	in, detached, err := aptsign.Signer{}.Sign(signers, []byte(release), now)
	if err != nil {
		t.Fatal(err)
	}
	_, binary, err := openpgpkey.Fingerprint([]byte(ring.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	keyring := write("paddock.gpg", binary)
	// gpgv exits 2 when one of several signatures has no key in the keyring; apt reads gpgv's status lines instead and
	// accepts a file with a valid signature of a trusted key and no bad one, as checked here.
	run := func(args ...string) error {
		var status, stderr bytes.Buffer
		cmd := exec.Command(gpgv, append([]string{"--homedir", dir, "--keyring", keyring, "--status-fd", "1"}, args...)...)
		cmd.Stdout, cmd.Stderr = &status, &stderr
		err := cmd.Run()
		var exit *exec.ExitError
		switch {
		case strings.Contains(status.String(), "[GNUPG:] BADSIG"):
			err = errors.New("bad signature")
		case !strings.Contains(status.String(), "[GNUPG:] VALIDSIG "+ring.Fingerprint):
			err = errors.New("no valid signature of " + ring.Fingerprint)
		case len(signers) > 1 && errors.As(err, &exit) && exit.ExitCode() == 2:
			err = nil
		}
		if err != nil {
			t.Logf("gpgv %v: %s%s", args, stderr.String(), status.String())
		}
		return err
	}
	if err := run(write("InRelease", in)); err != nil {
		t.Fatalf("gpgv refuses InRelease: %v", err)
	}
	if err := run(write("Release.gpg", detached), write("Release", []byte(release))); err != nil {
		t.Fatalf("gpgv refuses Release.gpg: %v", err)
	}
	if err := run(filepath.Join(dir, "Release.gpg"), write("Release-changed", []byte(release+"x"))); err == nil {
		t.Fatal("gpgv accepts Release.gpg for a changed Release")
	}
}

// TestAptAcceptsRepository runs apt itself (apt-get update as an unprivileged user against a file:// repository with
// Signed-By) on an index of software.BuildIndex signed by Sign: with the repository's key apt lists the package, with
// another key it lists nothing. During a rotation's overlap (plan M13c §3.8 L5) the index is signed with the new and
// the previous key, and a device that has only the previous key lists the package as well as one with the new key;
// once the index is signed with the new key alone, the previous key no longer lists it. It is skipped where apt-get is
// not installed.
func TestAptAcceptsRepository(t *testing.T) {
	if _, err := exec.LookPath("apt-get"); err != nil {
		t.Skip("apt not installed")
	}
	k, previous := generate(t, "acme"), generate(t, "acme")
	deb, sum := helloDeb(t)
	single := aptRepository(t, deb, sum, [][]byte{k.Private}, nil)
	if !aptLists(t, single, k.PublicKey, sum) {
		t.Fatal("apt does not list the package of the signed repository")
	}
	if aptLists(t, single, generate(t, "other").PublicKey, sum) {
		t.Fatal("apt lists the package with another key")
	}
	overlap := aptRepository(t, deb, sum, [][]byte{k.Private, previous.Private}, nil)
	if !aptLists(t, overlap, previous.PublicKey, sum) {
		t.Fatal("during the overlap apt does not list the package with the previous key alone")
	}
	if !aptLists(t, overlap, k.PublicKey, sum) {
		t.Fatal("during the overlap apt does not list the package with the new key alone")
	}
	if aptLists(t, single, previous.PublicKey, sum) {
		t.Fatal("after the overlap apt lists the package with the previous key")
	}
}

// TestAptReadsListsByHash (plan M13c §3.7): a build that failed after overwriting the lists at their names but before
// InRelease leaves the previous InRelease next to the new lists; apt reads the previous lists by their hash and still
// lists the package.
func TestAptReadsListsByHash(t *testing.T) {
	if _, err := exec.LookPath("apt-get"); err != nil {
		t.Skip("apt not installed")
	}
	k := generate(t, "acme")
	deb, sum := helloDeb(t)
	next, err := software.BuildIndex(nil, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	repo := aptRepository(t, deb, sum, [][]byte{k.Private}, &next)
	if !aptLists(t, repo, k.PublicKey, sum) {
		t.Fatal("apt does not list the package of the previous InRelease while the lists of the next build are in place")
	}
}

func helloDeb(t *testing.T) ([]byte, string) {
	t.Helper()
	deb, err := os.ReadFile("../../domain/software/testdata/hello-gzip.deb")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(deb)
	return deb, hex.EncodeToString(sum[:])
}

// aptRepository writes a repository with the package deb, its index signed by signers, the lists below by-hash and at
// their names; with partial, the lists at their names and below by-hash are those of the next, partly uploaded build.
func aptRepository(t *testing.T, deb []byte, sum string, signers [][]byte, partial *software.RepositoryIndex) string {
	t.Helper()
	pool := software.PoolPath("acme-hello", "1.0", "all")
	idx, err := software.BuildIndex([]software.IndexPackage{{Package: "acme-hello", Version: "1.0", Architecture: "all",
		Fields: map[string]string{"Maintainer": "Acme <it@acme.example>", "Description": "hello\n world"}, Filename: pool,
		Size: int64(len(deb)), SHA256: sum}}, now)
	if err != nil {
		t.Fatal(err)
	}
	in, detached, err := aptsign.Signer{}.Sign(signers, idx.Release, now)
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	files := map[string][]byte{pool: deb, "dists/paddock/Release": idx.Release, "dists/paddock/Release.gpg": detached,
		"dists/paddock/InRelease": in}
	lists := slices.Concat(idx.ByHash, idx.Files)
	if partial != nil {
		lists = slices.Concat(idx.ByHash, partial.ByHash, partial.Files)
	}
	for _, f := range lists {
		files["dists/paddock/"+f.Path] = f.Data
	}
	for name, data := range files {
		writeFile(t, filepath.Join(repo, name), data)
	}
	return repo
}

// aptLists runs apt-get update against repo with publicKey as the source's keyring and reports whether apt then
// shows the package with the SHA-256 sum.
func aptLists(t *testing.T, repo, publicKey, sum string) bool {
	t.Helper()
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	_, keyring, err := openpgpkey.Fingerprint([]byte(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "paddock.gpg"), keyring)
	writeFile(t, filepath.Join(root, "etc/sources.list"), nil)
	writeFile(t, filepath.Join(root, "status"), nil)
	writeFile(t, filepath.Join(root, "etc/sources.list.d/paddock.sources"), []byte("Types: deb\nURIs: file://"+repo+
		"/\nSuites: paddock\nComponents: main\nArchitectures: amd64\nSigned-By: "+root+"/paddock.gpg\n"))
	for _, d := range []string{"state/lists/partial", "cache/archives/partial", "etc/apt.conf.d", "etc/preferences.d", "log"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	opts := []string{"-o", "Dir::State=" + root + "/state", "-o", "Dir::State::status=" + root + "/status",
		"-o", "Dir::Cache=" + root + "/cache", "-o", "Dir::Etc=" + root + "/etc", "-o", "Dir::Log=" + root + "/log",
		"-o", "Dir::Etc::sourcelist=" + root + "/etc/sources.list", "-o", "Dir::Etc::sourceparts=" + root + "/etc/sources.list.d",
		"-o", "Debug::NoLocking=1", "-o", "APT::Sandbox::User=" + me.Username}
	out, _ := exec.Command("apt-get", append(opts, "update")...).CombinedOutput()
	t.Logf("apt-get update: %s", out)
	show, err := exec.Command("apt-cache", append(opts, "show", "acme-hello")...).CombinedOutput()
	return err == nil && strings.Contains(string(show), "SHA256: "+sum)
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
