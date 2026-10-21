package system

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestLUKSPassphraseSlots: every luks2 keyslot is a passphrase slot and a reencryption keyslot is not; keyslots and
// tokens come back in numeric order.
func TestLUKSPassphraseSlots(t *testing.T) {
	metadata := []byte(`{
		"keyslots": {"10": {"type": "luks2"}, "0": {"type": "luks2"}, "3": {"type": "reencrypt"}, "1": {"type": "luks2"}},
		"tokens": {"2": {"type": "systemd-tpm2", "keyslots": ["1"]}, "0": {"type": "systemd-recovery", "keyslots": ["0"]}},
		"segments": {}, "digests": {}, "config": {}
	}`)
	slots, tokens, err := luksPassphraseSlots(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(slots, []int{0, 1, 10}) || !slices.Equal(tokens, []int{0, 2}) {
		t.Fatalf("slots %v, tokens %v; want [0 1 10] and [0 2]", slots, tokens)
	}
	for _, bad := range []string{`{"keyslots": {"x": {"type": "luks2"}}}`, `{"tokens": {"x": {}}}`, `not json`} {
		if _, _, err := luksPassphraseSlots([]byte(bad)); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}

// TestOpensScriptIgnoresTokens is the self-test of Opens against a LUKS2 image whose second keyslot has a keyring
// token that unlocks without input, like a tpm2 token without a PIN: a plain cryptsetup --test-passphrase accepts any
// secret there, the script accepts only the passphrases of the keyslots and leaves the image's token in place. It needs
// cryptsetup and keyctl on the host.
func TestOpensScriptIgnoresTokens(t *testing.T) {
	for _, tool := range []string{"cryptsetup", "keyctl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	dir := t.TempDir()
	image := filepath.Join(dir, "luks.img")
	sh := func(stdin, script string) (string, int) {
		t.Helper()
		cmd := exec.CommandContext(context.Background(), "sh", "-c", script)
		cmd.Stdin = strings.NewReader(stdin)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		var exit *exec.ExitError
		switch {
		case err == nil:
			return out.String(), 0
		case errors.As(err, &exit):
			return out.String(), exit.ExitCode()
		default:
			t.Fatalf("%s: %v", script, err)
			return "", 0
		}
	}
	must := func(stdin, script string) string {
		t.Helper()
		out, rc := sh(stdin, script)
		if rc != 0 {
			t.Fatalf("%s: exit %d: %s", script, rc, out)
		}
		return out
	}
	description := "paddock-opens-" + unique()
	// pbkdf2 with few iterations keeps the self-test fast; the KDF does not matter for which keyslot answers.
	kdf := "--pbkdf pbkdf2 --pbkdf-force-iterations 1000"
	must("first-passphrase", "truncate -s 32M "+image+" && cryptsetup luksFormat -q --type luks2 "+kdf+" --key-file=- "+image)
	must("second-passphrase", "printf first-passphrase > "+dir+"/first && cryptsetup luksAddKey -q "+kdf+" --key-file "+dir+"/first "+image+" - && rm "+dir+"/first")
	must("", "cryptsetup token add --key-description "+description+" --key-slot 1 "+image)
	must("second-passphrase", "keyctl padd user "+description+" @u >/dev/null")
	t.Cleanup(func() { _, _ = sh("", "keyctl purge user "+description+" >/dev/null") })

	if _, rc := sh("wrong-secret", "cryptsetup open --test-passphrase --key-file=- "+image); rc != 0 {
		t.Fatalf("the keyring token does not answer for a wrong secret (exit %d); the self-test would prove nothing", rc)
	}
	slots, tokens, err := luksPassphraseSlots([]byte(must("", "cryptsetup luksDump --dump-json-metadata "+image)))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(slots, []int{0, 1}) || !slices.Equal(tokens, []int{0}) {
		t.Fatalf("slots %v, tokens %v", slots, tokens)
	}
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	script := opensScript(image, work, slots, tokens)
	if strings.Contains(script, "'") {
		t.Fatal("the script contains a single quote")
	}
	for secret, want := range map[string]int{"wrong-secret": opensRejected, "first-passphrase": 0, "second-passphrase": 0} {
		if out, rc := sh(secret, script); rc != want {
			t.Errorf("%s: exit %d, want %d: %s", secret, rc, want, out)
		}
	}
	if left, _ := os.ReadDir(work); len(left) != 0 {
		t.Errorf("the script left %d entries in its directory", len(left))
	}
	if _, tokens, _ := luksPassphraseSlots([]byte(must("", "cryptsetup luksDump --dump-json-metadata "+image))); !slices.Equal(tokens, []int{0}) {
		t.Errorf("tokens of the image after the script %v, want [0]", tokens)
	}
	if out, rc := sh("secret", opensScript(filepath.Join(dir, "missing.img"), work, slots, tokens)); rc == 0 || rc == opensRejected {
		t.Errorf("a missing device exits %d, want an error: %s", rc, out)
	}
}
