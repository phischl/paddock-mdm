package system

import (
	"strings"
	"testing"
)

// TestSoftwareHelpersUnit pins the parsers of the software gate: a parser that silently found nothing would make
// SW1, SW5, SW6 and SW7 compare against an empty value.
func TestSoftwareHelpersUnit(t *testing.T) {
	primary, sub := strings.Repeat("AB12", 10), strings.Repeat("CD34", 10)
	colons := "tru::1:1761900000:0:3:1:5\npub:u:255:22:0123456789ABCDEF:1761900000:1761986400::u:::scSC:::::ed25519:::0:\n" +
		"fpr:::::::::" + primary + ":\nuid:u::::1761900000::X::Paddock gate repository <gate@paddock.invalid>::::::::::0:\n" +
		"sub:u:255:18:FEDCBA9876543210:1761900000::::::e:::::cv25519::\nfpr:::::::::" + sub + ":\n"
	if got := colonFingerprint(colons); got != primary {
		t.Errorf("colonFingerprint = %q, want the primary key's", got)
	}
	if got := colonFingerprint("gpg: no valid OpenPGP data found.\n"); got != "" {
		t.Errorf("colonFingerprint without a key = %q", got)
	}

	report := `{"reconcile":"ok","software":{"digest":"d","items":[` +
		`{"id":"e1","package":"other","intent":"required","state":"installed","version":"2"},` +
		`{"id":"e2","package":"paddock-gate-app","intent":"forbid","state":"pending","version":"1.0","reason":"deferred_offline"}]}}`
	it, ok, err := healthSoftwareItem(report, gateApp)
	if err != nil || !ok || it.State != "pending" || it.Reason != "deferred_offline" || it.ID != "e2" {
		t.Errorf("healthSoftwareItem = %+v %v %v", it, ok, err)
	}
	if _, ok, err := healthSoftwareItem(`{"reconcile":"ok"}`, gateApp); ok || err != nil {
		t.Errorf("healthSoftwareItem without software = %v %v", ok, err)
	}
	if _, _, err := healthSoftwareItem("not json", gateApp); err == nil {
		t.Error("healthSoftwareItem accepted a report that is not JSON")
	}

	want := "# Managed by Paddock. Do not edit: local changes are reverted.\nTypes: deb\nURIs: https://127.0.0.1:8443/\n" +
		"Suites: ./\nSigned-By: /etc/apt/keyrings/paddock-gate-x.gpg\n"
	if got := gateSourceFile("gate-x"); got != want {
		t.Errorf("gateSourceFile =\n%s\nwant\n%s", got, want)
	}
}

// TestSoftwareAptOutputUnit pins how SW7 reads apt-get update: a refused signature in gpgv's and sqv's wording counts
// only with a W: or E: line, a clean update never counts, and the lists lock is told apart from other errors.
func TestSoftwareAptOutputUnit(t *testing.T) {
	gpgv := "Get:1 https://127.0.0.1:8443 ./ InRelease [1234 B]\nErr:1 https://127.0.0.1:8443 ./ InRelease\n" +
		"  The following signatures couldn't be verified because the public key is not available: NO_PUBKEY 0123456789ABCDEF\n" +
		"W: GPG error: https://127.0.0.1:8443 ./ InRelease: The following signatures couldn't be verified\n" +
		"E: The repository 'https://127.0.0.1:8443 ./ InRelease' is not signed.\n"
	sqv := "Err:1 https://127.0.0.1:8443 ./ InRelease\n  Sub-process /usr/bin/sqv returned an error code (1), error message is: Missing key 0123456789ABCDEF, which is needed to verify signature.\n" +
		"W: OpenPGP signature verification failed: https://127.0.0.1:8443 ./ InRelease: Sub-process /usr/bin/sqv returned an error code (1)\n" +
		"E: The repository 'https://127.0.0.1:8443 ./ InRelease' is not signed.\n"
	clean := "Get:1 https://127.0.0.1:8443 ./ InRelease [1234 B]\nReading package lists...\n"
	locked := "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 4242 (apt-get)\nE: Unable to lock directory /var/lib/apt/lists/\n"
	for name, c := range map[string]struct {
		out                   string
		refused, failed, lock bool
	}{
		"gpgv":      {gpgv, true, true, false},
		"sqv":       {sqv, true, true, false},
		"clean":     {clean, false, false, false},
		"locked":    {locked, false, true, true},
		"no line":   {"NO_PUBKEY in a package description\n", false, false, false},
		"dpkg lock": {"E: Could not get lock /var/lib/dpkg/lock-frontend.\n", false, true, false},
	} {
		if got := signatureRefused(c.out); got != c.refused {
			t.Errorf("%s: signatureRefused = %v, want %v", name, got, c.refused)
		}
		if got := aptError(c.out); got != c.failed {
			t.Errorf("%s: aptError = %v, want %v", name, got, c.failed)
		}
		if got := listsLocked(c.out); got != c.lock {
			t.Errorf("%s: listsLocked = %v, want %v", name, got, c.lock)
		}
	}
}
