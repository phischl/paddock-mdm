package getent

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// nssNoise is the line Himmelblau's NSS module printed while himmelblaud was down (PDK-892).
const nssNoise = "2026-11-08T05:01:13.152453Z ERROR Unix socket stream setup error while connecting to " +
	"/var/run/himmelblaud/socket -> Os { code: 111, kind: ConnectionRefused, message: \"Connection refused\" }\n"

func TestParsePasswd(t *testing.T) {
	pw, err := ParsePasswd("dave@acme.test:x:811622788:811622788:Dave:/home/dave@acme.test:/bin/bash\n")
	if err != nil || pw != (Passwd{Name: "dave@acme.test", UID: 811622788, GID: 811622788}) {
		t.Fatalf("ParsePasswd = %+v, %v", pw, err)
	}
	if pw, err := ParsePasswd("dave:x:1000:1000:::\n"); err != nil || pw.UID != 1000 {
		t.Fatalf("empty GECOS, home and shell: %+v, %v", pw, err)
	}
}

func TestParsePasswdRejectsForeignOutput(t *testing.T) {
	entry := "dave:x:811622788:811622788::/home/dave:/bin/bash\n"
	for name, out := range map[string]string{
		"noise before":      nssNoise + entry,
		"noise after":       entry + nssNoise,
		"noise only":        nssNoise,
		"empty":             "",
		"two entries":       entry + entry,
		"carriage return":   strings.TrimSuffix(entry, "\n") + "\r\n",
		"six fields":        "dave:x:1000:1000::/home/dave\n",
		"eight fields":      "dave:x:1000:1000::/home/dave:/bin/bash:x\n",
		"non-numeric UID":   "dave:x:13.152453Z ERROR:1000::/home/dave:/bin/bash\n",
		"negative GID":      "dave:x:1000:-1::/home/dave:/bin/bash\n",
		"UID over 32 bits":  "dave:x:4294967296:1000::/home/dave:/bin/bash\n",
		"empty name":        ":x:1000:1000::/home/dave:/bin/bash\n",
		"noise without EOL": strings.TrimSuffix(nssNoise, "\n"),
	} {
		if pw, err := ParsePasswd(out); !errors.Is(err, ErrUnexpectedOutput) {
			t.Errorf("%s: ParsePasswd = %+v, %v; want ErrUnexpectedOutput", name, pw, err)
		}
	}
}

func TestParseGroup(t *testing.T) {
	g, err := ParseGroup("sudo:x:27:paddock,dave@acme.test\n", "sudo")
	if err != nil || g.Name != "sudo" || g.GID != 27 || !slices.Equal(g.Members, []string{"paddock", "dave@acme.test"}) {
		t.Fatalf("ParseGroup = %+v, %v", g, err)
	}
	if g, err := ParseGroup("admin:x:118:\n", "admin"); err != nil || len(g.Members) != 0 {
		t.Fatalf("no members: %+v, %v", g, err)
	}
}

// TestParseGroupRejectsForeignOutput: a log line before the entry used to shift the fields, so that " 111" and
// " kind" became members of sudo and the real members were lost.
func TestParseGroupRejectsForeignOutput(t *testing.T) {
	entry := "sudo:x:27:paddock,eve\n"
	for name, out := range map[string]string{
		"noise before":   nssNoise + entry,
		"noise after":    entry + nssNoise,
		"noise only":     nssNoise,
		"empty":          "",
		"other group":    "admin:x:118:paddock\n",
		"three fields":   "sudo:x:27\n",
		"five fields":    "sudo:x:27:paddock:x\n",
		"non-numeric":    "sudo:x:x:paddock\n",
		"empty member":   "sudo:x:27:paddock,,eve\n",
		"blank member":   "sudo:x:27:paddock, 111\n",
		"trailing comma": "sudo:x:27:paddock,\n",
	} {
		if g, err := ParseGroup(out, "sudo"); !errors.Is(err, ErrUnexpectedOutput) {
			t.Errorf("%s: ParseGroup = %+v, %v; want ErrUnexpectedOutput", name, g, err)
		}
	}
}

func TestErrorQuotesBoundedOutput(t *testing.T) {
	_, err := ParsePasswd(strings.Repeat(nssNoise, 100))
	if err == nil {
		t.Fatal("no error")
	}
	if len(err.Error()) > 300 {
		t.Fatalf("error of %d bytes: %v", len(err.Error()), err)
	}
}
