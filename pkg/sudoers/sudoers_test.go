package sudoers

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func restricted() Entry {
	return Entry{
		Username: "dave@acme.test", Class: ClassRestricted,
		Commands:        []string{"/usr/bin/journalctl -u nginx.service", "/usr/bin/systemctl restart nginx.service"},
		RequirePassword: true, TimestampTimeoutMin: 5, Lecture: LectureAlways,
		ProfileDigest: strings.Repeat("ab", 32),
	}
}

func TestRenderGolden(t *testing.T) {
	got, err := Render(restricted(), 120034, Classic)
	if err != nil {
		t.Fatal(err)
	}
	want := "# Managed by Paddock. Do not edit. User dave@acme.test, profile digest " + strings.Repeat("ab", 32) + "\n" +
		"Defaults:#120034 lecture=always, lecture_file=/etc/paddock/sudo_lecture, timestamp_timeout=5\n" +
		"#120034 ALL=(root) /usr/bin/journalctl -u nginx.service, /usr/bin/systemctl restart nginx.service\n"
	if string(got) != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}

	full := Entry{Username: "erin@acme.test", Class: ClassFull, Lecture: LectureNever, TimestampTimeoutMin: 0}
	got, err = Render(full, 7, Classic)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(got), "#7 ALL=(root) NOPASSWD: ALL\n") {
		t.Fatalf("full entry without password:\n%s", got)
	}
}

// TestFlavorsDifferOnlyInLectureFile: the sudo-rs file is the classic file without the lecture_file setting, byte for
// byte; an unknown flavor is refused.
func TestFlavorsDifferOnlyInLectureFile(t *testing.T) {
	for _, e := range []Entry{
		restricted(),
		{Username: "erin@acme.test", Class: ClassFull, Lecture: LectureNever, TimestampTimeoutMin: 60},
	} {
		classic, err := Render(e, 120034, Classic)
		if err != nil {
			t.Fatal(err)
		}
		rs, err := Render(e, 120034, SudoRS)
		if err != nil {
			t.Fatal(err)
		}
		if want := strings.Replace(string(classic), ", lecture_file="+LectureFile, "", 1); string(rs) != want || bytes.Contains(rs, []byte("lecture_file")) {
			t.Fatalf("sudo-rs\n%s\nwant\n%s", rs, want)
		}
	}
	if _, err := Render(restricted(), 1, Flavor("doas")); !errors.Is(err, ErrFlavor) {
		t.Fatalf("unknown flavor: %v", err)
	}
	// sudo-rs handles at most 9 digits; classic sudo any UID.
	if _, err := Render(restricted(), MaxSudoRSUID, SudoRS); err != nil {
		t.Fatalf("9-digit UID: %v", err)
	}
	if _, err := Render(restricted(), MaxSudoRSUID+1, SudoRS); !errors.Is(err, ErrUIDTooLarge) || err.Error() != "uid exceeds sudo-rs limit" {
		t.Fatalf("10-digit UID under sudo-rs: %v", err)
	}
	if _, err := Render(restricted(), MaxSudoRSUID+1, Classic); err != nil {
		t.Fatalf("10-digit UID under classic sudo: %v", err)
	}
}

func TestValidateCommand(t *testing.T) {
	ok := []string{
		"/usr/bin/systemctl restart nginx.service", "/usr/bin/journalctl", "/usr/bin/apt-get update",
		`/usr/bin/foo ""`, "/usr/bin/foo a#b", // '#' only after whitespace is a comment, but it is refused anywhere
	}
	for _, c := range ok[:4] {
		if err := ValidateCommand(c); err != nil {
			t.Errorf("%q: %v", c, err)
		}
	}
	bad := []string{
		"", "systemctl restart x", "/usr/bin/x ALL", "ALL", "!/usr/bin/x", "/usr/bin/x !y", "/usr/bin/x a,b",
		"/usr/bin/x a:b", "/usr/bin/x a=b", `/usr/bin/x a\b`, "/usr/bin/x #y", ok[4], "/usr/bin/x\n/usr/bin/y",
		"/usr/bin/x \x00", " /usr/bin/x", "/usr/bin/x\ty", strings.Repeat("/x", 513),
	}
	for _, c := range bad {
		if err := ValidateCommand(c); !errors.Is(err, ErrCommand) {
			t.Errorf("%q accepted (%v)", c, err)
		}
	}
}

// TestValidateCommandRefusesPatterns: sudo regular expressions and globs widen a command, so every pattern character
// is refused anywhere, and the error names it (plan M3.1 decision 1).
func TestValidateCommandRefusesPatterns(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/systemctl ^.*$":       "'^'",
		"/usr/bin/systemctl restart x$": "'$'",
		"/usr/bin/systemctl restart *":  "'*'",
		"/usr/bin/systemctl restart ?":  "'?'",
		"/usr/bin/systemctl [a]":        "'['",
		"/usr/bin/systemctl a]":         "']'",
		"/usr/bin/syst?mctl status":     "'?'",
		"^/usr/bin/systemctl$":          "'^'",
	}
	for c, char := range cases {
		err := ValidateCommand(c)
		if !errors.Is(err, ErrCommand) || !strings.Contains(err.Error(), "character "+char+" is not allowed") {
			t.Errorf("%q: %v, want an error naming %s", c, err, char)
		}
	}
	// The device renderer refuses the same input.
	e := restricted()
	e.Commands = []string{"/usr/bin/systemctl ^.*$"}
	for _, flavor := range Flavors {
		if out, err := Render(e, 1000, flavor); !errors.Is(err, ErrCommand) || out != nil {
			t.Errorf("%s rendered a pattern command (%v):\n%s", flavor, err, out)
		}
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Entry)
		want   error
	}{
		"username with space":     {func(e *Entry) { e.Username = "dave smith" }, ErrUsername},
		"username with newline":   {func(e *Entry) { e.Username = "dave\nALL ALL=(ALL) ALL" }, ErrUsername},
		"uppercase username":      {func(e *Entry) { e.Username = "Dave@acme.test" }, ErrUsername},
		"class none":              {func(e *Entry) { e.Class = "none" }, ErrClass},
		"restricted without cmds": {func(e *Entry) { e.Commands = nil }, ErrNoCommands},
		"bad command":             {func(e *Entry) { e.Commands = []string{"/usr/bin/x, /bin/sh"} }, ErrCommand},
		"timeout too high":        {func(e *Entry) { e.TimestampTimeoutMin = 61 }, ErrScalars},
		"negative timeout":        {func(e *Entry) { e.TimestampTimeoutMin = -1 }, ErrScalars},
		"unknown lecture":         {func(e *Entry) { e.Lecture = "sometimes" }, ErrScalars},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := restricted()
			c.mutate(&e)
			if _, err := Render(e, 1, Classic); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestFileName(t *testing.T) {
	// The first 16 hex characters of sha256("dave@acme.test"); sudo ignores names with "." or a trailing "~".
	if got, want := FileName("dave@acme.test"), "paddock-u-a26ce0163b541088"; got != want {
		t.Fatalf("file name %q, want %q", got, want)
	}
	if FileName("dave") == FileName("dave@acme.test") {
		t.Fatal("different usernames share a file")
	}
}

func TestDigestIgnoresItself(t *testing.T) {
	a := restricted()
	b := a
	b.ProfileDigest = ""
	da, err := Digest(a)
	if err != nil {
		t.Fatal(err)
	}
	db, _ := Digest(b)
	if da != db || len(da) != 64 {
		t.Fatalf("digest %s vs %s", da, db)
	}
	b.TimestampTimeoutMin++
	if dc, _ := Digest(b); dc == da {
		t.Fatal("digest does not cover the scalars")
	}
}

// TestRenderedFilesPassVisudo checks every rendered variant with the host's visudo (the compiler repeats this check
// in its container before signing, gate P1).
func TestRenderedFilesPassVisudo(t *testing.T) {
	visudo := visudoPath(t)
	entries := []Entry{
		restricted(),
		{Username: "erin@acme.test", Class: ClassFull, RequirePassword: true, TimestampTimeoutMin: 0, Lecture: LectureOnce},
		{Username: "frank@acme.test", Class: ClassFull, Lecture: LectureNever, TimestampTimeoutMin: 60},
		{Username: "gina@acme.test", Class: ClassRestricted, Commands: []string{`/usr/bin/foo ""`, "/usr/bin/x a(b) {c}"},
			Lecture: LectureAlways},
	}
	for _, e := range entries {
		out, err := Render(e, PlaceholderUID, Classic)
		if err != nil {
			t.Fatal(err)
		}
		checkVisudo(t, visudo, out)
	}
}

func visudoPath(t testing.TB) string {
	t.Helper()
	for _, p := range []string{"/usr/sbin/visudo", "/sbin/visudo"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("visudo"); err == nil {
		return p
	}
	t.Skip("visudo not installed on this host; gate P1 checks the rendered files in the compiler container")
	return ""
}

func checkVisudo(t testing.TB, visudo string, content []byte) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "paddock-u-test")
	if err := os.WriteFile(f, content, 0o440); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(visudo, "-cf", f).CombinedOutput(); err != nil { //nolint:gosec // test binary path
		t.Fatalf("visudo rejects\n%s\n%s", content, out)
	}
}

// FuzzRender: whatever Render accepts is three lines, and the command line holds exactly the commands it was given.
func FuzzRender(f *testing.F) {
	f.Add("dave@acme.test", "/usr/bin/systemctl restart nginx.service", "/usr/bin/journalctl", 5, true)
	f.Add("x", "/a b c", "/usr/bin/x a#b", 0, false)
	f.Fuzz(func(t *testing.T, user, c1, c2 string, timeout int, password bool) {
		e := Entry{Username: user, Class: ClassRestricted, Commands: []string{c1, c2}, RequirePassword: password,
			TimestampTimeoutMin: timeout, Lecture: LectureOnce}
		out, err := Render(e, 1000, Classic)
		if err != nil {
			return
		}
		rs, err := Render(e, 1000, SudoRS)
		if err != nil || string(rs) != strings.Replace(string(out), ", lecture_file="+LectureFile, "", 1) {
			t.Fatalf("sudo-rs differs beyond lecture_file (%v):\n%s\n%s", err, rs, out)
		}
		lines := bytes.Split(bytes.TrimSuffix(out, []byte("\n")), []byte("\n"))
		if len(lines) != 3 {
			t.Fatalf("%d lines:\n%s", len(lines), out)
		}
		prefix := "#1000 ALL=(root) "
		if !password {
			prefix += "NOPASSWD: "
		}
		if string(lines[2]) != prefix+c1+", "+c2 {
			t.Fatalf("command line %q", lines[2])
		}
	})
}
