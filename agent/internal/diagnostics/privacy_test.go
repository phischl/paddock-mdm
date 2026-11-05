package diagnostics

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/desktop"
)

// privacySection is the heading of the diagnostics section of the privacy document (plan M12 decision 15).
const privacySection = "## Diagnostics bundle (on request only)"

// privacyDiagnostics returns the diagnostics section of docs/compliance/privacy.md.
func privacyDiagnostics(t *testing.T) string {
	t.Helper()
	doc, err := os.ReadFile("../../../docs/compliance/privacy.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(doc), "\n"+privacySection+"\n")
	if !ok {
		t.Fatalf("privacy.md has no section %q", privacySection)
	}
	section, _, _ = strings.Cut(section, "\n## ")
	return section
}

// privacyRow is the archive name and the source of a content list row as the privacy document shows it.
func privacyRow(name, source string) string { return "| `" + name + "` | `" + source + "` |" }

// TestPrivacyDocumentListsEntries is C7 of plan M12: the content list of the privacy document, which works councils
// read, names every entry of Entries() with its source, in order, and nothing else.
func TestPrivacyDocumentListsEntries(t *testing.T) {
	var got []string
	for _, line := range strings.Split(privacyDiagnostics(t), "\n") {
		if !strings.HasPrefix(line, "| `") {
			if strings.HasPrefix(line, "|") && !strings.HasPrefix(line, "| Archive file") && !strings.HasPrefix(line, "| ---") {
				t.Fatalf("table row the content list check does not read: %s", line)
			}
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 4 {
			t.Fatalf("content list row without a source: %s", line)
		}
		got = append(got, privacyRow(strings.Trim(strings.TrimSpace(cells[1]), "`"), strings.Trim(strings.TrimSpace(cells[2]), "`")))
	}
	var want []string
	for _, e := range Entries() {
		want = append(want, privacyRow(e.Name, e.Source))
	}
	if !slices.Equal(got, want) {
		t.Errorf("the content list of privacy.md differs from Entries(); its first two columns must read:\n%s\ngot:\n%s",
			strings.Join(want, "\n"), strings.Join(got, "\n"))
	}
}

// signedUnitState is the signed list of unit fields of systemd/status.txt (decision of 2026-11-05 on PDK-791): the
// states ActiveState, SubState, Result, ExecMainStatus and timestamps.
func signedUnitState(property string) bool {
	return slices.Contains([]string{"ActiveState", "SubState", "Result", "ExecMainStatus"}, property) ||
		strings.HasSuffix(property, "Timestamp")
}

// TestUnitStateFieldsSigned: every unit field systemd/status.txt collects is on the signed list, and the privacy
// document's row of the entry names each of them.
func TestUnitStateFieldsSigned(t *testing.T) {
	if len(UnitStateProperties) == 0 {
		t.Fatal("no unit state properties")
	}
	var row string
	for _, line := range strings.Split(privacyDiagnostics(t), "\n") {
		if strings.HasPrefix(line, "| `systemd/status.txt` |") {
			row = line
		}
	}
	if row == "" {
		t.Fatal("privacy.md has no row for systemd/status.txt")
	}
	cells := strings.Split(row, "|")
	for _, p := range UnitStateProperties {
		if !signedUnitState(p) {
			t.Errorf("systemd/status.txt collects %s, which is not on the signed list", p)
		}
		if !strings.Contains(cells[3], "`"+p+"`") {
			t.Errorf("the privacy.md row of systemd/status.txt does not name %s", p)
		}
	}
}

// TestPrivacyDocumentNotice: the privacy document quotes the notice the device shows, in both languages, with the
// placeholder <reason> for the administrator's text.
func TestPrivacyDocumentNotice(t *testing.T) {
	section := privacyDiagnostics(t)
	const reason = "REASON"
	for _, lang := range []string{desktop.English, desktop.German} {
		summary, body := Notice(lang, reason)
		for _, want := range []string{summary, strings.Replace(body, reason, "<reason>", 1)} {
			if !strings.Contains(section, want) {
				t.Errorf("privacy.md does not quote the %s notice %q", lang, want)
			}
		}
	}
}
