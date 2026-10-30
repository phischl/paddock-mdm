package main

import (
	"os"
	"strings"
	"testing"
)

func TestShapeAndLatest(t *testing.T) {
	cases := []struct {
		pinned string
		tags   []string
		want   string
	}{
		{"2.11.6", []string{"2.11.6", "2.12.0-beta.1", "2.11.6-alpine", "2.11.5", "latest"}, "2.11.6"},
		{"4.3.6-management", []string{"4.3.6", "4.3.7-management", "4.4.0-management-alpine", "4.3.10-management", "4.3.9-management"}, "4.3.10-management"},
		{"qemu-v10.2.3-68", []string{"qemu-v10.2.4-70", "qemu-v10.2.3-68", "desktop-v10.3.0-1", "qemu-v10.2.4-70-rc"}, "qemu-v10.2.4-70"},
		{"4.9.9", []string{"4.9.9", "4.10.0", "4.2.11"}, "4.10.0"},
		{"v4.92.3", []string{"4.93.0", "v4.93.0", "v4.92.4"}, "v4.93.0"},
		{"1.27.2-trixie", []string{"1.27.3-bookworm", "1.27.3-trixie", "1.28rc1-trixie"}, "1.27.3-trixie"},
		{"2.11.6", []string{"latest", "alpine"}, ""},
		{"8.4.11", InLine([]string{"8.4.13", "9.7.4", "26.10.0", "8.4.12"}, "8.4."), "8.4.13"},
		{"8.4.11", []string{"8.4.13", "9.7.4", "26.10.0", "8.4.12"}, "26.10.0"},
		{"8.4.11", InLine([]string{"9.7.4", "26.10.0", "8.40.1"}, "8.4."), ""},
	}
	for _, c := range cases {
		if got := Latest(c.pinned, c.tags); got != c.want {
			t.Errorf("Latest(%q) = %q, want %q", c.pinned, got, c.want)
		}
	}
	if re := Shape("v4.92.3"); re.String() != `^v\d+\.\d+\.\d+$` {
		t.Errorf("Shape = %s", re)
	}
}

func TestInLine(t *testing.T) {
	tags := []string{"8.4.13", "9.7.4", "26.10.0", "8.4.12"}
	if got := InLine(tags, ""); strings.Join(got, " ") != "8.4.13 9.7.4 26.10.0 8.4.12" {
		t.Errorf("InLine without line = %v", got)
	}
	if got := InLine(tags, "8.4."); strings.Join(got, " ") != "8.4.13 8.4.12" {
		t.Errorf("InLine 8.4. = %v", got)
	}
	if got := InLine(tags, "10."); len(got) != 0 {
		t.Errorf("InLine 10. = %v", got)
	}
}

func TestCompareTagsNumeric(t *testing.T) {
	if CompareTags("4.10.0", "4.9.9") <= 0 || CompareTags("4.9.9", "4.10.0") >= 0 || CompareTags("1.2.3", "1.2.3") != 0 {
		t.Fatal("numeric ordering broken")
	}
}

func TestClassify(t *testing.T) {
	cases := []struct{ pinned, latest, want string }{
		{"2.11.6", "2.11.7", ClassPatch},
		{"8.4.11", "8.4.13", ClassPatch},
		{"8.4.11", "26.10.0", ClassMajor},
		{"2.11.6", "2.12.0", ClassMinor},
		{"2.11.6", "3.0.0", ClassMajor},
		{"2.11.6", "2.11.6", ClassOK},
		{"2.11.6", "2.11.5", ClassOK},
		{"2.11.6", "", ClassOK},
		{"17.11", "17.12", ClassPatch},
		{"17.11", "18.0", ClassMajor},
		{"202610120101", "202610180059", ClassPatch},
		{"qemu-v10.2.3-68", "qemu-v10.2.4-70", ClassMinor},
		{"qemu-v10.2.3-68", "qemu-v10.2.3-70", ClassPatch},
	}
	for _, c := range cases {
		if got := Classify(c.pinned, c.latest); got != c.want {
			t.Errorf("Classify(%q, %q) = %s, want %s", c.pinned, c.latest, got, c.want)
		}
	}
}

func TestHimmelblauIndex(t *testing.T) {
	html, err := os.ReadFile("testdata/himmelblau-index.html")
	if err != nil {
		t.Fatal(err)
	}
	latest, err := HimmelblauLatest(string(html))
	if err != nil || latest != "4.0.6" {
		t.Fatalf("HimmelblauLatest = %q, %v; want 4.0.6", latest, err)
	}
	if got := Classify("4.0.4", latest); got != ClassPatch {
		t.Fatalf("Classify = %s, want patch", got)
	}
	if _, err := HimmelblauLatest("<html>nothing</html>"); err == nil {
		t.Fatal("empty index accepted")
	}
}

func TestParseLatestRelease(t *testing.T) {
	b, err := os.ReadFile("testdata/release.json")
	if err != nil {
		t.Fatal(err)
	}
	if tag, err := ParseLatestRelease(b); err != nil || tag != "202610180059" {
		t.Fatalf("ParseLatestRelease = %q, %v", tag, err)
	}
	if _, err := ParseLatestRelease([]byte(`{}`)); err == nil {
		t.Fatal("release without tag accepted")
	}
}
