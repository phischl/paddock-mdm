package osv

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// fixture is a zip of the real OSV records in testdata, written as layout writes them.
func fixture(t *testing.T, layout func(w *zip.Writer, name string, body []byte) error) []byte {
	t.Helper()
	files, err := filepath.Glob("testdata/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("testdata: %v", err)
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := layout(w, filepath.Base(f), body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// streamed writes entries with a data descriptor (archive/zip's default).
func streamed(w *zip.Writer, name string, body []byte) error {
	f, err := w.Create(name)
	if err == nil {
		_, err = f.Write(body)
	}
	return err
}

// sized writes deflated entries with their sizes in the local header, as the OSV bucket's zip has them.
func sized(w *zip.Writer, name string, body []byte) error {
	var c bytes.Buffer
	fw, _ := flate.NewWriter(&c, flate.DefaultCompression)
	if _, err := fw.Write(body); err != nil {
		return err
	}
	if err := fw.Close(); err != nil {
		return err
	}
	f, err := w.CreateRaw(&zip.FileHeader{Name: name, Method: zip.Deflate, CRC32: crc32.ChecksumIEEE(body),
		CompressedSize64: uint64(c.Len()), UncompressedSize64: uint64(len(body))})
	if err == nil {
		_, err = f.Write(c.Bytes())
	}
	return err
}

// stored writes uncompressed entries with their sizes in the local header.
func stored(w *zip.Writer, name string, body []byte) error {
	f, err := w.CreateRaw(&zip.FileHeader{Name: name, Method: zip.Store, CRC32: crc32.ChecksumIEEE(body),
		CompressedSize64: uint64(len(body)), UncompressedSize64: uint64(len(body))})
	if err == nil {
		_, err = f.Write(body)
	}
	return err
}

func readAll(t *testing.T, data []byte) ([]Entry, Stats) {
	t.Helper()
	var got []Entry
	st, err := Read(bytes.NewReader(data), func(e Entry) error {
		got = append(got, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(got, func(i, j int) bool {
		return got[i].CVE+got[i].Release+got[i].Package < got[j].CVE+got[j].Release+got[j].Package
	})
	return got, st
}

func TestReadFixture(t *testing.T) {
	ts := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	uaBinaries := []string{"ubuntu-advantage-pro", "ubuntu-advantage-tools", "ubuntu-pro-auto-attach", "ubuntu-pro-client", "ubuntu-pro-client-l10n"}
	want := []Entry{
		// Negligible priority, not fixed, in both managed releases.
		{CVE: "CVE-2008-5144", Release: "24.04", Package: "nvidia-cg-toolkit", Binaries: []string{"libcg", "libcggl", "nvidia-cg-toolkit"},
			Priority: "negligible", Modified: ts("2026-05-20T16:03:03.987367696Z")},
		{CVE: "CVE-2008-5144", Release: "26.04", Package: "nvidia-cg-toolkit", Binaries: []string{"libcg", "libcggl", "nvidia-cg-toolkit"},
			Priority: "negligible", Modified: ts("2026-05-20T16:03:03.987367696Z")},
		// No priority at all; a CVSS vector only.
		{CVE: "CVE-2008-7320", Release: "24.04", Package: "seahorse", CVSSVector: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Modified: ts("2018-11-18T19:29:00Z")},
		// The priority of the affected package (ecosystem_specific.ubuntu_priority) where the record has none.
		{CVE: "CVE-2014-3495", Release: "24.04", Package: "duplicity", Priority: "low",
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", Modified: ts("2026-02-04T02:53:32.568918Z")},
		// Ubuntu's priority without its type.
		{CVE: "CVE-2020-36123", Release: "24.04", Package: "libsixel", Priority: "medium",
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", Modified: ts("2025-07-08T14:32:20.906105Z")},
		// Fixed in 24.04; 22.04 is not a managed release.
		{CVE: "CVE-2024-6387", Release: "24.04", Package: "openssh",
			Binaries: []string{"openssh-client", "openssh-server", "openssh-sftp-server", "openssh-tests", "ssh", "ssh-askpass-gnome"},
			Priority: "high", FixedVersion: "1:9.6p1-3ubuntu13.3", CVSSVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Modified: ts("2026-02-04T04:18:00.629884Z")},
		// Different fixed versions per release; interim 25.10 is left out.
		{CVE: "CVE-2026-11386", Release: "24.04", Package: "ubuntu-advantage-tools", Binaries: uaBinaries, Priority: "high",
			FixedVersion: "37.2ubuntu~24.04.1", CVSSVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
			Modified: ts("2026-07-29T10:18:31.954474526Z")},
		{CVE: "CVE-2026-11386", Release: "26.04", Package: "ubuntu-advantage-tools", Binaries: uaBinaries, Priority: "high",
			FixedVersion: "37.2ubuntu0.1", CVSSVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
			Modified: ts("2026-07-29T10:18:31.954474526Z")},
	}
	for name, layout := range map[string]func(*zip.Writer, string, []byte) error{
		"data descriptor": streamed, "sizes in the header": sized, "stored": stored,
	} {
		t.Run(name, func(t *testing.T) {
			got, st := readAll(t, fixture(t, layout))
			if !reflect.DeepEqual(got, want) {
				t.Errorf("entries\n got %+v\nwant %+v", got, want)
			}
			if st != (Stats{Records: 6, Skipped: 1, Entries: len(want)}) {
				t.Errorf("stats %+v", st)
			}
		})
	}
}

func TestReadDamaged(t *testing.T) {
	data := fixture(t, sized)
	for name, damaged := range map[string][]byte{
		"truncated":        data[:len(data)/2],
		"truncated header": data[:20],
		"no end record":    data[:len(data)-30],
		"empty":            {},
		"not a zip":        []byte("<html>not found</html>"),
		"flipped byte":     flip(data, 200),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Read(bytes.NewReader(damaged), func(Entry) error { return nil }); err == nil {
				t.Error("no error")
			}
		})
	}
	t.Run("callback error stops", func(t *testing.T) {
		calls := 0
		_, err := Read(bytes.NewReader(data), func(Entry) error {
			calls++
			return io.ErrClosedPipe
		})
		if err != io.ErrClosedPipe || calls != 1 {
			t.Errorf("err %v after %d calls", err, calls)
		}
	})
}

func flip(data []byte, at int) []byte {
	out := bytes.Clone(data)
	out[at] ^= 0xff
	return out
}

func TestParseRecordOtherSchema(t *testing.T) {
	entries, ok, err := parseRecord([]byte(`{"id":"UBUNTU-CVE-2030-1","schema_version":"2.0.0","affected":[]}`))
	if err != nil || ok || entries != nil {
		t.Errorf("entries %v ok %v err %v", entries, ok, err)
	}
	if _, _, err := parseRecord([]byte(`{"id":"UBUNTU-XYZ-1","schema_version":"1.7.0"}`)); err == nil || !strings.Contains(err.Error(), "not a CVE") {
		t.Errorf("err %v", err)
	}
}

// TestReadFeed reads a downloaded bulk zip of the real feed (PADDOCK_OSV_ZIP), streaming it like the worker does.
func TestReadFeed(t *testing.T) {
	path := os.Getenv("PADDOCK_OSV_ZIP")
	if path == "" {
		t.Skip("PADDOCK_OSV_ZIP not set")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	releases := map[string]int{}
	st, err := Read(f, func(e Entry) error {
		releases[e.Release]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("stats %+v, entries per release %v", st, releases)
	if st.Records < 10000 || releases["24.04"] == 0 || releases["26.04"] == 0 {
		t.Errorf("stats %+v releases %v", st, releases)
	}
}
