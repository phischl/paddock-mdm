// Package osv reads Ubuntu's vulnerability data in the OSV format (ADR 0020, plan M5c decision 1): the bulk zip of the
// OSV bucket's ecosystem Ubuntu, one JSON record (OSV schema 1.x) per CVE. The zip is read as a stream, so a download
// is parsed while it arrives and nothing is written to disk.
package osv

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Entry is what Paddock keeps of one affected package of a CVE in one Ubuntu release.
type Entry struct {
	CVE string
	// Release is the Ubuntu release, normalised to "24.04".
	Release string
	// Package is the Ubuntu source package; Binaries are the binary packages it builds, as the record lists them.
	Package  string
	Binaries []string
	// Priority is Ubuntu's priority (negligible, low, medium, high, critical or another value Ubuntu uses, such as
	// untriaged), "" if the record has none.
	Priority string
	// FixedVersion is the version that fixes the CVE in the release, "" while there is none.
	FixedVersion string
	// CVSSVector is the record's CVSS v3 vector (else its v4 vector), "" if it has none.
	CVSSVector string
	Modified   time.Time
}

// Stats counts what Read saw.
type Stats struct {
	// Records are the CVE records read, Skipped the records of another kind (USN, LSN) or schema.
	Records, Skipped int
	Entries          int
}

// minRelease is the oldest Ubuntu LTS release Paddock manages (C3); older releases, interim releases and the
// Ubuntu Pro ecosystems (FIPS, Realtime, …) are left out, which keeps the table at a few hundred thousand rows
// instead of tens of millions.
const minRelease = 24

// maxRecordSize bounds one decompressed record; the largest records of the feed have a few MiB.
const maxRecordSize = 64 << 20

// ltsEcosystem matches the ecosystems of the standard LTS releases, such as "Ubuntu:24.04:LTS".
var ltsEcosystem = regexp.MustCompile(`^Ubuntu:(\d\d)\.04:LTS$`)

// Read reads the bulk zip from r and calls fn for every affected package of a CVE in a managed release; an error of
// fn stops it. A damaged zip or record is an error: a partial feed must never replace complete data.
func Read(r io.Reader, fn func(Entry) error) (Stats, error) {
	var st Stats
	err := readZip(r, maxRecordSize, func(name string, body []byte) error {
		if !strings.HasPrefix(name, "UBUNTU-CVE-") || !strings.HasSuffix(name, ".json") {
			st.Skipped++
			return nil
		}
		entries, ok, err := parseRecord(body)
		if err != nil {
			return fmt.Errorf("osv record %s: %w", name, err)
		}
		if !ok {
			st.Skipped++
			return nil
		}
		st.Records++
		for _, e := range entries {
			if err := fn(e); err != nil {
				return err
			}
			st.Entries++
		}
		return nil
	})
	return st, err
}

// record is the part of an OSV record Paddock reads.
type record struct {
	ID            string     `json:"id"`
	SchemaVersion string     `json:"schema_version"`
	Modified      time.Time  `json:"modified"`
	Severity      []severity `json:"severity"`
	Affected      []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific struct {
			Binaries []struct {
				Name string `json:"binary_name"`
			} `json:"binaries"`
			UbuntuPriority string `json:"ubuntu_priority"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

type severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// priorities are the values of Ubuntu's priority scale.
var priorities = map[string]bool{"negligible": true, "low": true, "medium": true, "high": true, "critical": true}

// parseRecord returns the entries of a CVE record; ok is false for a record of another schema version.
func parseRecord(body []byte) ([]Entry, bool, error) {
	var rec record
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, false, err
	}
	if major, _, _ := strings.Cut(rec.SchemaVersion, "."); major != "1" {
		return nil, false, nil
	}
	cve := strings.TrimPrefix(rec.ID, "UBUNTU-")
	if !strings.HasPrefix(cve, "CVE-") {
		return nil, false, fmt.Errorf("id %q is not a CVE", rec.ID)
	}
	priority, vector := "", ""
	var v4 string
	for _, s := range rec.Severity {
		score := strings.TrimSpace(s.Score)
		switch s.Type {
		case "Ubuntu":
			priority = strings.ToLower(score)
		case "CVSS_V3":
			if vector == "" {
				vector = score
			}
		case "CVSS_V4":
			if v4 == "" {
				v4 = score
			}
		case "":
			// A few records of the feed carry Ubuntu's priority without its type; a CVSS score is always a vector.
			if p := strings.ToLower(score); priority == "" && priorities[p] {
				priority = p
			}
		}
	}
	if vector == "" {
		vector = v4
	}

	var out []Entry
	index := map[[2]string]int{}
	for _, a := range rec.Affected {
		m := ltsEcosystem.FindStringSubmatch(a.Package.Ecosystem)
		if m == nil {
			continue
		}
		if major, _ := strconv.Atoi(m[1]); major < minRelease {
			continue
		}
		pkg := strings.TrimSpace(a.Package.Name)
		if pkg == "" {
			continue
		}
		e := Entry{CVE: cve, Release: m[1] + ".04", Package: pkg, Priority: priority, CVSSVector: vector, Modified: rec.Modified}
		if p := strings.ToLower(strings.TrimSpace(a.EcosystemSpecific.UbuntuPriority)); p != "" {
			e.Priority = p
		}
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				if f := ev["fixed"]; f != "" && e.FixedVersion == "" {
					e.FixedVersion = f
				}
			}
		}
		for _, b := range a.EcosystemSpecific.Binaries {
			if b.Name != "" {
				e.Binaries = append(e.Binaries, b.Name)
			}
		}
		key := [2]string{e.Release, e.Package}
		if n, dup := index[key]; dup {
			// The same package twice in one release: keep one entry, with a fixed version if either has one.
			if out[n].FixedVersion == "" {
				out[n].FixedVersion = e.FixedVersion
			}
			out[n].Binaries = append(out[n].Binaries, e.Binaries...)
			continue
		}
		index[key] = len(out)
		out = append(out, e)
	}
	return out, true, nil
}
