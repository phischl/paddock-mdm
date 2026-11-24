package acceptance

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestFleetOSVArtifactMatchesTheGateFindings checks without a stack that the artifact gate F3 seeds into Fleet decodes
// into Fleet's OSVArtifact (v4.96.0) and lists each gate package version for its CVE, so that Fleet's exact version
// match finds it; Fleet refuses an artifact without vulnerabilities (PDK-1093).
func TestFleetOSVArtifactMatchesTheGateFindings(t *testing.T) {
	findings := []fleetOSVFinding{
		{acmeVulnerable[0], acmeVulnerable[1], acmeCVE, time.Date(2022, 5, 17, 18, 0, 0, 0, time.UTC)},
		{globexVulnerable[0], globexVulnerable[1], globexCVE, time.Date(2024, 2, 5, 15, 15, 0, 0, time.UTC)},
	}
	raw, err := fleetOSVArtifact(findings)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct {
		SchemaVersion   string    `json:"schema_version"`
		UbuntuVersion   string    `json:"ubuntu_version"`
		Generated       time.Time `json:"generated"`
		TotalCVEs       int       `json:"total_cves"`
		TotalPackages   int       `json:"total_packages"`
		Vulnerabilities map[string][]struct {
			CVE        string    `json:"cve"`
			Published  time.Time `json:"published"`
			Modified   time.Time `json:"modified"`
			Details    string    `json:"details"`
			Introduced string    `json:"introduced"`
			Fixed      string    `json:"fixed"`
			Versions   []string  `json:"versions"`
		} `json:"vulnerabilities"`
	}
	dec := json.NewDecoder(zr)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.SchemaVersion != "1.0" || artifact.UbuntuVersion != "24.04" || artifact.TotalCVEs != 2 ||
		artifact.TotalPackages != 2 || len(artifact.Vulnerabilities) != 2 {
		t.Errorf("artifact header %+v", artifact)
	}
	for _, f := range findings {
		vulns := artifact.Vulnerabilities[f.Package]
		if len(vulns) != 1 || vulns[0].CVE != f.CVE || !slices.Equal(vulns[0].Versions, []string{f.Version}) ||
			vulns[0].Fixed != "" || !vulns[0].Published.Equal(f.Published) {
			t.Errorf("%s: %+v", f.Package, vulns)
		}
	}
	if !isFleetOSVArtifactName(fleetOSVSeedName) {
		t.Errorf("Fleet does not read %s as an Ubuntu 24.04 artifact", fleetOSVSeedName)
	}
}

// isFleetOSVArtifactName is Fleet's selection of a local full Ubuntu 24.04 artifact (isArtifact with the version
// prefix, server/vulnerabilities/osv/artifact.go, v4.96.0).
func isFleetOSVArtifactName(name string) bool {
	const prefix, ext = "osv-ubuntu-2404-", ".json.gz"
	return strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ext) && !strings.Contains(name, "delta")
}
