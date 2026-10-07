// Package inventory holds Paddock's inventory policies (plan M5a decision 8) and the severity scale of
// vulnerability findings. Policies are osquery SQL that returns rows when a host passes; the inventory system turns
// the answer into pass or fail and never stores the rows. There is no NTP policy: osquery has no table for the time
// synchronization state on Linux.
package inventory

import (
	"embed"
	"io/fs"
	"path"
	"strings"

	"github.com/phischl/paddock-mdm/server/internal/ports"
)

//go:embed policies/*.sql
var policyFiles embed.FS

// PolicyAgentRunning is the key of the mutual watch policy: paddockd runs.
const PolicyAgentRunning = "paddock_agent_running"

// Policies returns Paddock's policies, sorted by key; the key is the file name, the description its leading comment.
func Policies() ([]ports.PolicyDefinition, error) {
	names, err := fs.Glob(policyFiles, "policies/*.sql")
	if err != nil {
		return nil, err
	}
	out := make([]ports.PolicyDefinition, 0, len(names))
	for _, name := range names {
		data, err := policyFiles.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var comment, query []string
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if c, ok := strings.CutPrefix(line, "-- "); ok && len(query) == 0 {
				comment = append(comment, c)
				continue
			}
			query = append(query, line)
		}
		out = append(out, ports.PolicyDefinition{
			Key: strings.TrimSuffix(path.Base(name), ".sql"), Description: strings.Join(comment, " "),
			Query: strings.Join(query, "\n"),
		})
	}
	return out, nil
}

// Severities of vulnerability findings, from the CVSS v3 base score (NVD's qualitative rating).
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Severity rates a CVSS v3 base score; "" for an unknown score (Fleet free reports none) or 0.
func Severity(score *float64) string {
	switch {
	case score == nil || *score <= 0:
		return ""
	case *score >= 9:
		return SeverityCritical
	case *score >= 7:
		return SeverityHigh
	case *score >= 4:
		return SeverityMedium
	default:
		return SeverityLow
	}
}
