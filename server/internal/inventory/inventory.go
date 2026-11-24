// Package inventory holds Paddock's inventory policies (plan M5a decision 8) and the severity scale of
// vulnerability findings. Policies are osquery SQL that returns rows when a host passes; the inventory system turns
// the answer into pass or fail and never stores the rows. There is no NTP policy: osquery has no table for the time
// synchronization state on Linux.
package inventory

import (
	"embed"
	"io/fs"
	"log/slog"
	"path"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/server/internal/ports"
)

//go:embed policies/*.sql
var policyFiles embed.FS

// PolicyAgentRunning is the key of the mutual watch policy: paddockd runs.
const PolicyAgentRunning = "paddock_agent_running"

// PolicyAgentBinaryKnown is the key of the agent binary hash policy (plan M5a amendments 2026-11-16, ADR 0056 part
// A): every running Paddock agent process runs a published agent release.
const PolicyAgentBinaryKnown = "paddock_agent_binary_known"

// isAgentHash reports whether h has the form of a published agent artifact hash, ^[0-9a-f]{64}$; only this form is
// ever interpolated into the policy.
func isAgentHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// KnownAgentHashes returns the hashes the binary policy accepts: sorted, deduplicated, and only those of the form
// ^[0-9a-f]{64}$. Every other value is dropped and logged at Error, defense in depth before the values are put into
// SQL (the database already constrains agent_artifact.sha256).
func KnownAgentHashes(hashes []string) []string {
	out := make([]string, 0, len(hashes))
	for _, h := range hashes {
		if !isAgentHash(h) {
			slog.Error("dropping an invalid agent artifact hash from the binary policy", "length", len(h))
			continue
		}
		out = append(out, h)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// AgentBinaryPolicy builds the policy PolicyAgentBinaryKnown from the published agent artifact hashes (plan M5a
// amendment 2026-11-16, review round 1, A8): it fails while a judged process runs an executable whose SHA-256 is none
// of the hashes. Judged is every process named paddockd, running a file named paddockd or a file below
// /opt/paddock/agent/, or started by paddock-supervisor (other than before its exec), also by a supervisor whose file
// was renamed over (plan M5a addendum 2026-11-16, review round 2, A12). The hash is that of
// /proc/<pid>/exe, the executable the process actually runs, with its path as fallback for a process that exits during
// the evaluation. No judged process passes (that is paddock_agent_running's case). With no valid hash the policy is
// SELECT 1;, which always passes.
func AgentBinaryPolicy(hashes []string) ports.PolicyDefinition {
	def := ports.PolicyDefinition{
		Key: PolicyAgentBinaryKnown,
		Description: "A running Paddock agent process runs a published agent release (plan M5a amendments 2026-11-16, " +
			"ADR 0056). The policy returns pass or fail only, never a hash.",
		Query: "SELECT 1;",
	}
	known := KnownAgentHashes(hashes)
	if len(known) == 0 {
		return def
	}
	def.Query = "SELECT 1 WHERE NOT EXISTS (\n" +
		"  SELECT 1 FROM processes p\n" +
		"  WHERE p.path != ''\n" +
		"    AND (p.name = 'paddockd' OR p.path LIKE '%/paddockd' OR p.path LIKE '%/paddockd (deleted)'\n" +
		"      OR p.path LIKE '/opt/paddock/agent/%'\n" +
		"      OR (p.parent IN (SELECT pid FROM processes\n" +
		"            WHERE path IN ('/usr/sbin/paddock-supervisor', '/usr/sbin/paddock-supervisor (deleted)'))\n" +
		"        AND p.path NOT IN ('/usr/sbin/paddock-supervisor', '/usr/sbin/paddock-supervisor (deleted)')))\n" +
		"    AND COALESCE((SELECT sha256 FROM hash WHERE path = '/proc/' || p.pid || '/exe'),\n" +
		"      (SELECT sha256 FROM hash WHERE path = p.path), '') NOT IN ('" + strings.Join(known, "', '") + "'));"
	return def
}

// UnansweredAgentRunningAsFailing returns inv with PolicyAgentRunning moved from UnansweredPolicies to Policies as
// failing when gateOpen, otherwise inv unchanged (plan M5a amendment 2026-11-16 d, F6): the policy's query text never
// changes, so after the first evaluation of its definition an empty answer means the query failed on the host.
func UnansweredAgentRunningAsFailing(inv ports.HostInventory, gateOpen bool) ports.HostInventory {
	n := slices.Index(inv.UnansweredPolicies, PolicyAgentRunning)
	if !gateOpen || n < 0 {
		return inv
	}
	inv.UnansweredPolicies = slices.Delete(slices.Clone(inv.UnansweredPolicies), n, n+1)
	inv.Policies = append(slices.Clone(inv.Policies), ports.PolicyResult{Key: PolicyAgentRunning, Passing: false})
	return inv
}

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
