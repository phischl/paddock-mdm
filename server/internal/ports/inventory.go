package ports

import (
	"context"
	"time"
)

// HostRef identifies a host of the inventory system; it is opaque outside the adapter and stored only as
// device_inventory_ref.external_id (ADR 0009).
type HostRef string

// InventoryHost is a host of the inventory system as the sync round lists it.
type InventoryHost struct {
	Ref          HostRef
	HardwareUUID string
	// ChangedAt is the newest change of the host's details, software or policy results the inventory system recorded.
	ChangedAt time.Time
}

// HostSeen is one listed host of the inventory system that has a hardware UUID (ADR 0057).
type HostSeen struct {
	Ref          HostRef
	HardwareUUID string
	// SeenAt is the host's last contact in the inventory system's clock; zero when it reports none.
	SeenAt time.Time
	// EnrolledAt is the host's latest enrollment; nil when unknown.
	EnrolledAt *time.Time
	// PolicyUpdatedAt is when the host last stored policy results, in the inventory system's clock; nil when it never
	// did (plan M5a amendment 2026-11-16 d, F5).
	PolicyUpdatedAt *time.Time
}

// HostPage is one page of hosts; Next is the cursor of the next page, "" after the last one. Seen holds every host of
// the page with a hardware UUID, changed or not, in list order.
type HostPage struct {
	Hosts []InventoryHost
	Seen  []HostSeen
	Next  string
}

// HostInventory is what Paddock stores of a mapped host (plan M5a decision 6).
type HostInventory struct {
	OSVersion string
	// AgentVersion is the version of the inventory agent (fleetd, else osquery).
	AgentVersion string
	LastSeenAt   *time.Time
	// PolicyUpdatedAt is when the host last evaluated its policies; nil when the inventory system reports none.
	PolicyUpdatedAt *time.Time
	Software        []SoftwarePackage
	// Policies are the results of the policies the host has answered.
	Policies []PolicyResult
	// UnansweredPolicies are the keys of the policies the inventory system lists for the host without a pass or fail
	// answer: not yet evaluated since the policy changed, or the query did not run (plan M5a amendment 2026-11-16,
	// review round 1, A7).
	UnansweredPolicies []string
	Hardware           HostHardware
}

// HostHardware are the asset facts of a host (ADR 0037 decision 7): empty strings and zero values when the
// inventory system does not report them.
type HostHardware struct {
	Vendor, Model, Serial, CPUBrand string
	CPUCores                        int
	MemoryBytes, DiskTotalBytes     int64
}

// SoftwarePackage is one installed package with the vulnerabilities matched to it.
type SoftwarePackage struct {
	Name, Version, Source string
	Vulnerabilities       []Vulnerability
}

// Vulnerability is a CVE matched to a package; CVSSScore and FixedVersion are unknown (nil, "") where the inventory
// system does not provide them (Fleet free).
type Vulnerability struct {
	CVE          string
	CVSSScore    *float64
	FixedVersion string
}

// PolicyResult is the pass/fail answer of a host to one policy.
type PolicyResult struct {
	Key     string
	Passing bool
}

// PolicyDefinition is a pass/fail policy Paddock defines (server/internal/inventory/policies).
type PolicyDefinition struct {
	Key, Description, Query string
}

// Inventory is the inventory system (Fleet, architecture §15).
type Inventory interface {
	// ListHostsChangedSince returns a page of hosts whose details, software or policy results changed at or after
	// since (every host for the zero time); cursor is "" for the first page.
	ListHostsChangedSince(ctx context.Context, since time.Time, cursor string) (HostPage, error)
	// HostInventory returns a host's OS, agent version, software with vulnerabilities and policy results.
	HostInventory(ctx context.Context, ref HostRef) (HostInventory, error)
	// VulnerabilityState returns an opaque value that changes whenever the inventory system's vulnerability matches
	// change; it matches them on its own schedule, without marking the hosts as changed.
	VulnerabilityState(ctx context.Context) (string, error)
	// ApplyPolicies creates or updates Paddock's policies (idempotent).
	ApplyPolicies(ctx context.Context, policies []PolicyDefinition) error
}

// InventoryBinder resolves a device token to the host that registered it (ADR 0057).
type InventoryBinder interface {
	// ResolveDeviceToken returns the host the token identifies and its hardware UUID. An error wrapping
	// problem.NotFound means the inventory system knows no host for the token (unknown or older than its lifetime);
	// problem.UpstreamUnavailable that it failed or could not be reached. Errors never contain the token.
	ResolveDeviceToken(ctx context.Context, token string) (HostRef, string, error)
}

// InventoryAdmin deletes hosts from the inventory system (retention of retired devices, ADR 0032).
type InventoryAdmin interface {
	// DeleteHost removes a host; a host that no longer exists is not an error. An error wrapping
	// problem.UpstreamUnavailable means the inventory system failed or could not be reached; problem.InvalidState means
	// it refused this one host.
	DeleteHost(ctx context.Context, ref HostRef) error
	// HostSeenAt returns when the host last checked in; the zero time for a host that never did or no longer exists.
	// Its errors are classified like DeleteHost's.
	HostSeenAt(ctx context.Context, ref HostRef) (time.Time, error)
}
