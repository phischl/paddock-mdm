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

// HostPage is one page of hosts; Next is the cursor of the next page, "" after the last one.
type HostPage struct {
	Hosts []InventoryHost
	Next  string
}

// HostInventory is what Paddock stores of a mapped host (plan M5a decision 6).
type HostInventory struct {
	OSVersion string
	// AgentVersion is the version of the inventory agent (fleetd, else osquery).
	AgentVersion string
	LastSeenAt   *time.Time
	Software     []SoftwarePackage
	// Policies are the results of the policies the host has answered.
	Policies []PolicyResult
	Hardware HostHardware
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
