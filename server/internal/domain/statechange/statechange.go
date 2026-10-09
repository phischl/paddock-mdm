// Package statechange defines the event that tells the compiler which devices may need a new bundle
// (architecture §7.1, plan M2a decision 13). It travels through the outbox to exchange paddock.state.
package statechange

import (
	"strings"

	"github.com/google/uuid"
)

// Scopes of a state change.
const (
	ScopeOrg         = "org"          // every device of the organization
	ScopeDeviceGroup = "device_group" // the members of one device group
	ScopeDevice      = "device"       // one device
	ScopeUser        = "user"         // the devices affected by one user (plan M3a decision 10)
)

// Event is the payload of a state change. Priority events (user lock and unlock, login suspension) go to the
// priority lane, which the compiler serves without debounce (architecture §9.5).
type Event struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	Scope          string    `json:"scope"`
	ID             uuid.UUID `json:"id"` // organization, device group, device or user ID
	Priority       bool      `json:"priority,omitempty"`
	// Force publishes a new bundle version even when the rendered content equals the device's latest bundle (restore
	// after a database restore, plan M6c decision 19).
	Force bool `json:"force,omitempty"`
}

// Subject prefixes: state.<organization_id> and state.priority.<organization_id>.
const (
	subjectPrefix         = "state."
	prioritySubjectPrefix = "state.priority."
)

// Subject is the outbox subject of e.
func Subject(e Event) string {
	if e.Priority {
		return prioritySubjectPrefix + e.OrganizationID.String()
	}
	return subjectPrefix + e.OrganizationID.String()
}

// ParseSubject returns the organization of a state change subject and whether it belongs to the priority lane.
func ParseSubject(subject string) (org uuid.UUID, priority bool, ok bool) {
	rest, ok := strings.CutPrefix(subject, prioritySubjectPrefix)
	if ok {
		priority = true
	} else if rest, ok = strings.CutPrefix(subject, subjectPrefix); !ok {
		return uuid.Nil, false, false
	}
	org, err := uuid.Parse(rest)
	return org, priority, err == nil
}

// Valid reports whether e has a known scope and IDs.
func (e Event) Valid() bool {
	switch e.Scope {
	case ScopeOrg, ScopeDeviceGroup, ScopeDevice, ScopeUser:
		return e.OrganizationID != uuid.Nil && e.ID != uuid.Nil
	}
	return false
}
