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
)

// Event is the payload of a state change.
type Event struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	Scope          string    `json:"scope"`
	ID             uuid.UUID `json:"id"` // organization, device group or device ID
}

// subjectPrefix starts the outbox subject state.<organization_id>.
const subjectPrefix = "state."

// Subject is the outbox subject of a state change of org.
func Subject(org uuid.UUID) string { return subjectPrefix + org.String() }

// ParseSubject returns the organization of a state change subject.
func ParseSubject(subject string) (uuid.UUID, bool) {
	rest, ok := strings.CutPrefix(subject, subjectPrefix)
	if !ok {
		return uuid.Nil, false
	}
	org, err := uuid.Parse(rest)
	return org, err == nil
}

// Valid reports whether e has a known scope and IDs.
func (e Event) Valid() bool {
	switch e.Scope {
	case ScopeOrg, ScopeDeviceGroup, ScopeDevice:
		return e.OrganizationID != uuid.Nil && e.ID != uuid.Nil
	}
	return false
}
