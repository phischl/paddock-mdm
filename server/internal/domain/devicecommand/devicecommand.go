// Package devicecommand holds the server-side rules of device commands (plan M4a decisions 1–3): their states and
// the command.issued message that tells the worker to sign and deliver a new command. The command types and the
// signed payload are in pkg/command.
package devicecommand

import (
	"strings"

	"github.com/google/uuid"
)

// States of a command.
const (
	StatusPending   = "pending"
	StatusDelivered = "delivered"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusExpired   = "expired"
	StatusCancelled = "cancelled"
)

// Statuses are all states, in lifecycle order.
var Statuses = []string{StatusPending, StatusDelivered, StatusSucceeded, StatusFailed, StatusExpired, StatusCancelled}

// Issued is the payload of the outbox message command.<organization_id>: the worker signs the command and publishes
// it to the device (plan M4a decision 2).
type Issued struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	CommandID      uuid.UUID `json:"command_id"`
}

const subjectPrefix = "command."

// Subject is the outbox subject of a command.issued message of org.
func Subject(org uuid.UUID) string { return subjectPrefix + org.String() }

// ParseSubject returns the organization of a command.issued subject.
func ParseSubject(subject string) (uuid.UUID, bool) {
	rest, ok := strings.CutPrefix(subject, subjectPrefix)
	if !ok {
		return uuid.Nil, false
	}
	org, err := uuid.Parse(rest)
	return org, err == nil
}
