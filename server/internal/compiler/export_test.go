package compiler

import (
	"context"

	"github.com/google/uuid"
)

// RecordWarningsAt records warnings with codes for device as a compile that saw bundle seq would, so a test can
// replay an outdated compile's write after a newer one.
func (c *Compiler) RecordWarningsAt(ctx context.Context, org, device uuid.UUID, seq int64, codes ...string) error {
	ws := make([]compileWarning, 0, len(codes))
	for _, code := range codes {
		ws = append(ws, compileWarning{code: code, params: map[string]any{}})
	}
	return c.recordWarnings(systemContext(ctx, org), org, map[uuid.UUID]deviceWarnings{device: {seq: seq, warnings: ws}})
}

// ApprovalAgent is approvalAgent for the tests of the approval gate (A10-17).
const ApprovalAgent = approvalAgent

// SetApprovalAgent makes c compile with gate as approvalAgent, so a test can run the approval flow under another gate.
func (c *Compiler) SetApprovalAgent(gate string) { c.approvalAgent = gate }

// WithheldForApproval is withheldForApproval for the tests of the approval gate.
func WithheldForApproval(intent, approval, agent, gate string) bool {
	return withheldForApproval(intent, approval, agent, gate)
}
