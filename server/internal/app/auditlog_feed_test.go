package app

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// TestFeedRejectsBeforeReading: the role and the bounds are checked before any query, so a nil reader is never used.
func TestFeedRejectsBeforeReading(t *testing.T) {
	auditor := principal.With(context.Background(), principal.Principal{OrganizationID: uuid.New(), Role: principal.RoleOrgAuditor})
	operator := principal.With(context.Background(), principal.Principal{OrganizationID: uuid.New(), Role: principal.RoleOrgOperator})
	tests := []struct {
		name  string
		ctx   context.Context
		after int64
		limit int
		want  *problem.Error
	}{
		{"unauthenticated", context.Background(), 0, 100, problem.Unauthenticated},
		{"operator", operator, 0, 100, problem.Forbidden},
		{"negative after", auditor, -1, 100, problem.InvalidRequest},
		{"zero limit", auditor, 0, 0, problem.InvalidRequest},
		{"limit above max", auditor, 0, MaxFeedLimit + 1, problem.InvalidRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := (&AuditLog{}).Feed(tt.ctx, tt.after, tt.limit)
			var got *problem.Error
			if !errors.As(err, &got) || got.Code != tt.want.Code || got.Status != tt.want.Status {
				t.Errorf("Feed(after %d, limit %d) = %v, want %s", tt.after, tt.limit, err, tt.want.Code)
			}
		})
	}
}
