package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// CompileWarnings is the read use case of the compile warnings, what the compiler shortened or dropped from a device's
// bundle against what an administrator assigned (architect decisions A10-9 and A10-10); reads are not audited.
type CompileWarnings struct {
	org *db.OrgPool
}

// NewCompileWarnings creates the use case.
func NewCompileWarnings(org *db.OrgPool) *CompileWarnings { return &CompileWarnings{org: org} }

// CompileWarning is one warning of a device's latest compile, for the assignment and catalog entry it concerns.
type CompileWarning struct {
	ID             uuid.UUID
	DeviceID       uuid.UUID
	Hostname       string
	AssignmentID   uuid.NullUUID
	CatalogEntryID uuid.NullUUID
	Code           string
	Params         map[string]any
	CreatedAt      time.Time
}

// CompileWarningQuery selects a page of compile warnings; q matches the hostname and the code.
type CompileWarningQuery struct {
	Page           ListPage
	DeviceID       *uuid.UUID
	AssignmentID   *uuid.UUID
	CatalogEntryID *uuid.UUID
	Code           *string
}

// List returns one page of the organization's compile warnings.
func (c *CompileWarnings) List(ctx context.Context, query CompileWarningQuery) (Listed[CompileWarning], error) {
	var out Listed[CompileWarning]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := c.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountCompileWarnings(ctx, pgstore.CountCompileWarningsParams{
			QPattern: query.Page.QPattern, DeviceID: nullID(query.DeviceID), AssignmentID: nullID(query.AssignmentID),
			CatalogEntryID: nullID(query.CatalogEntryID), Code: query.Code, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count compile warnings: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListCompileWarnings(ctx, pgstore.ListCompileWarningsParams{
			QPattern: query.Page.QPattern, DeviceID: nullID(query.DeviceID), AssignmentID: nullID(query.AssignmentID),
			CatalogEntryID: nullID(query.CatalogEntryID), Code: query.Code, Sort: query.Page.Sort,
			SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list compile warnings: %w", err)
		}
		for _, r := range rows {
			w := CompileWarning{ID: r.ID, DeviceID: r.DeviceID, Hostname: r.Hostname, AssignmentID: r.AssignmentID,
				CatalogEntryID: r.CatalogEntryID, Code: r.Code, CreatedAt: r.CreatedAt}
			if err := json.Unmarshal(r.Params, &w.Params); err != nil {
				return fmt.Errorf("decode compile warning %s: %w", r.ID, err)
			}
			out.Items = append(out.Items, w)
		}
		return nil
	})
	return out, err
}
