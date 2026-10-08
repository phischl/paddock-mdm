package app

import (
	"context"
	"fmt"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// Attention lists the conditions of devices that need an administrator (plan M5b decision 11).
type Attention struct {
	org *db.OrgPool
}

// NewAttention creates the use case.
func NewAttention(org *db.OrgPool) *Attention { return &Attention{org: org} }

// AttentionQuery selects a page of the attention list.
type AttentionQuery struct {
	Page  ListPage
	Kinds []string
}

// List returns one page of open conditions.
func (a *Attention) List(ctx context.Context, query AttentionQuery) (Listed[pgstore.AttentionCondition], error) {
	var out Listed[pgstore.AttentionCondition]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := a.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		kinds := nilIfEmpty(query.Kinds)
		n, err := q.CountAttention(ctx, pgstore.CountAttentionParams{QPattern: query.Page.QPattern, Kinds: kinds, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count attention: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListAttention(ctx, pgstore.ListAttentionParams{
			QPattern: query.Page.QPattern, Kinds: kinds, Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		return err
	})
	return out, err
}
