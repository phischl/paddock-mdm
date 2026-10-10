package app

import (
	"context"
	"fmt"

	"github.com/google/uuid"

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

// AttentionDeviceQuery selects a page of the attention list grouped by device (plan M7c decision 27).
type AttentionDeviceQuery struct {
	Page  ListPage
	Kinds []string
	// DeviceID selects one device exactly (its page reads its conditions with it).
	DeviceID *uuid.UUID
}

// ListDevices returns one page of devices with open conditions, every condition of a device most severe first.
func (a *Attention) ListDevices(ctx context.Context, query AttentionDeviceQuery) (Listed[pgstore.ListAttentionDevicesRow], error) {
	var out Listed[pgstore.ListAttentionDevicesRow]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := a.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		kinds := nilIfEmpty(query.Kinds)
		device := nullID(query.DeviceID)
		n, err := q.CountAttentionDevices(ctx, pgstore.CountAttentionDevicesParams{
			QPattern: query.Page.QPattern, Kinds: kinds, DeviceID: device, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count attention devices: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListAttentionDevices(ctx, pgstore.ListAttentionDevicesParams{
			QPattern: query.Page.QPattern, Kinds: kinds, DeviceID: device, Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		return err
	})
	return out, err
}
