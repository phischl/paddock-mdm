package app

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// AccountList lists the organization's administrator accounts, e.g. for the assignee picker of findings (plan M9
// decision 34). Disabled accounts are not listed.
type AccountList struct {
	org *db.OrgPool
}

// NewAccountList creates the use case.
func NewAccountList(org *db.OrgPool) *AccountList { return &AccountList{org: org} }

// AccountQuery selects a page of accounts.
type AccountQuery struct {
	Page  ListPage
	Roles []string
}

// AccountItem is one account of the organization.
type AccountItem struct {
	ID                          uuid.UUID
	Username, DisplayName, Role string
}

// List returns one page of the organization's accounts.
func (a *AccountList) List(ctx context.Context, query AccountQuery) (Listed[AccountItem], error) {
	var out Listed[AccountItem]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := a.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		roles := nilIfEmpty(query.Roles)
		n, err := q.CountOrgAccounts(ctx, pgstore.CountOrgAccountsParams{QPattern: query.Page.QPattern, Roles: roles, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count accounts: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListOrgAccounts(ctx, pgstore.ListOrgAccountsParams{
			QPattern: query.Page.QPattern, Roles: roles, Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list accounts: %w", err)
		}
		out.Items = make([]AccountItem, len(rows))
		for i, r := range rows {
			out.Items[i] = AccountItem{ID: r.ID, Username: r.Username, DisplayName: r.DisplayName, Role: r.Role}
		}
		return nil
	})
	return out, err
}
