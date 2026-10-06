// Package listing implements the list contract of every collection endpoint of the admin API (ADR 0018): it
// validates page, page_size, sort, q and enum filters and builds the response envelope.
package listing

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Contract values of ADR 0018.
const (
	DefaultPageSize = 25
	MinSearch       = 2
	MaxSearch       = 100
)

// PageSizes are the allowed values of page_size.
var PageSizes = []int{10, 25, 50, 100}

// Spec is the list definition of one endpoint; it matches the endpoint's x-paddock-list extension.
type Spec struct {
	Sort        []string // allowed fields without prefix, e.g. {"name", "created_at", "updated_at"}
	DefaultSort string   // e.g. "name" or "-occurred_at"
}

// Query holds the raw list parameters as bound by the generated server; nil means absent.
type Query struct {
	Page     *int
	PageSize *int
	Sort     *string
	Q        *string
}

// Params are validated list parameters.
type Params struct {
	Page     int     // ≥ 1
	PageSize int     // 10|25|50|100
	Sort     string  // validated value incl. optional "-" prefix
	Q        *string // nil when absent; trimmed, 2–100 runes
	QPattern *string // escaped "%…%" pattern for ILIKE … ESCAPE '\'
}

// Parse validates q against spec. Invalid values are 400 invalid_request, a page beyond the depth limit is 400
// page_out_of_range.
func Parse(spec Spec, q Query) (Params, error) {
	p := Params{Page: 1, PageSize: DefaultPageSize, Sort: spec.DefaultSort}
	if q.Page != nil {
		if *q.Page < 1 {
			return Params{}, problem.InvalidRequest.WithDetail("page must be at least 1")
		}
		p.Page = *q.Page
	}
	if q.PageSize != nil {
		if !slices.Contains(PageSizes, *q.PageSize) {
			return Params{}, problem.InvalidRequest.WithDetail("page_size must be one of 10, 25, 50, 100")
		}
		p.PageSize = *q.PageSize
	}
	// Compared by division so huge page numbers cannot overflow.
	if p.Page > app.ListMaxRows/p.PageSize {
		return Params{}, problem.PageOutOfRange.WithDetail(fmt.Sprintf("page × page_size may not exceed %d", app.ListMaxRows))
	}
	if q.Sort != nil {
		if !slices.Contains(spec.Sort, strings.TrimPrefix(*q.Sort, "-")) {
			return Params{}, problem.InvalidRequest.WithDetail("sort must be one of " + strings.Join(spec.Sort, ", ") +
				`, optionally prefixed with "-"`)
		}
		p.Sort = *q.Sort
	}
	if q.Q != nil {
		text := strings.TrimSpace(*q.Q)
		if n := utf8.RuneCountInString(text); text != "" && (n < MinSearch || n > MaxSearch) {
			return Params{}, problem.InvalidRequest.WithDetail(fmt.Sprintf("q must have %d to %d characters", MinSearch, MaxSearch))
		}
		if text != "" {
			pattern := "%" + likeEscaper.Replace(text) + "%"
			p.Q, p.QPattern = &text, &pattern
		}
	}
	return p, nil
}

// likeEscaper makes the search text literal inside ILIKE … ESCAPE '\'.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// Offset is the number of rows before the page.
func (p Params) Offset() int { return (p.Page - 1) * p.PageSize }

// ListPage is the page selection handed to the use cases.
func (p Params) ListPage() app.ListPage {
	return app.ListPage{Sort: p.Sort, QPattern: p.QPattern, Offset: int32(p.Offset()), Limit: int32(p.PageSize)} //nolint:gosec // both ≤ app.ListMaxRows (Parse)
}

// Page is the response envelope. The field order matches the generated *Page schemas of the contract, so a Page
// converts directly to them (adminapi.DeviceGroupPage(page)).
type Page[T any] struct {
	Items       []T    `json:"items"`
	Page        int    `json:"page"`
	PageSize    int    `json:"page_size"`
	Sort        string `json:"sort"`
	Total       int    `json:"total"`
	TotalCapped bool   `json:"total_capped"`
}

// NewPage builds the envelope from the rows of the page and the count of matching rows (counted up to
// app.ListMaxRows+1).
func NewPage[T any](items []T, p Params, countUpTo10001 int) Page[T] {
	if items == nil {
		items = []T{}
	}
	return Page[T]{
		Items: items, Page: p.Page, PageSize: p.PageSize, Sort: p.Sort,
		Total: min(countUpTo10001, app.ListMaxRows), TotalCapped: countUpTo10001 > app.ListMaxRows,
	}
}

// Enum validates a repeatable enum filter; it returns nil (no filter) when values is absent or empty.
func Enum[T interface {
	~string
	Valid() bool
}](name string, values *[]T) ([]string, error) {
	if values == nil || len(*values) == 0 {
		return nil, nil
	}
	out := make([]string, len(*values))
	for i, v := range *values {
		if !v.Valid() {
			return nil, problem.InvalidRequest.WithDetail(fmt.Sprintf("unknown %s %q", name, string(v)))
		}
		out[i] = string(v)
	}
	return out, nil
}

// Strings returns a repeatable free-text filter; nil (no filter) when values is absent or empty.
func Strings(values *[]string) []string {
	if values == nil || len(*values) == 0 {
		return nil
	}
	return *values
}
