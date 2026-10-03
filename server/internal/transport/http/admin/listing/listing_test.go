package listing_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/paddock-mdm/paddock/server/internal/problem"
	"github.com/paddock-mdm/paddock/server/internal/transport/http/admin/listing"
)

var spec = listing.Spec{Sort: []string{"name", "created_at"}, DefaultSort: "name"}

func ptr[T any](v T) *T { return &v }

func TestParseDefaults(t *testing.T) {
	p, err := listing.Parse(spec, listing.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Page != 1 || p.PageSize != 25 || p.Sort != "name" || p.Q != nil || p.QPattern != nil || p.Offset() != 0 {
		t.Fatalf("defaults: %+v", p)
	}
}

func TestParseValid(t *testing.T) {
	p, err := listing.Parse(spec, listing.Query{Page: ptr(3), PageSize: ptr(50), Sort: ptr("-created_at"), Q: ptr("  lap  ")})
	if err != nil {
		t.Fatal(err)
	}
	if p.Page != 3 || p.PageSize != 50 || p.Sort != "-created_at" || *p.Q != "lap" || *p.QPattern != "%lap%" {
		t.Fatalf("parsed: %+v", p)
	}
	if p.Offset() != 100 {
		t.Fatalf("offset %d", p.Offset())
	}
	lp := p.ListPage()
	if lp.Offset != 100 || lp.Limit != 50 || lp.Sort != "-created_at" || *lp.QPattern != "%lap%" {
		t.Fatalf("list page: %+v", lp)
	}
	for _, size := range []int{10, 25, 50, 100} {
		if _, err := listing.Parse(spec, listing.Query{PageSize: ptr(size)}); err != nil {
			t.Errorf("page_size %d: %v", size, err)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	for name, q := range map[string]listing.Query{
		"page 0":             {Page: ptr(0)},
		"negative page":      {Page: ptr(-1)},
		"page_size 7":        {PageSize: ptr(7)},
		"page_size 0":        {PageSize: ptr(0)},
		"page_size 200":      {PageSize: ptr(200)},
		"unknown sort":       {Sort: ptr("description")},
		"empty sort":         {Sort: ptr("")},
		"only minus":         {Sort: ptr("-")},
		"double minus":       {Sort: ptr("--name")},
		"plus prefix":        {Sort: ptr("+name")},
		"case differs":       {Sort: ptr("Name")},
		"q one rune":         {Q: ptr("a")},
		"q one rune trimmed": {Q: ptr("  ä  ")},
		"q 101 runes":        {Q: ptr(strings.Repeat("ü", 101))},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := listing.Parse(spec, q)
			if !errors.Is(err, problem.InvalidRequest) {
				t.Fatalf("got %v, want invalid_request", err)
			}
		})
	}
}

func TestParseSearchBounds(t *testing.T) {
	for _, q := range []string{"ab", "äö", strings.Repeat("ü", 100)} {
		if _, err := listing.Parse(spec, listing.Query{Q: ptr(q)}); err != nil {
			t.Errorf("q %q: %v", q, err)
		}
	}
	p, err := listing.Parse(spec, listing.Query{Q: ptr("   ")})
	if err != nil || p.Q != nil || p.QPattern != nil {
		t.Fatalf("blank q is no search: %+v %v", p, err)
	}
}

func TestParseDepthLimit(t *testing.T) {
	for _, tc := range []struct {
		page, size int
		ok         bool
	}{
		{400, 25, true}, {401, 25, false}, {100, 100, true}, {101, 100, false}, {1000, 10, true}, {1001, 10, false},
		{1 << 62, 100, false},
	} {
		_, err := listing.Parse(spec, listing.Query{Page: ptr(tc.page), PageSize: ptr(tc.size)})
		switch {
		case tc.ok && err != nil:
			t.Errorf("page %d × %d: %v", tc.page, tc.size, err)
		case !tc.ok && !errors.Is(err, problem.PageOutOfRange):
			t.Errorf("page %d × %d: got %v, want page_out_of_range", tc.page, tc.size, err)
		}
	}
}

func TestSearchEscaping(t *testing.T) {
	for in, want := range map[string]string{
		"50%":       `%50\%%`,
		"a_b":       `%a\_b%`,
		`C:\temp`:   `%C:\\temp%`,
		`\%_`:       `%\\\%\_%`,
		"plain txt": "%plain txt%",
	} {
		p, err := listing.Parse(spec, listing.Query{Q: ptr(in)})
		if err != nil {
			t.Fatal(err)
		}
		if *p.QPattern != want || *p.Q != in {
			t.Errorf("q %q: pattern %q, want %q", in, *p.QPattern, want)
		}
	}
}

func TestNewPage(t *testing.T) {
	p := listing.Params{Page: 2, PageSize: 10, Sort: "-name"}
	page := listing.NewPage([]string{"a"}, p, 137)
	if page.Total != 137 || page.TotalCapped || page.Page != 2 || page.PageSize != 10 || page.Sort != "-name" {
		t.Fatalf("page: %+v", page)
	}
	if page := listing.NewPage([]string{}, p, 10000); page.Total != 10000 || page.TotalCapped {
		t.Fatalf("exactly 10000: %+v", page)
	}
	if page := listing.NewPage([]string{}, p, 10001); page.Total != 10000 || !page.TotalCapped {
		t.Fatalf("capped: %+v", page)
	}
	if page := listing.NewPage[string](nil, p, 0); page.Items == nil {
		t.Fatal("nil items must encode as []")
	}
}

type color string

func (c color) Valid() bool { return c == "red" || c == "green" }

func TestEnum(t *testing.T) {
	if got, err := listing.Enum[color]("color", nil); got != nil || err != nil {
		t.Fatalf("absent: %v %v", got, err)
	}
	if got, err := listing.Enum("color", &[]color{}); got != nil || err != nil {
		t.Fatalf("empty: %v %v", got, err)
	}
	got, err := listing.Enum("color", &[]color{"red", "green"})
	if err != nil || strings.Join(got, ",") != "red,green" {
		t.Fatalf("valid: %v %v", got, err)
	}
	if _, err := listing.Enum("color", &[]color{"red", "blue"}); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("unknown value: %v", err)
	}
	if listing.Strings(nil) != nil || listing.Strings(&[]string{}) != nil {
		t.Fatal("empty free-text filter must be nil")
	}
}
