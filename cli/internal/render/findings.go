package render

import (
	"fmt"
	"io"
	"math"
	"text/tabwriter"
)

// Finding is the part of an admin API finding that the table shows.
type Finding struct {
	Kind       string `json:"kind"`
	Code       string `json:"code"`
	Subject    string `json:"subject"`
	Hostname   string `json:"hostname"`
	Status     string `json:"status"`
	LastSeenAt string `json:"last_seen_at"`
	Assignee   *struct {
		DisplayName string `json:"display_name"`
	} `json:"assignee"`
}

// FindingPage is the list envelope of GET /api/v1/findings.
type FindingPage struct {
	Items       []Finding `json:"items"`
	Page        int       `json:"page"`
	PageSize    int       `json:"page_size"`
	Total       int       `json:"total"`
	TotalCapped bool      `json:"total_capped"`
}

// FindingsTable writes the findings as a table and the footer of DevicesTable.
func FindingsTable(w io.Writer, p FindingPage) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "HOSTNAME\tKIND\tCODE\tSUBJECT\tSTATUS\tASSIGNEE\tLAST SEEN")
	for _, f := range p.Items {
		assignee := "-"
		if f.Assignee != nil && f.Assignee.DisplayName != "" {
			assignee = f.Assignee.DisplayName
		}
		subject := f.Subject
		if subject == "" {
			subject = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", f.Hostname, f.Kind, f.Code, subject, f.Status, assignee, f.LastSeenAt)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	pages := 1
	if p.PageSize > 0 && p.Total > 0 {
		pages = int(math.Ceil(float64(p.Total) / float64(p.PageSize)))
	}
	plus := ""
	if p.TotalCapped {
		plus = "+"
	}
	_, err := fmt.Fprintf(w, "page %d of %d (total %d%s)\n", p.Page, pages, p.Total, plus)
	return err
}
