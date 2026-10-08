package render

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"text/tabwriter"
)

// Plan is the plan of PUT /api/v1/config.
type Plan struct {
	Changes []Change `json:"changes"`
	Created int      `json:"created"`
	Updated int      `json:"updated"`
	Deleted int      `json:"deleted"`
}

// Change is one change of a plan.
type Change struct {
	Section string        `json:"section"`
	Key     string        `json:"key"`
	Action  string        `json:"action"`
	Fields  []FieldChange `json:"fields"`
}

// FieldChange is one changed field.
type FieldChange struct {
	Name   string `json:"name"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}

// PlanText writes one line per created ("+") and deleted ("-") item, one line per changed field of an updated item
// ("~"), and the summary line.
func PlanText(w io.Writer, p Plan) error {
	var b strings.Builder
	for _, c := range p.Changes {
		target := c.Section
		if c.Key != "" {
			target += " " + c.Key
		}
		switch c.Action {
		case "create":
			b.WriteString("+ " + target + "\n")
		case "delete":
			b.WriteString("- " + target + "\n")
		default:
			for _, f := range c.Fields {
				fmt.Fprintf(&b, "~ %s %s: %s -> %s\n", target, f.Name, value(f.Before), value(f.After))
			}
		}
	}
	fmt.Fprintf(&b, "Plan: %d to create, %d to update, %d to delete\n", p.Created, p.Updated, p.Deleted)
	_, err := io.WriteString(w, b.String())
	return err
}

func value(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(raw)
}

// Device is a row of GET /api/v1/devices.
type Device struct {
	Hostname             string  `json:"hostname"`
	State                string  `json:"state"`
	LastContactAt        *string `json:"last_contact_at"`
	AgentVersion         *string `json:"agent_version"`
	AppliedBundleVersion *int64  `json:"applied_bundle_version"`
}

// DevicePage is the list envelope of GET /api/v1/devices.
type DevicePage struct {
	Items       []Device `json:"items"`
	Page        int      `json:"page"`
	PageSize    int      `json:"page_size"`
	Total       int      `json:"total"`
	TotalCapped bool     `json:"total_capped"`
}

// DevicesTable writes the devices as a table and a footer "page P of N (total T[+])".
func DevicesTable(w io.Writer, p DevicePage) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "HOSTNAME\tSTATE\tLAST CONTACT\tAGENT\tBUNDLE")
	for _, d := range p.Items {
		bundle := "-"
		if d.AppliedBundleVersion != nil {
			bundle = strconv.FormatInt(*d.AppliedBundleVersion, 10)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", d.Hostname, d.State, orDash(d.LastContactAt), orDash(d.AgentVersion), bundle)
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

func orDash(s *string) string {
	if s == nil || *s == "" {
		return "-"
	}
	return *s
}
