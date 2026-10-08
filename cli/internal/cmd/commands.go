package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/oasdiff/yaml"

	"github.com/phischl/paddock-mdm/cli/internal/render"
	"github.com/phischl/paddock-mdm/cli/internal/schema"
)

// maxDocument mirrors the server's limit, so an oversized file is refused before it is sent.
const maxDocument = 1 << 20

func runSchema(e Env, args []string) error {
	if len(args) != 0 {
		return usagef("schema takes no arguments")
	}
	_, err := e.Stdout.Write(schema.JSON)
	return err
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func runWhoami(ctx context.Context, e Env, args []string) error {
	var g globals
	fs := newFlags("whoami")
	g.register(fs, "text")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := g.requireOutput("text", "json"); err != nil {
		return err
	}
	c, err := g.connect(e)
	if err != nil {
		return err
	}
	var me struct {
		Role         string `json:"role"`
		Organization *struct {
			Slug string `json:"slug"`
			Name string `json:"name"`
		} `json:"organization"`
		APIToken *struct {
			Name      string `json:"name"`
			ExpiresAt string `json:"expires_at"`
		} `json:"api_token"`
	}
	if err := c.Do(ctx, http.MethodGet, "/api/v1/me", nil, nil, &me); err != nil {
		return err
	}
	out := struct {
		Organization string `json:"organization"`
		Role         string `json:"role"`
		Token        string `json:"token"`
		ExpiresAt    string `json:"expires_at"`
	}{Role: me.Role}
	if me.Organization != nil {
		out.Organization = me.Organization.Slug
	}
	if me.APIToken != nil {
		out.Token, out.ExpiresAt = me.APIToken.Name, me.APIToken.ExpiresAt
	}
	if g.output == "json" {
		return writeJSON(e.Stdout, out)
	}
	_, err = fmt.Fprintf(e.Stdout, "organization: %s\nrole: %s\ntoken: %s\nexpires_at: %s\n", out.Organization, out.Role, out.Token, out.ExpiresAt)
	return err
}

func runGetConfig(ctx context.Context, e Env, args []string) error {
	var g globals
	fs := newFlags("get config")
	g.register(fs, "yaml")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := g.requireOutput("yaml", "json"); err != nil {
		return err
	}
	c, err := g.connect(e)
	if err != nil {
		return err
	}
	var raw []byte
	if err := c.Do(ctx, http.MethodGet, "/api/v1/config", nil, nil, &raw); err != nil {
		return err
	}
	if g.output == "json" {
		_, err = e.Stdout.Write(raw)
		return err
	}
	y, err := render.JSONToYAML(raw)
	if err != nil {
		return err
	}
	_, err = e.Stdout.Write(y)
	return err
}

// applyResult is the 200 body of PUT /api/v1/config.
type applyResult struct {
	DryRun      bool        `json:"dry_run"`
	ChangeSetID *string     `json:"change_set_id"`
	Plan        render.Plan `json:"plan"`
}

func runApply(ctx context.Context, e Env, args []string) error {
	var g globals
	fs := newFlags("apply")
	g.register(fs, "text")
	file := fs.String("f", "", "")
	dryRun := fs.Bool("dry-run", false, "")
	yes := fs.Bool("yes", false, "")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := g.requireOutput("text", "json"); err != nil {
		return err
	}
	if *file == "" {
		return usagef("apply needs -f <file|->")
	}
	doc, err := readDocument(e, *file)
	if err != nil {
		return err
	}
	c, err := g.connect(e)
	if err != nil {
		return err
	}
	var plan applyResult
	if err := c.Do(ctx, http.MethodPut, "/api/v1/config", url.Values{"dry_run": {"true"}}, doc, &plan); err != nil {
		return err
	}
	if *dryRun {
		return writePlan(e, g.output, plan)
	}
	if plan.Plan.Deleted > 0 && !*yes {
		if err := writePlan(e, g.output, plan); err != nil {
			return err
		}
		return &refusedError{msg: fmt.Sprintf("plan deletes %d resources; re-run with --yes", plan.Plan.Deleted)}
	}
	var applied applyResult
	if err := c.Do(ctx, http.MethodPut, "/api/v1/config", nil, doc, &applied); err != nil {
		return err
	}
	if g.output == "json" {
		return writeJSON(e.Stdout, applied)
	}
	if err := render.PlanText(e.Stdout, applied.Plan); err != nil {
		return err
	}
	if applied.ChangeSetID == nil {
		_, err = fmt.Fprintln(e.Stdout, "No changes")
		return err
	}
	_, err = fmt.Fprintf(e.Stdout, "Applied change set %s\n", *applied.ChangeSetID)
	return err
}

func writePlan(e Env, output string, plan applyResult) error {
	if output == "json" {
		return writeJSON(e.Stdout, plan)
	}
	return render.PlanText(e.Stdout, plan.Plan)
}

// readDocument reads a YAML or JSON document from a file or stdin ("-") and converts it to JSON.
func readDocument(e Env, path string) ([]byte, error) {
	r := e.Stdin
	if path != "-" {
		f, err := os.Open(path) //nolint:gosec // the operator's own document
		if err != nil {
			return nil, usagef("%v", err)
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxDocument+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxDocument {
		return nil, usagef("%s is larger than 1 MiB", path)
	}
	doc, err := yaml.YAMLToJSON(raw)
	if err != nil {
		return nil, usagef("%s is neither YAML nor JSON: %v", path, err)
	}
	return doc, nil
}

// repeated is a repeatable string flag.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

func runDevicesList(ctx context.Context, e Env, args []string) error {
	var g globals
	fs := newFlags("devices list")
	g.register(fs, "table")
	page := fs.Int("page", 0, "")
	pageSize := fs.Int("page-size", 0, "")
	sort := fs.String("sort", "", "")
	q := fs.String("q", "", "")
	group := fs.String("device-group-id", "", "")
	var states, disks repeated
	fs.Var(&states, "state", "")
	fs.Var(&disks, "disk-state", "")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := g.requireOutput("table", "json"); err != nil {
		return err
	}
	query := url.Values{}
	if *page != 0 {
		query.Set("page", strconv.Itoa(*page))
	}
	if *pageSize != 0 {
		query.Set("page_size", strconv.Itoa(*pageSize))
	}
	for k, v := range map[string]string{"sort": *sort, "q": *q, "device_group_id": *group} {
		if v != "" {
			query.Set(k, v)
		}
	}
	query["state"], query["disk_state"] = states, disks
	if len(states) == 0 {
		delete(query, "state")
	}
	if len(disks) == 0 {
		delete(query, "disk_state")
	}
	c, err := g.connect(e)
	if err != nil {
		return err
	}
	var raw []byte
	if err := c.Do(ctx, http.MethodGet, "/api/v1/devices", query, nil, &raw); err != nil {
		return err
	}
	if g.output == "json" {
		_, err = e.Stdout.Write(raw)
		return err
	}
	var p render.DevicePage
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	return render.DevicesTable(e.Stdout, p)
}
