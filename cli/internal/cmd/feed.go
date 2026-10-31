package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/phischl/paddock-mdm/cli/internal/render"
)

const defaultPollInterval = 30 * time.Second

type feedPage struct {
	Events    []json.RawMessage `json:"events"`
	NextAfter int64             `json:"next_after"`
	Latest    int64             `json:"latest"`
}

func runAuditFeed(ctx context.Context, e Env, args []string) error {
	var g globals
	fs := newFlags("audit feed")
	g.register(fs, "json")
	after := fs.Int64("after", 0, "")
	limit := fs.Int("limit", 0, "")
	follow := fs.Bool("follow", false, "")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *after < 0 {
		return usagef("--after must not be negative")
	}
	if *limit < 0 || *limit > 1000 {
		return usagef("--limit must be between 1 and 1000")
	}
	c, err := g.connect(e)
	if err != nil {
		return err
	}
	interval := e.PollInterval
	if interval <= 0 {
		interval = defaultPollInterval
	}
	cursor := *after
	for {
		query := url.Values{"after": {strconv.FormatInt(cursor, 10)}}
		if *limit != 0 {
			query.Set("limit", strconv.Itoa(*limit))
		}
		var page feedPage
		if err := c.Do(ctx, http.MethodGet, "/api/v1/audit-events/feed", query, nil, &page); err != nil {
			if *follow && ctx.Err() != nil {
				break
			}
			return err
		}
		for _, ev := range page.Events {
			if _, err := fmt.Fprintf(e.Stdout, "%s\n", ev); err != nil {
				return err
			}
		}
		cursor = page.NextAfter
		if !*follow {
			break
		}
		if page.NextAfter < page.Latest {
			continue
		}
		select {
		case <-ctx.Done():
		case <-time.After(interval):
		}
		if ctx.Err() != nil {
			break
		}
	}
	_, err = fmt.Fprintf(e.Stderr, "next_after=%d\n", cursor)
	return err
}

func runFindingsList(ctx context.Context, e Env, args []string) error {
	var g globals
	fs := newFlags("findings list")
	g.register(fs, "table")
	page := fs.Int("page", 0, "")
	pageSize := fs.Int("page-size", 0, "")
	sort := fs.String("sort", "", "")
	q := fs.String("q", "", "")
	kind := fs.String("kind", "", "")
	cleared := fs.Bool("cleared", false, "")
	var statuses repeated
	fs.Var(&statuses, "status", "")
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
	for k, v := range map[string]string{"sort": *sort, "q": *q, "kind": *kind} {
		if v != "" {
			query.Set(k, v)
		}
	}
	if len(statuses) > 0 {
		query["status"] = statuses
	}
	if *cleared {
		query.Set("cleared", "true")
	}
	c, err := g.connect(e)
	if err != nil {
		return err
	}
	var raw []byte
	if err := c.Do(ctx, http.MethodGet, "/api/v1/findings", query, nil, &raw); err != nil {
		return err
	}
	if g.output == "json" {
		_, err = e.Stdout.Write(raw)
		return err
	}
	var p render.FindingPage
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	return render.FindingsTable(e.Stdout, p)
}
