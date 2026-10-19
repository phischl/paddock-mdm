package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
)

// Label marks the issues the watch owns.
const Label = "upstream"

// Issue is an open issue of the repository.
type Issue struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	// PullRequest is set by the issues API for pull requests, which the watch never touches.
	PullRequest json.RawMessage `json:"pull_request,omitempty"`
}

// GitHub is the part of the GitHub API the watch uses (plan M8d decision 62).
type GitHub interface {
	List(ctx context.Context, repo string) ([]Issue, error)
	Create(ctx context.Context, repo, title, body string) error
	Edit(ctx context.Context, repo string, number int, title, body string) error
	Comment(ctx context.Context, repo string, number int, body string) error
	Close(ctx context.Context, repo string, number int) error
}

// GH talks to GitHub through the gh CLI (GH_TOKEN from the workflow).
type GH struct {
	labelReady bool
}

func (g *GH) api(ctx context.Context, input any, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "gh", append([]string{"api"}, args...)...) //nolint:gosec // fixed binary; the arguments are API paths built here
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		cmd.Args = append(cmd.Args, "--input", "-")
		cmd.Stdin = bytes.NewReader(b)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gh api %v: %w: %s", args, err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}

// List returns the open issues with the label upstream.
func (g *GH) List(ctx context.Context, repo string) ([]Issue, error) {
	out, err := g.api(ctx, nil, "--paginate", fmt.Sprintf("repos/%s/issues?labels=%s&state=open&per_page=100", repo, Label))
	if err != nil {
		return nil, err
	}
	// --paginate prints one JSON array per page.
	dec := json.NewDecoder(bytes.NewReader(out))
	var issues []Issue
	for {
		var page []Issue
		if err := dec.Decode(&page); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode issues: %w", err)
		}
		for _, is := range page {
			if len(is.PullRequest) == 0 {
				issues = append(issues, is)
			}
		}
	}
	return issues, nil
}

func (g *GH) ensureLabel(ctx context.Context, repo string) error {
	if g.labelReady {
		return nil
	}
	if _, err := g.api(ctx, nil, fmt.Sprintf("repos/%s/labels/%s", repo, Label)); err != nil {
		if _, err := g.api(ctx, map[string]string{
			"name": Label, "color": "c5def5", "description": "A pinned upstream version is behind (upstream version watch)",
		}, "-X", "POST", fmt.Sprintf("repos/%s/labels", repo)); err != nil {
			return fmt.Errorf("create label %s: %w", Label, err)
		}
	}
	g.labelReady = true
	return nil
}

// Create opens an issue with the label upstream, creating the label once if it is missing.
func (g *GH) Create(ctx context.Context, repo, title, body string) error {
	if err := g.ensureLabel(ctx, repo); err != nil {
		return err
	}
	_, err := g.api(ctx, map[string]any{"title": title, "body": body, "labels": []string{Label}},
		"-X", "POST", fmt.Sprintf("repos/%s/issues", repo))
	return err
}

// Edit replaces title and body of an issue.
func (g *GH) Edit(ctx context.Context, repo string, number int, title, body string) error {
	_, err := g.api(ctx, map[string]string{"title": title, "body": body},
		"-X", "PATCH", fmt.Sprintf("repos/%s/issues/%d", repo, number))
	return err
}

// Comment adds a comment to an issue.
func (g *GH) Comment(ctx context.Context, repo string, number int, body string) error {
	_, err := g.api(ctx, map[string]string{"body": body},
		"-X", "POST", fmt.Sprintf("repos/%s/issues/%d/comments", repo, number))
	return err
}

// Close closes an issue as completed.
func (g *GH) Close(ctx context.Context, repo string, number int) error {
	_, err := g.api(ctx, map[string]string{"state": "closed", "state_reason": "completed"},
		"-X", "PATCH", fmt.Sprintf("repos/%s/issues/%d", repo, number))
	return err
}

// LatestRelease returns the tag of the latest release of a repository.
func (g *GH) LatestRelease(ctx context.Context, repo string) (string, error) {
	out, err := g.api(ctx, nil, fmt.Sprintf("repos/%s/releases/latest", repo))
	if err != nil {
		return "", err
	}
	return ParseLatestRelease(out)
}

// ParseLatestRelease reads tag_name of a GitHub release JSON.
func ParseLatestRelease(b []byte) (string, error) {
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(b, &rel); err != nil {
		return "", fmt.Errorf("decode release: %w", err)
	}
	if rel.TagName == "" {
		return "", errors.New("release without tag_name")
	}
	return rel.TagName, nil
}

// issueNumber formats an issue number for messages.
func issueNumber(n int) string { return "#" + strconv.Itoa(n) }
