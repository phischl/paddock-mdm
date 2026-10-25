// Package githubreleases lists and downloads the assets of GitHub releases (ADR 0043 decision 5). GitHub is
// transport only: the caller verifies every downloaded file with the release public key.
package githubreleases

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
)

// Request headers and bounds of ADR 0043 decision 5.
const (
	APIVersion      = "2022-11-28"
	UserAgent       = "paddock-server"
	MaxListBytes    = 1 << 20
	MaxMinisigBytes = 4 << 10
	ListTimeout     = 15 * time.Second
	AssetTimeout    = 60 * time.Second
	MaxRedirects    = 5
)

// Errors of the client.
var (
	ErrTooLarge       = errors.New("githubreleases: the download exceeds the size limit")
	ErrHostNotAllowed = errors.New("githubreleases: the URL is outside the allowed hosts")
	ErrRateLimited    = errors.New("githubreleases: rate limit exceeded")
)

// RateLimitError wraps ErrRateLimited with the reset time (x-ratelimit-reset).
type RateLimitError struct{ ResetAt time.Time }

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("%v; resets at %s", ErrRateLimited, e.ResetAt.UTC().Format(time.RFC3339))
}

// Unwrap makes errors.Is(err, ErrRateLimited) hold.
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

// Release is a non-draft release whose tag is v<Version>.
type Release struct {
	Version     string // tag without the leading "v"
	PublishedAt time.Time
	Assets      []Asset
}

// Asset is one file of a release as the source lists it; nothing about it is trusted beyond the selection.
type Asset struct {
	Name string
	Size int64
	URL  string
}

// Client lists the releases of one repository and downloads their assets.
type Client struct {
	repository     string
	baseURL        string
	baseHost       string
	token          string
	allowPlainHTTP bool
	http           *http.Client
	listTimeout    time.Duration
	assetTimeout   time.Duration
}

// New creates a client for repository ("<owner>/<repo>") on baseURL (API base, no trailing slash); allowPlainHTTP is
// true only in development.
func New(baseURL, repository, token string, allowPlainHTTP bool) *Client {
	c := &Client{repository: repository, baseURL: baseURL, token: token, allowPlainHTTP: allowPlainHTTP,
		listTimeout: ListTimeout, assetTimeout: AssetTimeout}
	if u, err := url.Parse(baseURL); err == nil {
		c.baseHost = u.Host
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	tr.TLSHandshakeTimeout = 10 * time.Second
	tr.ResponseHeaderTimeout = 15 * time.Second
	c.http = &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > MaxRedirects {
			return fmt.Errorf("githubreleases: stopped after %d redirects", MaxRedirects)
		}
		return c.checkURL(req.URL)
	}}
	return c
}

// checkURL applies the host rule: the source's host, github.com or a subdomain of githubusercontent.com, over https
// (http only in development).
func (c *Client) checkURL(u *url.URL) error {
	if u.Scheme != "https" && (u.Scheme != "http" || !c.allowPlainHTTP) {
		return fmt.Errorf("%w: %s", ErrHostNotAllowed, u.Redacted())
	}
	h := u.Hostname()
	if u.Host == c.baseHost || h == "github.com" || strings.HasSuffix(h, ".githubusercontent.com") {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrHostNotAllowed, u.Redacted())
}

type releaseJSON struct {
	TagName     string    `json:"tag_name"`
	Draft       bool      `json:"draft"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// ListReleases fetches GET <baseURL>/repos/<repository>/releases?per_page=100 (one page) and returns the non-draft
// releases whose tag_name is v<version> with a version that passes agentrelease.ValidateSourceVersion; every other
// release is dropped silently. The body is bounded by MaxListBytes and ListTimeout.
func (c *Client) ListReleases(ctx context.Context) ([]Release, error) {
	ctx, cancel := context.WithTimeout(ctx, c.listTimeout)
	defer cancel()
	body, err := c.get(ctx, c.baseURL+"/repos/"+c.repository+"/releases?per_page=100", "application/vnd.github+json", MaxListBytes)
	if err != nil {
		return nil, fmt.Errorf("githubreleases: list releases: %w", err)
	}
	var list []releaseJSON
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("githubreleases: list releases: %w", err)
	}
	out := make([]Release, 0, len(list))
	for _, r := range list {
		v, ok := strings.CutPrefix(r.TagName, "v")
		if r.Draft || !ok || agentrelease.ValidateSourceVersion(v) != nil {
			continue
		}
		rel := Release{Version: v, PublishedAt: r.PublishedAt, Assets: make([]Asset, 0, len(r.Assets))}
		for _, a := range r.Assets {
			rel.Assets = append(rel.Assets, Asset{Name: a.Name, Size: a.Size, URL: a.BrowserDownloadURL})
		}
		out = append(out, rel)
	}
	return out, nil
}

// Download fetches one asset within maxBytes and AssetTimeout, following at most MaxRedirects redirects, each to an
// allowed host; ErrTooLarge beyond maxBytes (also when the listed Size exceeds it), ErrHostNotAllowed for a URL or
// redirect outside the allowed hosts or scheme.
func (c *Client) Download(ctx context.Context, a Asset, maxBytes int64) ([]byte, error) {
	if a.Size > maxBytes {
		return nil, fmt.Errorf("githubreleases: %s: %w", a.Name, ErrTooLarge)
	}
	ctx, cancel := context.WithTimeout(ctx, c.assetTimeout)
	defer cancel()
	body, err := c.get(ctx, a.URL, "application/octet-stream", maxBytes)
	if err != nil {
		return nil, fmt.Errorf("githubreleases: %s: %w", a.Name, err)
	}
	return body, nil
}

// get fetches rawURL and reads at most maxBytes of a 200 response.
func (c *Client) get(ctx context.Context, rawURL, accept string, maxBytes int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if err := c.checkURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", APIVersion)
	req.Header.Set("User-Agent", UserAgent)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		// The body of a failed request is discarded unread: it is the source's text, not ours to show or log.
		if (res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusTooManyRequests) &&
			res.Header.Get("X-Ratelimit-Remaining") == "0" {
			reset, _ := strconv.ParseInt(res.Header.Get("X-Ratelimit-Reset"), 10, 64)
			return nil, &RateLimitError{ResetAt: time.Unix(reset, 0).UTC()}
		}
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	if res.ContentLength > maxBytes {
		return nil, ErrTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, ErrTooLarge
	}
	return body, nil
}
