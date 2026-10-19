package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// maxPages bounds every paginated listing so that a misbehaving registry cannot keep the job running.
const maxPages = 200

// hubMaxPages is the last page Docker Hub serves to anonymous clients (page 11 answers 403). Ordered newest first,
// the 1000 tags cover every candidate of a maintained image.
const hubMaxPages = 10

// Registries reads tag listings and manifest digests anonymously.
type Registries struct {
	HTTP *http.Client
	// HubBase is the Docker Hub API (https://hub.docker.com).
	HubBase string
	// RegistryURL maps a registry host to the base URL of its distribution API.
	RegistryURL func(host string) string
}

// NewRegistries returns the production endpoints.
func NewRegistries(c *http.Client) *Registries {
	return &Registries{HTTP: c, HubBase: "https://hub.docker.com", RegistryURL: func(host string) string {
		if host == "docker.io" {
			host = "registry-1.docker.io"
		}
		return "https://" + host
	}}
}

// Tags lists every tag of an image: Docker Hub through its API, every other registry through the OCI distribution
// API with an anonymous bearer token.
func (r *Registries) Tags(ctx context.Context, img ImageRef) ([]string, error) {
	if img.Registry == "docker.io" {
		return r.hubTags(ctx, img.Repo, img.Tag)
	}
	return r.ociTags(ctx, img)
}

func (r *Registries) hubTags(ctx context.Context, repo, pinned string) ([]string, error) {
	q := url.Values{"page_size": {"100"}, "ordering": {"last_updated"}}
	if f := hubNameFilter(pinned); f != "" {
		q.Set("name", f)
	}
	next := fmt.Sprintf("%s/v2/repositories/%s/tags?%s", r.HubBase, repo, q.Encode())
	var tags []string
	for page := 0; next != "" && page < hubMaxPages; page++ {
		var body struct {
			Next    *string `json:"next"`
			Results []struct {
				Name string `json:"name"`
			} `json:"results"`
		}
		if err := r.getJSON(ctx, next, nil, &body); err != nil {
			return nil, err
		}
		for _, t := range body.Results {
			tags = append(tags, t.Name)
		}
		next = ""
		if body.Next != nil {
			next = *body.Next
		}
	}
	return tags, nil
}

// hubNameFilter returns the longest literal part of the pinned tag that contains a letter (-management,
// -trixie-slim), which Docker Hub matches as a substring: it keeps the listing of images with many variants short.
func hubNameFilter(pinned string) string {
	best := ""
	for _, part := range digitsRE.Split(pinned, -1) {
		part = strings.Trim(part, ".")
		if len(part) >= 3 && strings.ContainsFunc(part, unicode.IsLetter) && len(part) > len(best) {
			best = part
		}
	}
	return best
}

func (r *Registries) ociTags(ctx context.Context, img ImageRef) ([]string, error) {
	base := r.RegistryURL(img.Registry)
	next := fmt.Sprintf("%s/v2/%s/tags/list?n=1000", base, img.Repo)
	token := ""
	var tags []string
	for page := 0; next != "" && page < maxPages; page++ {
		resp, err := r.authorized(ctx, http.MethodGet, next, img.Repo, &token, nil)
		if err != nil {
			return nil, err
		}
		var body struct {
			Tags []string `json:"tags"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		link := resp.Header.Get("Link")
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", next, err)
		}
		tags = append(tags, body.Tags...)
		next = nextLink(base, link)
	}
	return tags, nil
}

var linkRE = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func nextLink(base, header string) string {
	m := linkRE.FindStringSubmatch(header)
	if m == nil {
		return ""
	}
	if strings.HasPrefix(m[1], "/") {
		return base + m[1]
	}
	return m[1]
}

// Digest resolves the manifest digest a tag points to now.
func (r *Registries) Digest(ctx context.Context, img ImageRef) (string, error) {
	u := fmt.Sprintf("%s/v2/%s/manifests/%s", r.RegistryURL(img.Registry), img.Repo, img.Tag)
	accept := http.Header{"Accept": []string{strings.Join([]string{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", ")}}
	token := ""
	resp, err := r.authorized(ctx, http.MethodHead, u, img.Repo, &token, accept)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	d := resp.Header.Get("Docker-Content-Digest")
	if d == "" {
		return "", fmt.Errorf("%s: no Docker-Content-Digest", u)
	}
	return d, nil
}

// authorized sends the request and, on a 401 with a Bearer challenge, fetches an anonymous token and retries once.
// The caller closes the body of the returned response.
func (r *Registries) authorized(ctx context.Context, method, u, repo string, token *string, h http.Header) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, u, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range h {
			req.Header[k] = v
		}
		if *token != "" {
			req.Header.Set("Authorization", "Bearer "+*token)
		}
		resp, err := r.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			challenge := resp.Header.Get("WWW-Authenticate")
			_ = resp.Body.Close()
			if *token, err = r.anonymousToken(ctx, challenge, repo); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("%s %s: %s", method, u, resp.Status)
		}
		return resp, nil
	}
}

var challengeParamRE = regexp.MustCompile(`(\w+)="([^"]*)"`)

func (r *Registries) anonymousToken(ctx context.Context, challenge, repo string) (string, error) {
	scheme, params, _ := strings.Cut(challenge, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", fmt.Errorf("unsupported auth challenge %q", challenge)
	}
	p := map[string]string{}
	for _, m := range challengeParamRE.FindAllStringSubmatch(params, -1) {
		p[m[1]] = m[2]
	}
	if p["realm"] == "" {
		return "", errors.New("auth challenge without realm")
	}
	if p["scope"] == "" {
		p["scope"] = "repository:" + repo + ":pull"
	}
	q := url.Values{"scope": {p["scope"]}}
	if p["service"] != "" {
		q.Set("service", p["service"])
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := r.getJSON(ctx, p["realm"]+"?"+q.Encode(), nil, &body); err != nil {
		return "", fmt.Errorf("anonymous token: %w", err)
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", errors.New("anonymous token: empty answer")
}

func (r *Registries) getJSON(ctx context.Context, u string, h http.Header, v any) error {
	b, err := getBody(ctx, r.HTTP, u, h)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("decode %s: %w", u, err)
	}
	return nil
}

// maxRetries is how often a 429 answer is retried after its Retry-After.
const maxRetries = 3

// getBody fetches a URL and returns its body (at most 16 MiB); any status but 200 is an error. A 429 is retried
// after Retry-After (at most 60 s each), because Docker Hub rate-limits anonymous listings per minute.
func getBody(ctx context.Context, c *http.Client, u string, h http.Header) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range h {
			req.Header[k] = v
		}
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRetries {
			wait := retryAfter(resp.Header.Get("Retry-After"))
			_ = resp.Body.Close()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		_ = resp.Body.Close()
		return b, err
	}
}

func retryAfter(v string) time.Duration {
	s, err := strconv.Atoi(v)
	if err != nil || s < 1 {
		return 10 * time.Second
	}
	return min(time.Duration(s)*time.Second, time.Minute)
}
