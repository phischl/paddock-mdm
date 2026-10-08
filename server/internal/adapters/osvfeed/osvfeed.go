// Package osvfeed downloads Ubuntu's OSV bulk zip (ADR 0020, plan M5c decision 1): a conditional GET with the ETag of
// the last download, streamed to the reader and bounded in size and time. Only the server downloads it; devices
// never contact OSV.
package osvfeed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultURL is the bulk file of the OSV bucket's ecosystem Ubuntu (ADR 0020).
const DefaultURL = "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip"

// MaxSize bounds a download; the file has well under 1 GiB.
const MaxSize int64 = 2 << 30

// Timeout bounds a download including the reader's work on it.
const Timeout = 10 * time.Minute

// ErrTooLarge is a download beyond MaxSize.
var ErrTooLarge = errors.New("osv: the download exceeds the size limit")

// Client downloads the bulk zip from one URL.
type Client struct {
	url     string
	http    *http.Client
	maxSize int64
}

// New creates a client for url.
func New(url string) *Client {
	return &Client{url: url, http: &http.Client{Timeout: Timeout}, maxSize: MaxSize}
}

// Fetch downloads the file unless it still has etag, and calls read with the new ETag and the body while it arrives;
// read's error is returned. notModified reports a 304 (read is not called).
func (c *Client) Fetch(ctx context.Context, etag string, read func(etag string, body io.Reader) error) (notModified bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return false, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("osv: download: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	switch {
	case res.StatusCode == http.StatusNotModified:
		return true, nil
	case res.StatusCode != http.StatusOK:
		return false, fmt.Errorf("osv: download: HTTP %d", res.StatusCode)
	case res.ContentLength > c.maxSize:
		return false, ErrTooLarge
	}
	return false, read(res.Header.Get("ETag"), &limited{r: res.Body, left: c.maxSize})
}

// limited fails with ErrTooLarge once more than left bytes arrived, instead of ending the stream early.
type limited struct {
	r    io.Reader
	left int64
}

func (l *limited) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.left -= int64(n)
	if l.left < 0 {
		return n, ErrTooLarge
	}
	return n, err
}
