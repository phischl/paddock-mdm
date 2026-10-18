package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Result is the comparison of one pin with upstream.
type Result struct {
	Pin    Pin
	Latest string
	Class  string
	Err    error
}

// Upstream looks up the latest version of each kind of pin.
type Upstream struct {
	Registries      *Registries
	HTTP            *http.Client
	HimmelblauIndex string
	LatestRelease   func(ctx context.Context, repo string) (string, error)
}

// Check compares every pin with upstream. A lookup error makes that pin unknown; it never stops the others.
func (u *Upstream) Check(ctx context.Context, pins []Pin) []Result {
	out := make([]Result, 0, len(pins))
	for _, p := range pins {
		out = append(out, u.check(ctx, p))
	}
	return out
}

func (u *Upstream) check(ctx context.Context, p Pin) Result {
	r := Result{Pin: p}
	var latest string
	var err error
	switch p.Kind {
	case KindHimmelblau:
		latest, err = FetchHimmelblau(ctx, u.HTTP, u.HimmelblauIndex)
	case KindNVD:
		latest, err = u.LatestRelease(ctx, p.Info.GitHub)
	case KindImage:
		if Floating(p.Image.Tag) {
			return u.checkDigest(ctx, p)
		}
		var tags []string
		if tags, err = u.Registries.Tags(ctx, p.Image); err == nil {
			if latest = Latest(p.Pinned, tags); latest == "" {
				err = fmt.Errorf("no tag of the shape %s", Shape(p.Pinned))
			}
		}
	}
	if err != nil {
		r.Class, r.Err = ClassUnknown, err
		return r
	}
	r.Latest, r.Class = latest, Classify(p.Pinned, latest)
	return r
}

func (u *Upstream) checkDigest(ctx context.Context, p Pin) Result {
	r := Result{Pin: p}
	d, err := u.Registries.Digest(ctx, p.Image)
	if err != nil {
		r.Class, r.Err = ClassUnknown, err
		return r
	}
	r.Latest = p.Image.Tag + "@" + d
	r.Class = ClassOK
	if d != p.Image.Digest {
		r.Class = ClassDigest
	}
	return r
}

// PinnedLabel is the pinned version as reports and issue titles show it (floating tags with their digest).
func (r Result) PinnedLabel() string {
	if r.Pin.Kind == KindImage && Floating(r.Pin.Image.Tag) {
		return shortDigest(r.Pin.Image.Tag + "@" + r.Pin.Image.Digest)
	}
	return r.Pin.Pinned
}

// LatestLabel is the latest version as reports and issue titles show it; "-" when unknown.
func (r Result) LatestLabel() string {
	switch {
	case r.Latest == "":
		return "-"
	case r.Pin.Kind == KindImage && Floating(r.Pin.Image.Tag):
		return shortDigest(r.Latest)
	default:
		return r.Latest
	}
}

func shortDigest(s string) string {
	tag, d, ok := strings.Cut(s, "@sha256:")
	if !ok || len(d) < 12 {
		return s
	}
	return tag + "@sha256:" + d[:12]
}

// ReleaseNotes is the release notes URL of the latest version, "" when the pin's project publishes none.
func (r Result) ReleaseNotes() string {
	switch {
	case r.Latest == "":
		return ""
	case r.Pin.Kind == KindHimmelblau:
		return HimmelblauIndex + r.Latest + "/"
	case r.Pin.Info.GitHub == "" || (r.Pin.Kind == KindImage && Floating(r.Pin.Image.Tag)):
		return ""
	default:
		return fmt.Sprintf("https://github.com/%s/releases/tag/%s", r.Pin.Info.GitHub, r.Latest)
	}
}

// WriteText prints one line per pin: name, pinned, latest, classification. Errors go to errw.
func WriteText(w, errw io.Writer, results []Result) {
	for _, r := range results {
		_, _ = fmt.Fprintf(w, "%s %s %s %s\n", r.Pin.Info.Name, r.PinnedLabel(), r.LatestLabel(), r.Class)
		if r.Err != nil {
			_, _ = fmt.Fprintf(errw, "upstreamwatch: %s: %v\n", r.Pin.Info.Name, r.Err)
		}
	}
}

// WriteJSON prints the results as a JSON array.
func WriteJSON(w io.Writer, results []Result) error {
	type row struct {
		Name         string `json:"name"`
		Pinned       string `json:"pinned"`
		Latest       string `json:"latest,omitempty"`
		Class        string `json:"class"`
		ReleaseNotes string `json:"release_notes,omitempty"`
		Error        string `json:"error,omitempty"`
	}
	rows := make([]row, 0, len(results))
	for _, r := range results {
		x := row{Name: r.Pin.Info.Name, Pinned: r.PinnedLabel(), Latest: r.Latest, Class: r.Class, ReleaseNotes: r.ReleaseNotes()}
		if r.Err != nil {
			x.Error = r.Err.Error()
		}
		rows = append(rows, x)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}
