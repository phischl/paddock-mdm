package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Title is the issue title of an outdated pin.
func Title(r Result) string {
	return fmt.Sprintf("upstream: %s %s → %s", r.Pin.Info.Name, r.PinnedLabel(), r.LatestLabel())
}

func titlePrefix(name string) string { return "upstream: " + name + " " }

// Body is the issue body of an outdated pin: the pinned line, the latest version, the classification, the followed
// line when the pin has one, the release notes and the gates to run before the bump.
func Body(r Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**Pinned** in `%s`:\n\n```\n%s\n```\n\n", r.Pin.File, r.Pin.Line)
	fmt.Fprintf(&b, "**Latest:** `%s`\n\n", r.Latest)
	fmt.Fprintf(&b, "**Classification:** %s\n\n", r.Class)
	if r.Pin.Info.Line != "" {
		fmt.Fprintf(&b, "**Line:** this pin follows the `%s` line only; newer lines are not reported (plan M6d decision 10).\n\n", r.Pin.Info.Line)
	}
	if notes := r.ReleaseNotes(); notes != "" {
		fmt.Fprintf(&b, "**Release notes:** %s\n\n", notes)
	} else {
		b.WriteString("**Release notes:** the project publishes none the watch knows of; check the image's registry page.\n\n")
	}
	b.WriteString("**Gates to run before the bump:**\n\n")
	for _, g := range r.Pin.Info.Gates {
		fmt.Fprintf(&b, "- %s\n", g)
	}
	b.WriteString("\nOpened by the upstream version watch (`tools/upstreamwatch`, `docs/operations/upgrade.md`). " +
		"It edits this issue when upstream moves again and closes it once the pin is current.\n")
	return b.String()
}

func outdated(class string) bool {
	switch class {
	case ClassPatch, ClassMinor, ClassMajor, ClassDigest:
		return true
	}
	return false
}

// Reconcile keeps exactly one open issue per outdated pin: it creates a missing one, edits one whose latest
// version moved, and comments and closes the issue of a pin that is current again. Unknown pins are left alone.
func Reconcile(ctx context.Context, gh GitHub, repo string, results []Result) error {
	open, err := gh.List(ctx, repo)
	if err != nil {
		return fmt.Errorf("list issues: %w", err)
	}
	var errs []error
	for _, r := range results {
		var existing *Issue
		for i := range open {
			if strings.HasPrefix(open[i].Title, titlePrefix(r.Pin.Info.Name)) {
				existing = &open[i]
				break
			}
		}
		switch {
		case outdated(r.Class) && existing == nil:
			if err := gh.Create(ctx, repo, Title(r), Body(r)); err != nil {
				errs = append(errs, fmt.Errorf("%s: create: %w", r.Pin.Info.Name, err))
			}
		case outdated(r.Class) && existing.Title != Title(r):
			if err := gh.Edit(ctx, repo, existing.Number, Title(r), Body(r)); err != nil {
				errs = append(errs, fmt.Errorf("%s: edit %s: %w", r.Pin.Info.Name, issueNumber(existing.Number), err))
			}
		case r.Class == ClassOK && existing != nil:
			err := gh.Comment(ctx, repo, existing.Number, "pinned "+r.PinnedLabel()+" now")
			if err == nil {
				err = gh.Close(ctx, repo, existing.Number)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: close %s: %w", r.Pin.Info.Name, issueNumber(existing.Number), err))
			}
		}
	}
	return errors.Join(errs...)
}
