package authentik_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/adapters/authentik"
)

var uuidPattern = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// ensureDescription describes what EnsureOrganization creates and corrects: every request it sends to an empty
// Authentik and then to the Authentik it filled, with method, path, query and body. Primary keys are replaced by the
// name of the object they point to, so the description is the same on every run; the order of the requests is not
// part of it, because independent steps run concurrently.
func ensureDescription(t *testing.T) []string {
	t.Helper()
	f, srv := newFake(t)
	c := client(srv)
	var lines []string
	for _, run := range []string{"create", "steady"} {
		f.served = nil
		if _, err := c.EnsureOrganization(context.Background(), "acme"); err != nil {
			t.Fatal(err)
		}
		labels := map[string]string{}
		for _, g := range f.groups {
			labels[g.pk] = "group:" + g.name
		}
		for collection, objects := range f.objects {
			for pk, obj := range objects {
				name, _ := obj["name"].(string)
				if slug, ok := obj["slug"].(string); ok {
					name = slug
				}
				labels[pk] = collection + ":" + name
				if own, ok := obj["pk"]; ok {
					labels[fmt.Sprint(own)] = collection + ":" + name
				}
			}
		}
		label := func(s string) string {
			if l, ok := labels[s]; ok {
				return l
			}
			return uuidPattern.ReplaceAllString(s, "<uuid>")
		}
		var normalize func(v any) any
		normalize = func(v any) any {
			switch v := v.(type) {
			case string:
				return label(v)
			case float64:
				if l, ok := labels[strconv.FormatFloat(v, 'f', -1, 64)]; ok {
					return l
				}
				return v
			case []any:
				out := make([]any, len(v))
				for i, e := range v {
					out[i] = normalize(e)
				}
				if slices.ContainsFunc(out, func(e any) bool { _, ok := e.(string); return !ok }) {
					return out
				}
				// Lists of references are sets to Authentik; their order follows the random primary keys.
				slices.SortFunc(out, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
				return out
			case map[string]any:
				out := map[string]any{}
				for k, e := range v {
					out[k] = normalize(e)
				}
				return out
			}
			return v
		}
		for _, r := range f.served {
			segments := strings.Split(r.path, "/")
			for i, s := range segments {
				segments[i] = label(s)
			}
			var query []string
			for k, vs := range r.query {
				for _, v := range vs {
					query = append(query, k+"="+label(v))
				}
			}
			slices.Sort(query)
			body, err := json.Marshal(normalize(map[string]any(r.body)))
			if err != nil {
				t.Fatal(err)
			}
			lines = append(lines, fmt.Sprintf("%s %s %s?%s %s", run, r.method, strings.Join(segments, "/"), strings.Join(query, "&"), body))
		}
	}
	slices.Sort(lines)
	return lines
}

// TestEnsureRevision (PDK-1021, plan M17 decision 20) pins authentik.EnsureRevision to the hash of what
// EnsureOrganization creates and corrects. A change of a request (an object, a field, a lookup) changes the hash and
// fails this test: set EnsureRevision to the new value, so every organization is ensured in full once more.
func TestEnsureRevision(t *testing.T) {
	first := ensureDescription(t)
	if again := ensureDescription(t); !slices.Equal(first, again) {
		t.Fatalf("the description is not stable:\n%s\n---\n%s", strings.Join(first, "\n"), strings.Join(again, "\n"))
	}
	sum := sha256.Sum256([]byte(strings.Join(first, "\n")))
	if got := hex.EncodeToString(sum[:])[:16]; got != authentik.EnsureRevision {
		t.Fatalf("EnsureOrganization's requests changed: set authentik.EnsureRevision to %q (is %q)\n%s", got,
			authentik.EnsureRevision, strings.Join(first, "\n"))
	}
}
