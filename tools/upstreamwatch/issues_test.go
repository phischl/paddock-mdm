package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fakeGitHub keeps issues in memory and records every call.
type fakeGitHub struct {
	issues  map[int]*Issue
	closed  map[int]bool
	calls   []string
	next    int
	failAll bool
}

func newFakeGitHub() *fakeGitHub {
	return &fakeGitHub{issues: map[int]*Issue{}, closed: map[int]bool{}, next: 1}
}

func (f *fakeGitHub) List(_ context.Context, repo string) ([]Issue, error) {
	f.calls = append(f.calls, "list "+repo)
	if f.failAll {
		return nil, errors.New("gh: HTTP 502")
	}
	var out []Issue
	for n := 1; n < f.next; n++ {
		if is, ok := f.issues[n]; ok && !f.closed[n] {
			out = append(out, *is)
		}
	}
	return out, nil
}

func (f *fakeGitHub) Create(_ context.Context, _, title, body string) error {
	f.calls = append(f.calls, "create "+title)
	f.issues[f.next] = &Issue{Number: f.next, Title: title, Body: body}
	f.next++
	return nil
}

func (f *fakeGitHub) Edit(_ context.Context, _ string, n int, title, body string) error {
	f.calls = append(f.calls, fmt.Sprintf("edit #%d %s", n, title))
	f.issues[n].Title, f.issues[n].Body = title, body
	return nil
}

func (f *fakeGitHub) Comment(_ context.Context, _ string, n int, body string) error {
	f.calls = append(f.calls, fmt.Sprintf("comment #%d %s", n, body))
	return nil
}

func (f *fakeGitHub) Close(_ context.Context, _ string, n int) error {
	f.calls = append(f.calls, fmt.Sprintf("close #%d", n))
	f.closed[n] = true
	return nil
}

func himmelblauResult(pinned, latest string) Result {
	p := Pin{
		Info: PinInfo{Name: "himmelblau", Gates: []string{gateHimmelblau}}, Kind: KindHimmelblau,
		File: "server/cmd/paddock-server/compiler.go", Line: `himmelblau := l.String("PADDOCK_HIMMELBLAU_VERSION", "` + pinned + `")`,
		Pinned: pinned,
	}
	return Result{Pin: p, Latest: latest, Class: Classify(pinned, latest)}
}

func TestReconcileLifecycle(t *testing.T) {
	ctx := context.Background()
	gh := newFakeGitHub()
	// An unrelated upstream issue of another pin stays untouched.
	gh.issues[gh.next] = &Issue{Number: gh.next, Title: "upstream: himmelblau-extra 1 → 2"}
	gh.next++

	if err := Reconcile(ctx, gh, "o/r", []Result{himmelblauResult("4.0.4", "4.0.6")}); err != nil {
		t.Fatal(err)
	}
	created := gh.issues[2]
	if created == nil || created.Title != "upstream: himmelblau 4.0.4 → 4.0.6" {
		t.Fatalf("issues = %+v", gh.issues)
	}
	for _, want := range []string{
		"`server/cmd/paddock-server/compiler.go`", `"PADDOCK_HIMMELBLAU_VERSION", "4.0.4"`,
		"**Latest:** `4.0.6`", "**Classification:** patch",
		"**Release notes:** https://packages.himmelblau-idm.org/stable/4.0.6/",
		"- make system-test VM=all T=TestIdentity",
	} {
		if !strings.Contains(created.Body, want) {
			t.Errorf("body lacks %q:\n%s", want, created.Body)
		}
	}

	// Same state again: nothing changes.
	gh.calls = nil
	if err := Reconcile(ctx, gh, "o/r", []Result{himmelblauResult("4.0.4", "4.0.6")}); err != nil {
		t.Fatal(err)
	}
	if len(gh.calls) != 1 {
		t.Fatalf("idempotent run called %v", gh.calls)
	}

	// Upstream moved to 4.0.7: the same issue is edited, no second one.
	if err := Reconcile(ctx, gh, "o/r", []Result{himmelblauResult("4.0.4", "4.0.7")}); err != nil {
		t.Fatal(err)
	}
	if len(gh.issues) != 2 || gh.issues[2].Title != "upstream: himmelblau 4.0.4 → 4.0.7" || !strings.Contains(gh.issues[2].Body, "4.0.7") {
		t.Fatalf("after 4.0.7: %+v", gh.issues)
	}

	// An unknown lookup leaves the issue alone.
	gh.calls = nil
	unknown := himmelblauResult("4.0.4", "")
	unknown.Class = ClassUnknown
	if err := Reconcile(ctx, gh, "o/r", []Result{unknown}); err != nil || len(gh.calls) != 1 {
		t.Fatalf("unknown run: %v %v", err, gh.calls)
	}

	// After the bump: comment and close.
	gh.calls = nil
	if err := Reconcile(ctx, gh, "o/r", []Result{himmelblauResult("4.0.7", "4.0.7")}); err != nil {
		t.Fatal(err)
	}
	want := []string{"list o/r", "comment #2 pinned 4.0.7 now", "close #2"}
	if strings.Join(gh.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %v, want %v", gh.calls, want)
	}
	if gh.closed[1] {
		t.Fatal("the unrelated issue was closed")
	}
}

func TestBodyNamesTheFollowedLine(t *testing.T) {
	mysql := Pin{
		Info: PinInfo{Name: "fleet_mysql", Line: "8.4.", Gates: []string{gateFleet}}, Kind: KindImage,
		File: "deploy/compose/versions.env", Line: "FLEET_MYSQL_IMAGE=mysql:8.4.11@sha256:aa", Pinned: "8.4.11",
	}
	body := Body(Result{Pin: mysql, Latest: "8.4.13", Class: ClassPatch})
	if want := "**Line:** this pin follows the `8.4.` line only; newer lines are not reported (plan M6d decision 10)."; !strings.Contains(body, want) {
		t.Errorf("body lacks %q:\n%s", want, body)
	}

	postgres := Pin{
		Info: imagePins()["POSTGRES_IMAGE"], Kind: KindImage,
		File: "deploy/compose/versions.env", Line: "POSTGRES_IMAGE=postgres:17.6@sha256:bb", Pinned: "17.6",
	}
	if body := Body(Result{Pin: postgres, Latest: "18.0", Class: ClassMajor}); strings.Contains(body, "**Line:**") {
		t.Errorf("body of a pin without a line names one:\n%s", body)
	}
}

func TestReconcileReportsGitHubFailure(t *testing.T) {
	gh := newFakeGitHub()
	gh.failAll = true
	if err := Reconcile(context.Background(), gh, "o/r", []Result{himmelblauResult("4.0.4", "4.0.6")}); err == nil {
		t.Fatal("a failing list was not reported")
	}
}

func TestIssuesCommand(t *testing.T) {
	srv := fakeUpstream(t)
	gh := newFakeGitHub()
	var out, errOut strings.Builder
	code := run(context.Background(), []string{"issues", "--repo", "o/r", "--versions", "testdata/versions.env", "--compiler", "testdata/compiler.go.txt"},
		&out, &errOut, upstreamAt(srv.URL, srv.Client()), gh)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	var titles []string
	for n := 1; n < gh.next; n++ {
		titles = append(titles, gh.issues[n].Title)
	}
	want := []string{
		"upstream: caddy 2.11.6 → 2.11.7",
		"upstream: authentik 2026.8.3 → 2026.10.1",
		"upstream: runtime nonroot@sha256:afa5c872c891 → nonroot@sha256:111111111111",
		"upstream: fleet_nvd 202610120101 → 202610180059",
		"upstream: himmelblau 4.0.4 → 4.0.6",
	}
	if strings.Join(titles, "|") != strings.Join(want, "|") {
		t.Fatalf("titles = %v", titles)
	}
	if !strings.Contains(gh.issues[1].Body, "make restore-drill") || !strings.Contains(gh.issues[2].Body, "TestIdentityLockAuthentik") {
		t.Fatal("gates missing from the bodies")
	}
}
