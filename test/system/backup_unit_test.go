package system

import (
	"slices"
	"testing"
	"time"
)

func TestSetEnvLine(t *testing.T) {
	in := "A=1\n# PADDOCK_LAB_BACKUP=no\nPADDOCK_LAB_BACKUP=no\n"
	if got := setEnvLine(in, "PADDOCK_LAB_BACKUP", "yes"); got != "A=1\nPADDOCK_LAB_BACKUP=yes\nPADDOCK_LAB_BACKUP=no\n" {
		t.Fatalf("the commented default is not replaced first: %q", got)
	}
	if got := setEnvLine("A=1\n", "B", "2"); got != "A=1\nB=2\n" {
		t.Fatalf("a missing name is not appended: %q", got)
	}
	if got := setEnvLine("AB=1\n", "A", "2"); got != "AB=1\nA=2\n" {
		t.Fatalf("a name that only prefixes another is replaced: %q", got)
	}
}

func TestAlertActive(t *testing.T) {
	body := `{"data":{"alerts":[{"labels":{"alertname":"PaddockBackupTargetUnreachable","target":"nas"},"state":"pending"},
		{"labels":{"alertname":"PaddockBackupTargetUnreachable","target":"other"},"state":"inactive"}]}}`
	for _, c := range []struct {
		target string
		want   bool
	}{{"nas", true}, {"other", false}, {"none", false}} {
		if got := alertActive(body, "PaddockBackupTargetUnreachable", c.target); got != c.want {
			t.Errorf("target %s: %v, want %v", c.target, got, c.want)
		}
	}
	if alertActive("not json", "PaddockBackupTargetUnreachable", "nas") {
		t.Error("an unreadable answer counts as active")
	}
}

func TestMirroredSince(t *testing.T) {
	since := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	before, after := since.Add(-time.Minute), since.Add(time.Minute)
	status := func(times map[string]*time.Time) labTarget {
		var bt labTarget
		for k, v := range times {
			bt.Status = append(bt.Status, labKindStatus{Kind: k, LastSuccessAt: v})
		}
		return bt
	}
	all := map[string]*time.Time{"postgres": &after, "openbao": &after, "fleet": &after, "escrow": &after}
	if !status(all).mirroredSince(since) {
		t.Error("every kind after since is not mirrored")
	}
	all["authentik"] = &before
	if status(all).mirroredSince(since) {
		t.Error("an older authentik set counts as mirrored")
	}
	if status(map[string]*time.Time{"postgres": &after, "openbao": &after, "fleet": &after}).mirroredSince(since) {
		t.Error("a missing escrow kind counts as mirrored")
	}
	if status(map[string]*time.Time{"postgres": &after, "openbao": nil, "fleet": &after, "escrow": &after}).mirroredSince(since) {
		t.Error("a kind without a success counts as mirrored")
	}
}

func TestFailedWith(t *testing.T) {
	shrunk, io := classSetShrunk, "io"
	target := func(errs ...*string) labTarget {
		var bt labTarget
		for i, e := range errs {
			bt.Status = append(bt.Status, labKindStatus{Kind: backupKinds[i], LastError: e})
		}
		return bt
	}
	if !target(&shrunk, &shrunk, &shrunk, &shrunk).failedWith(classSetShrunk) {
		t.Error("every kind set_shrunk is not reported")
	}
	if target(&shrunk, &io, &shrunk, &shrunk).failedWith(classSetShrunk) {
		t.Error("a kind with another class counts as set_shrunk")
	}
	if target(&shrunk, nil, &shrunk, &shrunk).failedWith(classSetShrunk) {
		t.Error("a kind without an error counts as set_shrunk")
	}
	if !target(nil, nil, nil, nil).failedWith("") {
		t.Error("a target without errors is not reported clean")
	}
	if target(nil, &io, nil, nil).failedWith("") {
		t.Error("a target with one error counts as clean")
	}
	if target().failedWith("") {
		t.Error("a target without any status counts as clean")
	}
}

func TestListingDiff(t *testing.T) {
	before := "a 1 10\nb 2 20\n"
	if d := listingDiff(before, "b 2 20\na 1 10"); len(d) != 0 {
		t.Errorf("the same objects in another order differ: %v", d)
	}
	got := listingDiff(before, "a 1 10\nb 3 30\nc 4 40\n")
	if want := []string{"+ b 3 30", "+ c 4 40", "- b 2 20"}; !slices.Equal(got, want) {
		t.Errorf("diff %v, want %v", got, want)
	}
	if got := listingDiff(before, ""); !slices.Equal(got, []string{"- a 1 10", "- b 2 20"}) {
		t.Errorf("an emptied target: %v", got)
	}
}

func TestParamHas(t *testing.T) {
	params := map[string]any{"components": []any{"backup-repo"}, "source": "target"}
	if !paramHas(params, "components", "backup-repo") {
		t.Error("a listed component is not found")
	}
	if paramHas(params, "components", "postgres") || paramHas(params, "source", "target") || paramHas(params, "missing", "x") {
		t.Error("an unlisted value, a scalar param or a missing param counts as listed")
	}
}
