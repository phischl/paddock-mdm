package agent

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"slices"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/agent/internal/selfservice"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// TestSelfServiceWiring: the self-service socket exists while the agent runs (mode 0666) and is gone after it stopped,
// and the run loop spools the self-service events (here the operation a previous process left running, F4) and the
// software requests (plan M13c decision 9).
func TestSelfServiceWiring(t *testing.T) {
	g := testgw.New(t)
	g.Checkin.NextCheckinS = 3600
	a := newAgent(t, g)
	sys := fakesys.New()
	marker := `{"id":"op1","uid":200001,"user":"alice@example.org","entry_id":"aaaaaaaa-0000-4000-8000-000000000001",` +
		`"package":"code","scope":"system","action":"install","started_at":"2026-11-09T10:00:00Z"}`
	if err := sys.WriteFileAtomic(selfservice.RunningFile, []byte(marker), 0o600, 0, 0); err != nil {
		t.Fatal(err)
	}
	a.d.SelfService = selfservice.New(selfservice.Config{Sys: sys, Packages: &reconcile.Software{Sys: sys}, Version: "test"})
	a.current = &bundle.Bundle{BundleVersion: 1, Software: &bundle.SoftwareSpec{Packages: []bundle.SoftwarePackage{{Package: "code",
		Intent: bundle.SoftwareAvailable, CatalogEntryID: "aaaaaaaa-0000-4000-8000-000000000001", Audience: &bundle.SoftwareAudience{All: true},
		Approval: bundle.SoftwareApprovalRequired}}}}
	path := a.d.Layout.SelfServiceSocket()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("socket before the start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitFor(t, func() bool { fi, err := os.Lstat(path); return err == nil && fi.Mode().Perm() == 0o666 })
	waitFor(t, func() bool {
		pending, _ := a.d.Spool.Pending()
		return slices.ContainsFunc(pending, func(ev protocol.Event) bool { return ev.Type == protocol.EventSoftwareSelfService }) ||
			slices.Contains(g.EventTypes(), protocol.EventSoftwareSelfService)
	})
	alice := selfservice.Principal{UID: 200001, Name: "alice@example.org", UPN: "alice@example.org", Directory: true}
	waitFor(t, func() bool {
		_, err := a.d.SelfService.Request(alice, "aaaaaaaa-0000-4000-8000-000000000001", "for work")
		return err == nil
	})
	waitFor(t, func() bool {
		pending, _ := a.d.Spool.Pending()
		return slices.ContainsFunc(pending, func(ev protocol.Event) bool { return ev.Type == protocol.EventSoftwareRequest }) ||
			slices.Contains(g.EventTypes(), protocol.EventSoftwareRequest)
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("socket after the stop: %v", err)
	}
}
