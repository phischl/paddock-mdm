package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
)

// fakeAuthentik answers blueprint lookups from a table; paths without an entry are not discovered yet.
type fakeAuthentik struct {
	mu     sync.Mutex
	status map[string]env.Blueprint
	err    error
}

func (f *fakeAuthentik) Blueprint(_ context.Context, path string) (env.Blueprint, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return env.Blueprint{}, false, f.err
	}
	b, ok := f.status[path]
	return b, ok, nil
}

func TestWaitBlueprintsTimeoutNamesPendingBlueprints(t *testing.T) {
	paths, err := paddockBlueprints()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) < 2 {
		t.Fatalf("expected at least two blueprints, found %v", paths)
	}
	ak := &fakeAuthentik{status: map[string]env.Blueprint{
		paths[0]: {Name: "Paddock first", Path: paths[0], Status: "successful"},
		paths[1]: {Name: "Paddock second", Path: paths[1], Status: "error"},
	}}
	err = waitBlueprints(context.Background(), ak, 50*time.Millisecond, 10*time.Millisecond)
	if err == nil {
		t.Fatal("wait succeeded although a blueprint failed")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "authentik blueprints not applied after 50ms: ") {
		t.Fatalf("message %q", msg)
	}
	if !strings.Contains(msg, "Paddock second ("+paths[1]+"): error") {
		t.Fatalf("message does not name the failed blueprint: %q", msg)
	}
	if strings.Contains(msg, paths[0]) {
		t.Fatalf("message names an applied blueprint: %q", msg)
	}
	for _, p := range paths[2:] {
		if !strings.Contains(msg, p+": not discovered") {
			t.Fatalf("message does not name the undiscovered blueprint %s: %q", p, msg)
		}
	}
}

func TestWaitBlueprintsTimeoutKeepsLastAPIError(t *testing.T) {
	paths, err := paddockBlueprints()
	if err != nil {
		t.Fatal(err)
	}
	ak := &fakeAuthentik{err: errors.New("HTTP 503")}
	err = waitBlueprints(context.Background(), ak, 30*time.Millisecond, 10*time.Millisecond)
	// Authentik never answered: every blueprint is still pending, and the API error is reported.
	if err == nil || !strings.Contains(err.Error(), strings.Join(paths, "; ")) || !strings.HasSuffix(err.Error(), "(last API error: HTTP 503)") {
		t.Fatalf("error %v", err)
	}
}

func TestWaitBlueprintsSucceedsOnceAllAreApplied(t *testing.T) {
	paths, err := paddockBlueprints()
	if err != nil {
		t.Fatal(err)
	}
	ak := &fakeAuthentik{status: map[string]env.Blueprint{}}
	go func() {
		time.Sleep(30 * time.Millisecond)
		ak.mu.Lock()
		defer ak.mu.Unlock()
		for _, p := range paths {
			ak.status[p] = env.Blueprint{Name: p, Path: p, Status: "successful"}
		}
	}()
	if err := waitBlueprints(context.Background(), ak, 5*time.Second, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}
