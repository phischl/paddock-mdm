package commands_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/commands"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

func TestRunMarksBeforeExecutingAndPrunes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ran := false
	e := commands.New(map[string]commands.Handler{"test": func(context.Context, *command.Command) (string, map[string]any) {
		ran = true
		return protocol.CommandSucceeded, nil
	}}, func() time.Time { return now })
	env := testgw.SignedCommand(t, command.Command{CommandID: "0190f000-0000-7000-8000-0000000000c1", DeviceID: testgw.DeviceID,
		OrganizationID: testgw.OrgID, Type: "test", IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	executed := map[string]time.Time{"old": now.Add(-commands.Retention - time.Hour), "recent": now.Add(-time.Hour)}

	// The record of the command cannot be saved: the handler does not run, the command stays unexecuted.
	res, err := commands.New(nil, func() time.Time { return now }).Run(context.Background(), []json.RawMessage{env}, testgw.CommandKeys(),
		testgw.DeviceID, testgw.OrgID, executed, func() error { return errors.New("disk full") })
	if err == nil || len(res) != 0 || ran {
		t.Fatalf("mark failure: %v %v", res, err)
	}
	if _, ok := executed["0190f000-0000-7000-8000-0000000000c1"]; ok {
		t.Fatal("unsaved command recorded as executed")
	}
	if _, ok := executed["old"]; ok {
		t.Fatal("entries older than 60 days are kept")
	}

	marked := 0
	res, err = e.Run(context.Background(), []json.RawMessage{env, env}, testgw.CommandKeys(), testgw.DeviceID, testgw.OrgID, executed,
		func() error { marked++; return nil })
	if err != nil || len(res) != 1 || !ran || marked != 1 || res[0].Status != "succeeded" || string(res[0].Result) != "{}" {
		t.Fatalf("run: %+v %v, marked %d", res, err, marked)
	}
	if _, err := e.Run(context.Background(), []json.RawMessage{env}, nil, testgw.DeviceID, testgw.OrgID, executed, nil); !errors.Is(err, commands.ErrNoKeys) {
		t.Fatalf("without keys: %v", err)
	}
}
