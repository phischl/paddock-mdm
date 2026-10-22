//go:build !paddock_dev

package agent

import (
	"context"
	"os"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// TestReleaseBuildWritesNoTestHooks: a build without paddock_dev never lets the init script honour the test delays
// (plan M8e decision 19, PDK-391). The preparation runs through the agent's own wiring to the end, so that a preparer
// built with test hooks would have written the marker next to the plan.
func TestReleaseBuildWritesNoTestHooks(t *testing.T) {
	if buildinfo.Dev {
		t.Fatal("buildinfo.Dev is true without the paddock_dev tag")
	}
	a, _, _ := convAgent(t)
	if p := a.preparer(context.Background()); p.TestHooks {
		t.Fatal("the agent builds its preparer with test hooks")
	}
	if status, _ := a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1",
		`{"conversion_id":"`+testConversionID+`"}`)); status != protocol.CommandSucceeded {
		t.Fatal("not accepted")
	}
	runWorker(t, a)
	if a.st.Conversion.Phase != state.ConversionPrepared {
		t.Fatalf("conversion %+v", a.st.Conversion)
	}
	if _, err := os.Stat(a.d.Layout.EncryptPlanEnv()); err != nil {
		t.Fatalf("plan env: %v", err)
	}
	if _, err := os.Stat(a.d.Layout.EncryptTestHooks()); !os.IsNotExist(err) {
		t.Fatalf("test hooks marker %s: %v, want not exist", a.d.Layout.EncryptTestHooks(), err)
	}
}
