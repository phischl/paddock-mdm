package acceptance

import (
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// TestAuditIndexPurge is gate R4 (plan M10 §9, PDK-140): the dry run of the audit index purge runs in the audit-writer
// container with the writer's credentials and, as no partition of the development stack is older than the 400-day
// retention, prints "nothing to purge" or KEEP lines only.
func TestAuditIndexPurge(t *testing.T) {
	ctx := testContext(t, 2*time.Minute)
	code, out, err := stack.PaddockServer(ctx, "audit", "purge", "--dry-run")
	if err != nil || code != 0 {
		t.Fatalf("audit purge --dry-run: exit %d, %v\n%s", code, err, out)
	}
	nothing, keep := false, 0
	for _, line := range strings.Split(out, "\n") {
		switch {
		case line == "nothing to purge":
			nothing = true
		case strings.HasPrefix(line, "KEEP "):
			keep++
		case strings.HasPrefix(line, "DROP "), strings.HasPrefix(line, "FAIL "):
			t.Errorf("the development stack has a partition past the retention: %s", line)
		}
	}
	if nothing == (keep > 0) {
		t.Errorf("want either \"nothing to purge\" or KEEP lines, got:\n%s", out)
	}
}
