package acceptance

import (
	"net/http"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// stagedResult is the part of ConfigApplyResult the staging gate reads.
type stagedResult struct {
	ChangeSetID *string `json:"change_set_id"`
	Rollout     *string `json:"rollout"`
	RolloutID   *string `json:"rollout_id"`
}

func stagedResultOf(t *testing.T, res env.Response) stagedResult {
	t.Helper()
	expectStatus(t, res, http.StatusOK, "")
	var out stagedResult
	if err := res.JSON(&out); err != nil {
		t.Fatal(err)
	}
	return out
}
