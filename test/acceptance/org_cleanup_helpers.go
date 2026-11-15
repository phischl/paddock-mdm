package acceptance

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// orgCleanupWait bounds how long a gate waits for the worker to delete its organization (plan M17 §7 step 7).
const orgCleanupWait = 5 * time.Minute

// orgCleanupStepUpAge is below the shortest step-up window of the admin API (5 minutes), so a deletion request never
// runs on an expired step-up.
const orgCleanupStepUpAge = 3 * time.Minute

// orgCleaner is the one platform administrator session that deletes the gates' organizations. A step-up of a session
// races with every other request on it (PDK-445) and Authentik hands out one TOTP code per 30 s step, so the cleanups
// of parallel cases share the session and take turns.
var orgCleaner struct {
	mu        sync.Mutex
	portal    *env.Portal
	steppedUp time.Time
}

// withCleanupSession runs fn on the cleanup session, signing in and stepping up first when due.
func withCleanupSession(ctx context.Context, fn func(p *env.Portal) error) error {
	orgCleaner.mu.Lock()
	defer orgCleaner.mu.Unlock()
	if orgCleaner.portal == nil {
		p, err := env.Login(ctx, env.PlatformAdmin, "")
		if err != nil {
			return err
		}
		orgCleaner.portal = p
	}
	if orgCleaner.steppedUp.IsZero() || time.Since(orgCleaner.steppedUp) > orgCleanupStepUpAge {
		final, err := orgCleaner.portal.StepUp(ctx, env.PlatformAdmin, "/settings")
		if err != nil {
			return err
		}
		if strings.Contains(final, "stepup=failed") {
			orgCleaner.portal = nil
			return errors.New("step-up of the cleanup session failed")
		}
		orgCleaner.steppedUp = time.Now()
	}
	return fn(orgCleaner.portal)
}

// gateOrgState is the part of an organization the cleanup looks at.
type gateOrgState struct {
	Status   string `json:"status"`
	Deletion *struct {
		Step          *string `json:"step"`
		LastErrorCode *string `json:"last_error_code"`
	} `json:"deletion"`
}

func readGateOrg(ctx context.Context, p *env.Portal, id string) (gateOrgState, int, error) {
	var st gateOrgState
	res, err := p.Do(ctx, http.MethodGet, orgPath+id, nil)
	if err != nil {
		return st, 0, err
	}
	if res.Status == http.StatusOK {
		err = res.JSON(&st)
	}
	return st, res.Status, err
}

// deleteGateOrgAtEnd registers the deletion of a gate organization for the end of the case, with grace_days 0 (a
// development stack allows it, ADR 0052). Leftover organizations make the identity provider's periodic rounds cost
// CPU on a long-lived stack (PDK-946), so every organization a gate creates is deleted again. A cleanup that fails
// is logged and never fails the gate: the case's verdict is already in, and `make dev-prune-gate-orgs` removes what
// is left.
func deleteGateOrgAtEnd(t *testing.T, id, slug string) {
	t.Helper()
	t.Cleanup(func() {
		// Not testContext: its cancel is registered as a cleanup of its own and would run before this one.
		ctx, cancel := context.WithTimeout(context.Background(), orgCleanupWait+10*time.Minute)
		defer cancel()
		if err := cleanupGateOrg(ctx, id, slug); err != nil {
			t.Logf("cleanup of gate organization %s (%s): %v; make dev-prune-gate-orgs removes it", slug, id, err)
		}
	})
}

func cleanupGateOrg(ctx context.Context, id, slug string) error {
	var skip error
	err := withCleanupSession(ctx, func(p *env.Portal) error {
		res, err := p.Do(ctx, http.MethodPost, orgPath+id+"/delete",
			map[string]any{"confirm_slug": slug, "reason": "gate cleanup", "grace_days": 0})
		if err != nil {
			return err
		}
		switch res.Status {
		case http.StatusAccepted:
		case http.StatusConflict:
			// A case that requested the deletion itself leaves it running or done; one that left a pending deletion
			// with a grace period (or an organization still provisioning) is not ours to wait for.
			st, _, err := readGateOrg(ctx, p, id)
			if err != nil {
				return err
			}
			if st.Status != "deleting" && st.Status != "deleted" {
				skip = fmt.Errorf("deletion refused (409) and the organization is %s", st.Status)
			}
		default:
			return fmt.Errorf("delete: HTTP %d %s", res.Status, res.ProblemCode())
		}
		return nil
	})
	if err != nil {
		return err
	}
	if skip != nil {
		return skip
	}

	deadline := time.Now().Add(orgCleanupWait)
	var last gateOrgState
	for {
		var code int
		err := withCleanupSession(ctx, func(p *env.Portal) error {
			var err error
			last, code, err = readGateOrg(ctx, p, id)
			return err
		})
		if err == nil && (code == http.StatusNotFound || (code == http.StatusOK && last.Status == "deleted")) {
			return nil
		}
		if time.Now().After(deadline) {
			// Until audit_final is implemented (PDK-1017) the step completes at once; afterwards a stuck step shows here.
			return fmt.Errorf("not deleted within %s: status %q%s", orgCleanupWait, last.Status, stepOf(last))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func stepOf(st gateOrgState) string {
	if st.Deletion == nil {
		return ""
	}
	out := ""
	if st.Deletion.Step != nil {
		out += ", step " + *st.Deletion.Step
	}
	if st.Deletion.LastErrorCode != nil {
		out += ", last error " + *st.Deletion.LastErrorCode
	}
	return out
}
