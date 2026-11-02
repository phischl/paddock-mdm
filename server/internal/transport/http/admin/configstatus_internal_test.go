package admin

import (
	"errors"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/problem"
)

func TestBundleOutcomes(t *testing.T) {
	if got, err := bundleOutcomes([]string{"applied", "none"}); err != nil || len(got) != 2 {
		t.Fatalf("valid outcomes: %v, %v", got, err)
	}
	if got, err := bundleOutcomes(nil); err != nil || got != nil {
		t.Fatalf("no filter: %v, %v", got, err)
	}
	if _, err := bundleOutcomes([]string{"applied", "bogus"}); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("unknown outcome = %v", err)
	}
}
