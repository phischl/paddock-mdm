package devicecache_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
)

// TestDeleteOrganizationKeys (plan M17 decision 13, amendment k addendum point 2): under the worker's real ACL user the
// deletion removes every device key of the organization and its time ticket, bp: and tt: included, and leaves another
// organization's keys alone. A single DEL that mixes bp: with dk: is refused for the worker, which is why the two go in
// calls of their own.
func TestDeleteOrganizationKeys(t *testing.T) {
	srv := valkeytest.StartACL(t)
	admin, worker := srv.Client(t, "acceptance"), srv.Client(t, "worker")
	ctx := context.Background()
	org, other := uuid.New(), uuid.New()
	dev, otherDev := uuid.New(), uuid.New()
	keysOf := func(o, d uuid.UUID, keyID string) []string {
		return []string{"cmd:" + d.String(), "seq:" + d.String(), "sd:" + d.String(), "bp:" + d.String(), "hb:" + d.String(),
			"au:" + d.String(), "dk:" + keyID, "tt:" + o.String()}
	}
	mine, theirs := keysOf(org, dev, "key-a"), keysOf(other, otherDev, "key-b")
	for _, k := range append(append([]string{}, mine...), theirs...) {
		if err := admin.Do(ctx, admin.B().Set().Key(k).Value("x").Build()).Error(); err != nil {
			t.Fatal(err)
		}
	}

	err := worker.Do(ctx, worker.B().Del().Key("dk:key-b", "bp:"+otherDev.String()).Build()).Error()
	if err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Fatalf("a mixed DEL of the worker: %v, want NOPERM", err)
	}

	n, err := devicecache.New(worker).DeleteOrganization(ctx, org, []uuid.UUID{dev}, []string{"key-a"})
	if err != nil || n != int64(len(mine)) {
		t.Fatalf("DeleteOrganization = %d, %v; want %d", n, err, len(mine))
	}
	count := func(keys []string) int64 {
		n, err := admin.Do(ctx, admin.B().Exists().Key(keys...).Build()).AsInt64()
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if left := count(mine); left != 0 {
		t.Fatalf("%d keys of the organization remain", left)
	}
	if kept := count(theirs); kept != int64(len(theirs)) {
		t.Fatalf("another organization kept %d of %d keys", kept, len(theirs))
	}
	if n, err := devicecache.New(worker).DeleteOrganization(ctx, org, []uuid.UUID{dev}, []string{"key-a"}); err != nil || n != 0 {
		t.Fatalf("second deletion = %d, %v", n, err)
	}
}
