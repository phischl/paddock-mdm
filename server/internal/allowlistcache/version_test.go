package allowlistcache_test

import (
	"context"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/allowlistcache"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
)

func TestVersion(t *testing.T) {
	ctx := context.Background()
	v := allowlistcache.NewVersion(valkeytest.Start(t).Client(t))
	if n, err := v.Get(ctx); err != nil || n != 0 {
		t.Fatalf("absent: %d %v", n, err)
	}
	for i := int64(1); i <= 3; i++ {
		if err := v.Bump(ctx); err != nil {
			t.Fatal(err)
		}
		if n, err := v.Get(ctx); err != nil || n != i {
			t.Fatalf("after %d bumps: %d %v", i, n, err)
		}
	}
}
