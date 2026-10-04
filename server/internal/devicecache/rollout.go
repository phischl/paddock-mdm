package devicecache

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/valkey-io/valkey-go"

	"github.com/paddock-mdm/paddock/server/internal/domain/agentrelease"
)

// offerKey is ar:current, the agent rollout devices are offered (plan M2b decision 21). The worker rewrites it every
// round; it has no TTL, so a restarting worker never switches a running rollout off.
const offerKey = "ar:current"

// PutOffer stores the current offer; nil deletes it (no rollout, or the last one was halted).
func (c *Cache) PutOffer(ctx context.Context, o *agentrelease.Offer) error {
	if o == nil {
		return c.c.Do(ctx, c.c.B().Del().Key(offerKey).Build()).Error()
	}
	data, err := json.Marshal(o)
	if err != nil {
		return err
	}
	if err := c.c.Do(ctx, c.c.B().Set().Key(offerKey).Value(string(data)).Build()).Error(); err != nil {
		return fmt.Errorf("devicecache: put offer: %w", err)
	}
	return nil
}

// Offer reads the current offer.
func (c *Cache) Offer(ctx context.Context) (agentrelease.Offer, bool, error) {
	data, err := c.c.Do(ctx, c.c.B().Get().Key(offerKey).Build()).AsBytes()
	if valkey.IsValkeyNil(err) {
		return agentrelease.Offer{}, false, nil
	}
	if err != nil {
		return agentrelease.Offer{}, false, fmt.Errorf("devicecache: offer: %w", err)
	}
	var o agentrelease.Offer
	if err := json.Unmarshal(data, &o); err != nil {
		return agentrelease.Offer{}, false, fmt.Errorf("devicecache: corrupt offer: %w", err)
	}
	return o, true, nil
}
