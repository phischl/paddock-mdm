package devicecache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go"
)

// UpdateRequestLifetime is how long an update-now request stays open (plan M8d decision 26).
const UpdateRequestLifetime = 24 * time.Hour

func updateRequestKey(device uuid.UUID) string { return "au:" + device.String() }

type updateRequest struct {
	Version     string    `json:"version"`
	RequestedAt time.Time `json:"requested_at"`
}

// PutUpdateRequest writes au:<device> with the remaining lifetime of the request; an expired request deletes it.
func (c *Cache) PutUpdateRequest(ctx context.Context, device uuid.UUID, version string, requestedAt, now time.Time) error {
	left := UpdateRequestLifetime - now.Sub(requestedAt)
	if left <= 0 {
		return c.DeleteUpdateRequest(ctx, device)
	}
	data, err := json.Marshal(updateRequest{Version: version, RequestedAt: requestedAt.UTC()})
	if err != nil {
		return err
	}
	if err := c.c.Do(ctx, c.c.B().Set().Key(updateRequestKey(device)).Value(string(data)).PxMilliseconds(left.Milliseconds()).Build()).Error(); err != nil {
		return fmt.Errorf("devicecache: put update request: %w", err)
	}
	return nil
}

// DeleteUpdateRequest removes au:<device>.
func (c *Cache) DeleteUpdateRequest(ctx context.Context, device uuid.UUID) error {
	if err := c.c.Do(ctx, c.c.B().Del().Key(updateRequestKey(device)).Build()).Error(); err != nil {
		return fmt.Errorf("devicecache: delete update request: %w", err)
	}
	return nil
}

// UpdateRequest reads au:<device>: the requested version and when it was requested.
func (c *Cache) UpdateRequest(ctx context.Context, device uuid.UUID) (version string, requestedAt time.Time, ok bool, err error) {
	data, err := c.c.Do(ctx, c.c.B().Get().Key(updateRequestKey(device)).Build()).AsBytes()
	if valkey.IsValkeyNil(err) {
		return "", time.Time{}, false, nil
	}
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("devicecache: update request: %w", err)
	}
	var r updateRequest
	if err := json.Unmarshal(data, &r); err != nil {
		return "", time.Time{}, false, fmt.Errorf("devicecache: corrupt update request: %w", err)
	}
	return r.Version, r.RequestedAt, true, nil
}
