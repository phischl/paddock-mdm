package devicecache

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go"
)

func commandsKey(device uuid.UUID) string { return "cmd:" + device.String() }

// Command is one field of cmd:<device_id> (plan M4a decision 2): a signed command envelope with its expiry, so the
// gateway never delivers an expired command even before the worker removed it.
type Command struct {
	ExpiresAt time.Time       `json:"expires_at"`
	Envelope  json.RawMessage `json:"envelope"`
}

// PutCommand sets the field command_id of cmd:<device_id>.
func (c *Cache) PutCommand(ctx context.Context, device, id uuid.UUID, cmd Command) error {
	value, err := json.Marshal(cmd)
	if err != nil {
		return err
	}
	err = c.c.Do(ctx, c.c.B().Hset().Key(commandsKey(device)).FieldValue().FieldValue(id.String(), string(value)).Build()).Error()
	if err != nil {
		return fmt.Errorf("devicecache: put command: %w", err)
	}
	return nil
}

// HasCommand reports whether cmd:<device_id> holds the command.
func (c *Cache) HasCommand(ctx context.Context, device, id uuid.UUID) (bool, error) {
	ok, err := c.c.Do(ctx, c.c.B().Hexists().Key(commandsKey(device)).Field(id.String()).Build()).AsBool()
	if err != nil {
		return false, fmt.Errorf("devicecache: command: %w", err)
	}
	return ok, nil
}

// DeleteCommand removes the field command_id of cmd:<device_id>.
func (c *Cache) DeleteCommand(ctx context.Context, device, id uuid.UUID) error {
	if err := c.c.Do(ctx, c.c.B().Hdel().Key(commandsKey(device)).Field(id.String()).Build()).Error(); err != nil {
		return fmt.Errorf("devicecache: delete command: %w", err)
	}
	return nil
}

// Commands returns the commands of a device that have not expired at now, by command ID. A corrupt field is skipped:
// the worker rewrites it.
func (c *Cache) Commands(ctx context.Context, device uuid.UUID, now time.Time) (map[uuid.UUID]Command, error) {
	m, err := c.c.Do(ctx, c.c.B().Hgetall().Key(commandsKey(device)).Build()).AsStrMap()
	if err != nil {
		return nil, fmt.Errorf("devicecache: commands: %w", err)
	}
	out := make(map[uuid.UUID]Command, len(m))
	for field, value := range m {
		id, err := uuid.Parse(field)
		var cmd Command
		if err != nil || json.Unmarshal([]byte(value), &cmd) != nil || !now.Before(cmd.ExpiresAt) {
			continue
		}
		out[id] = cmd
	}
	return out, nil
}

// ResultTTL is how long the gateway remembers the result status of a command (cres:<command_id>), so a repeated
// result post is answered without the database (plan M4a decision 3).
const ResultTTL = 30 * 24 * time.Hour

func resultKey(id uuid.UUID) string { return "cres:" + id.String() }

// ClaimResult records "<device_id>:<status>" in cres:<command_id> unless a result exists. It returns the device and
// status of the result that counts: the claimed one, or the existing one.
func (c *Cache) ClaimResult(ctx context.Context, device, id uuid.UUID, status string) (uuid.UUID, string, error) {
	err := c.c.Do(ctx, c.c.B().Set().Key(resultKey(id)).Value(device.String()+":"+status).Nx().Ex(ResultTTL).Build()).Error()
	if err == nil {
		return device, status, nil
	}
	if !valkey.IsValkeyNil(err) {
		return uuid.Nil, "", fmt.Errorf("devicecache: claim result: %w", err)
	}
	owner, existing, ok, err := c.Result(ctx, id)
	if err == nil && !ok {
		err = fmt.Errorf("devicecache: result of %s vanished", id)
	}
	return owner, existing, err
}

// Result reads cres:<command_id>.
func (c *Cache) Result(ctx context.Context, id uuid.UUID) (device uuid.UUID, status string, ok bool, err error) {
	v, err := c.c.Do(ctx, c.c.B().Get().Key(resultKey(id)).Build()).ToString()
	if valkey.IsValkeyNil(err) {
		return uuid.Nil, "", false, nil
	}
	if err != nil {
		return uuid.Nil, "", false, fmt.Errorf("devicecache: result: %w", err)
	}
	dev, status, found := strings.Cut(v, ":")
	if device, err = uuid.Parse(dev); err != nil || !found {
		return uuid.Nil, "", false, fmt.Errorf("devicecache: corrupt result entry of %s", id)
	}
	return device, status, true, nil
}
