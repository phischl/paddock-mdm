package worker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/commandsign"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/domain/devicecommand"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// CommandInterval is the period of the command round: expiry, delayed commands and repair of cmd:<device_id>
// (plan M4a decision 3).
const CommandInterval = 60 * time.Second

// commandLockKey is the advisory lock of the command round ("paddock cmds").
const commandLockKey = 0x7061646420636d64

// Commands signs device commands with command-signing and publishes them to cmd:<device_id>, records their results
// and expires them (plan M4a decisions 2 and 3). The worker's AppRole may sign with command-signing only.
type Commands struct {
	commands *app.DeviceCommands
	pool     *db.OrgPool
	platform *db.PlatformPool
	cache    *devicecache.Cache
	signer   commandsign.Signer
	pause    time.Duration
	interval time.Duration
	now      func() time.Time
}

// NewCommands creates the command consumers and the command round.
func NewCommands(commands *app.DeviceCommands, pool *db.OrgPool, platform *db.PlatformPool, cache *devicecache.Cache,
	signer commandsign.Signer) *Commands {
	return &Commands{commands: commands, pool: pool, platform: platform, cache: cache, signer: signer, pause: RetryPause,
		interval: CommandInterval, now: time.Now}
}

// HandleIssued is the mq.ConsumeFunc of queue command.issued: it signs and publishes a new command unless it is not
// due yet (the command round publishes it then) or no longer open.
func (c *Commands) HandleIssued(ctx context.Context, _ *amqp.Channel, deliveries <-chan amqp.Delivery) error {
	return consume(ctx, deliveries, c.pause, func(ctx context.Context, d amqp.Delivery) outcome {
		return c.issued(ctx, d.MessageId, d.Body)
	})
}

func (c *Commands) issued(ctx context.Context, messageID string, body []byte) outcome {
	var msg devicecommand.Issued
	if err := decode(body, &msg); err != nil {
		return poison
	}
	ctx = systemContext(ctx, msg.OrganizationID, messageID)
	cmd, err := c.commands.Get(ctx, msg.CommandID)
	switch {
	case err != nil && permanent(err):
		slog.WarnContext(ctx, "issued command not found", "command_id", msg.CommandID)
		return ack
	case err != nil:
		slog.WarnContext(ctx, "loading issued command failed; retrying", "command_id", msg.CommandID, "error", err)
		return retry
	case !app.Deliverable(cmd, c.now()):
		return ack
	}
	if err := c.publish(ctx, cmd); err != nil {
		slog.WarnContext(ctx, "publishing command failed; retrying", "command_id", cmd.ID, "error", err)
		return retry
	}
	return ack
}

// HandleResults is the mq.ConsumeFunc of queue ingest.command_result: it records the result and removes the
// command from cmd:<device_id>.
func (c *Commands) HandleResults(ctx context.Context, _ *amqp.Channel, deliveries <-chan amqp.Delivery) error {
	return consume(ctx, deliveries, c.pause, func(ctx context.Context, d amqp.Delivery) outcome {
		return c.result(ctx, d.MessageId, d.Body)
	})
}

func (c *Commands) result(ctx context.Context, messageID string, body []byte) outcome {
	var res ingest.CommandResult
	if err := decode(body, &res); err != nil {
		return poison
	}
	ctx = systemContext(ctx, res.OrganizationID, messageID)
	if err := c.commands.Finish(ctx, res); err != nil {
		slog.WarnContext(ctx, "recording command result failed; retrying", "command_id", res.CommandID, "error", err)
		return retry
	}
	// A finished command stays in Valkey only if this fails; the gateway answers its result from cres: anyway.
	if err := c.cache.DeleteCommand(ctx, res.DeviceID, res.CommandID); err != nil {
		slog.WarnContext(ctx, "removing finished command failed; retrying", "command_id", res.CommandID, "error", err)
		return retry
	}
	slog.InfoContext(ctx, "command finished", "device_id", res.DeviceID, "command_id", res.CommandID, "status", res.Status)
	return ack
}

// publish signs a command and writes it to cmd:<device_id>.
func (c *Commands) publish(ctx context.Context, cmd pgstore.DeviceCommand) error {
	env, err := commandsign.Sign(ctx, c.signer, app.Payload(cmd))
	if err != nil {
		return err
	}
	return c.cache.PutCommand(ctx, cmd.DeviceID, cmd.ID, devicecache.Command{ExpiresAt: cmd.ExpiresAt, Envelope: env})
}

// Run runs the command round at start and then every interval until ctx ends; only the replica holding the lock
// acts.
func (c *Commands) Run(ctx context.Context) error {
	tick := time.NewTicker(c.interval)
	defer tick.Stop()
	for {
		if err := c.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "command round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round expires the commands whose lifetime ended and removes them from Valkey, and publishes every open, due
// command that is missing in Valkey (a command delayed by not_before, a lost command.issued message or an emptied
// Valkey).
func (c *Commands) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := c.platform.WithLeaderLock(sys, commandLockKey, func(ctx context.Context) error {
		orgs, err := c.pool.OrganizationIDs(ctx)
		if err != nil {
			return err
		}
		for _, org := range orgs {
			if err := c.roundOrg(systemContext(ctx, org, "command-round"), org); err != nil {
				return fmt.Errorf("organization %s: %w", org, err)
			}
		}
		return nil
	})
	return err
}

func (c *Commands) roundOrg(ctx context.Context, org uuid.UUID) error {
	now := c.now()
	expired, err := c.commands.Expire(ctx, now)
	if err != nil {
		return err
	}
	for _, e := range expired {
		if err := c.cache.DeleteCommand(ctx, e.DeviceID, e.ID); err != nil {
			return err
		}
		slog.InfoContext(ctx, "command expired", "organization_id", org, "device_id", e.DeviceID, "command_id", e.ID)
	}
	due, err := c.commands.Due(ctx, now)
	if err != nil {
		return err
	}
	for _, cmd := range due {
		present, err := c.cache.HasCommand(ctx, cmd.DeviceID, cmd.ID)
		if err != nil {
			return err
		}
		if present {
			continue
		}
		if err := c.publish(ctx, cmd); err != nil {
			return err
		}
	}
	return nil
}
