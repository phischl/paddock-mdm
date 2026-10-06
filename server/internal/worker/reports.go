package worker

import (
	"context"
	"log/slog"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
)

// Reports consumes ingest.heartbeat and ingest.event.
type Reports struct {
	reports  *app.DeviceReports
	commands *app.DeviceCommands
	cache    *devicecache.Cache
	pause    time.Duration
}

// NewReports creates the consumers.
func NewReports(reports *app.DeviceReports, commands *app.DeviceCommands, cache *devicecache.Cache) *Reports {
	return &Reports{reports: reports, commands: commands, cache: cache, pause: RetryPause}
}

// HandleHeartbeats is the mq.ConsumeFunc of queue ingest.heartbeat.
func (r *Reports) HandleHeartbeats(ctx context.Context, _ *amqp.Channel, deliveries <-chan amqp.Delivery) error {
	return consume(ctx, deliveries, r.pause, func(ctx context.Context, d amqp.Delivery) outcome {
		return r.heartbeat(ctx, d.MessageId, d.Body)
	})
}

// HandleEvents is the mq.ConsumeFunc of queue ingest.event.
func (r *Reports) HandleEvents(ctx context.Context, _ *amqp.Channel, deliveries <-chan amqp.Delivery) error {
	return consume(ctx, deliveries, r.pause, func(ctx context.Context, d amqp.Delivery) outcome {
		return r.events(ctx, d.MessageId, d.Body)
	})
}

// heartbeat quarantines a suspected clone, records the delivery of the commands the check-in carried and writes
// device_status at most once per device and devicecache.HeartbeatInterval.
func (r *Reports) heartbeat(ctx context.Context, messageID string, body []byte) outcome {
	var hb ingest.Heartbeat
	if err := decode(body, &hb); err != nil {
		return poison
	}
	ctx = systemContext(ctx, hb.OrganizationID, messageID)
	if hb.CloneSuspected {
		quarantined, err := r.reports.QuarantineClone(ctx, hb)
		switch {
		case err != nil && !permanent(err):
			slog.WarnContext(ctx, "quarantine failed; retrying", "device_id", hb.DeviceID, "error", err)
			return retry
		case quarantined:
			slog.WarnContext(ctx, "clone suspected; device quarantined", "device_id", hb.DeviceID,
				"reported_seq", hb.ReportedSeq, "issued_seq", hb.Seq-1)
		}
	}
	if err := r.commands.MarkDelivered(ctx, hb); err != nil {
		slog.WarnContext(ctx, "recording command delivery failed; retrying", "device_id", hb.DeviceID, "error", err)
		return retry
	}
	fresh, err := r.cache.ClaimHeartbeat(ctx, hb.DeviceID)
	if err != nil {
		slog.WarnContext(ctx, "heartbeat coalescing failed; retrying", "device_id", hb.DeviceID, "error", err)
		return retry
	}
	if !fresh {
		return ack
	}
	if err := r.reports.RecordStatus(ctx, hb); err != nil {
		slog.WarnContext(ctx, "recording device status failed; retrying", "device_id", hb.DeviceID, "error", err)
		if err := r.cache.ReleaseHeartbeat(ctx, hb.DeviceID); err != nil {
			slog.WarnContext(ctx, "releasing heartbeat claim failed", "device_id", hb.DeviceID, "error", err)
		}
		return retry
	}
	return ack
}

// events records every event of a batch; redelivered events are skipped by (device_id, event_seq).
func (r *Reports) events(ctx context.Context, messageID string, body []byte) outcome {
	var batch ingest.Events
	if err := decode(body, &batch); err != nil {
		return poison
	}
	ctx = systemContext(ctx, batch.OrganizationID, messageID)
	for _, ev := range batch.Events {
		if _, err := r.reports.RecordEvent(ctx, batch.DeviceID, ev); err != nil {
			slog.WarnContext(ctx, "recording device event failed; retrying", "device_id", batch.DeviceID,
				"event_seq", ev.EventSeq, "error", err)
			return retry
		}
	}
	return ack
}
