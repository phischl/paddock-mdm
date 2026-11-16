package worker

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
)

// metricUnknownEvents counts device events of a type this server does not know, once per (device, event_seq); the
// type is in the log line only, because a device chooses it (label cardinality).
var metricUnknownEvents = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "paddock_device_events_unknown_total",
	Help: "Device events of an unknown type, from a newer agent, that were skipped; each counted once.",
})

// Reports consumes ingest.heartbeat and ingest.event.
type Reports struct {
	reports    *app.DeviceReports
	commands   *app.DeviceCommands
	cache      *devicecache.Cache
	offboarded offboardedUninstalls
	pause      time.Duration
}

// offboardedUninstalls ends the record of a device of a deleted organization on its removal report
// (app.OffboardedDevices).
type offboardedUninstalls interface {
	Uninstalled(ctx context.Context, device uuid.UUID) (bool, error)
}

// WithOffboardedDevices handles agent.uninstalled of devices whose organization is being deleted or was deleted (plan
// M17 decision 15); without it such a report is dropped like every other message of the organization.
func (r *Reports) WithOffboardedDevices(o offboardedUninstalls) *Reports {
	r.offboarded = o
	return r
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

// EventConcurrency is the number of ingest.event messages a worker handles at a time: each event is one transaction,
// so a single loop bounded N2 (5 000 events/s with 3 workers) at about 1 000 events/s. The order does not matter:
// events are deduplicated by (device_id, event_seq) and a login state never replaces a newer one.
const EventConcurrency = 8

// HandleEvents is the mq.ConsumeFunc of queue ingest.event.
func (r *Reports) HandleEvents(ctx context.Context, _ *amqp.Channel, deliveries <-chan amqp.Delivery) error {
	return consumeConcurrently(ctx, deliveries, EventConcurrency, r.pause, func(ctx context.Context, d amqp.Delivery) outcome {
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
				"reported_seq", hb.ReportedSeq, "issued_seq", hb.ExpectedSeq)
		}
	}
	if err := r.commands.MarkDelivered(ctx, hb); unavailable(ctx, err) {
		return ack
	} else if err != nil {
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
	if err := r.reports.RecordStatus(ctx, hb); unavailable(ctx, err) {
		return ack
	} else if err != nil {
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
	unknown, err := r.reports.RecordEventBatch(ctx, batch.DeviceID, batch.ReceivedAt, batch.Events)
	for _, t := range unknown {
		metricUnknownEvents.Inc()
		slog.WarnContext(ctx, "device event of an unknown type skipped", "device_id", batch.DeviceID, "type", t)
	}
	if unavailable(ctx, err) {
		return r.offboardedReport(ctx, batch)
	}
	if err != nil {
		slog.WarnContext(ctx, "recording device events failed; retrying", "device_id", batch.DeviceID,
			"events", len(batch.Events), "error", err)
		return retry
	}
	// The removal report retires the device (plan M8d decision 41); a redelivery finds it retired and records nothing.
	if slices.ContainsFunc(batch.Events, func(e protocol.Event) bool { return e.Type == protocol.EventAgentUninstalled }) {
		if _, err := r.reports.RetireUninstalled(ctx, batch.DeviceID); err != nil && !permanent(err) {
			slog.WarnContext(ctx, "retiring the uninstalled device failed; retrying", "device_id", batch.DeviceID, "error", err)
			return retry
		}
	}
	return ack
}

// offboardedReport handles the batch of a device whose organization is being deleted or was deleted: its removal
// report ends the device's offboarded record; anything else stays dropped (amendment f point 2).
func (r *Reports) offboardedReport(ctx context.Context, batch ingest.Events) outcome {
	if r.offboarded == nil || !slices.ContainsFunc(batch.Events, func(e protocol.Event) bool { return e.Type == protocol.EventAgentUninstalled }) {
		return ack
	}
	recorded, err := r.offboarded.Uninstalled(ctx, batch.DeviceID)
	if err != nil {
		slog.WarnContext(ctx, "ending the record of an uninstalled offboarded device failed; retrying", "device_id", batch.DeviceID, "error", err)
		return retry
	}
	if recorded {
		slog.InfoContext(ctx, "a device of a deleted organization removed Paddock", "device_id", batch.DeviceID)
	}
	return ack
}
