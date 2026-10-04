package worker

import (
	"context"
	"log/slog"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/devicecache"
	"github.com/paddock-mdm/paddock/server/internal/domain/device"
	"github.com/paddock-mdm/paddock/server/internal/ingest"
	"github.com/paddock-mdm/paddock/server/internal/problem"
)

// Enroller creates devices from enrollment requests (app.Enrollments).
type Enroller interface {
	Enroll(ctx context.Context, req ingest.Enroll) (app.EnrollResult, error)
}

// Enrollment consumes ingest.enroll.
type Enrollment struct {
	enroller Enroller
	cache    *devicecache.Cache
	now      func() time.Time
	pause    time.Duration
}

// NewEnrollment creates the consumer.
func NewEnrollment(enroller Enroller, cache *devicecache.Cache) *Enrollment {
	return &Enrollment{enroller: enroller, cache: cache, now: time.Now, pause: RetryPause}
}

// Handle is the mq.ConsumeFunc of queue ingest.enroll.
func (e *Enrollment) Handle(ctx context.Context, _ *amqp.Channel, deliveries <-chan amqp.Delivery) error {
	return consume(ctx, deliveries, e.pause, func(ctx context.Context, d amqp.Delivery) outcome {
		return e.process(ctx, d.MessageId, d.Body)
	})
}

// process handles one enrollment request: the use case creates the device (or rejects the request), then the
// enrollment status and, for a device that is not pending, its identity key are written to Valkey.
func (e *Enrollment) process(ctx context.Context, messageID string, body []byte) outcome {
	var req ingest.Enroll
	if err := decode(body, &req); err != nil || req.EnrollmentID.String() != messageID {
		return poison
	}
	ctx = systemContext(ctx, req.OrganizationID, messageID)
	entry := devicecache.Enrollment{KeyID: req.KeyID, PublicKey: req.PublicKey, OrganizationID: req.OrganizationID}
	res, err := e.enroller.Enroll(ctx, req)
	switch {
	case err != nil && permanent(err):
		entry.Status, entry.Reason = protocol.EnrollRejected, problem.From(err).Code
		slog.InfoContext(ctx, "enrollment rejected", "enrollment_id", req.EnrollmentID, "reason", entry.Reason)
	case err != nil:
		slog.WarnContext(ctx, "enrollment failed; retrying", "enrollment_id", req.EnrollmentID, "error", err)
		return retry
	default:
		entry.DeviceID, entry.Status = res.DeviceID, EnrollStatus(res.State)
		if res.State != device.StatePending {
			key := devicecache.DeviceKey{DeviceID: res.DeviceID, OrganizationID: req.OrganizationID,
				Status: devicecache.KeyStatus(res.KeyStatus, res.State), PublicKey: req.PublicKey}
			if err := e.cache.PutDeviceKey(ctx, req.KeyID, key); err != nil {
				slog.WarnContext(ctx, "caching device key failed; retrying", "enrollment_id", req.EnrollmentID, "error", err)
				return retry
			}
		}
	}
	if err := e.cache.PutEnrollment(ctx, req.EnrollmentID, entry, e.now()); err != nil {
		slog.WarnContext(ctx, "caching enrollment status failed; retrying", "enrollment_id", req.EnrollmentID, "error", err)
		return retry
	}
	return ack
}

// EnrollStatus maps a device state to the status of GET /v1/enroll/{id}.
func EnrollStatus(state string) string {
	switch state {
	case device.StatePending:
		return protocol.EnrollPending
	case device.StateActive, device.StateQuarantined:
		return protocol.EnrollActive
	default:
		return protocol.EnrollRejected
	}
}
