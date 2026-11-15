package worker

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/offboarding"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// offboardingLockKey is the advisory lock of the organization deletion round ("paddoffb").
const offboardingLockKey = 0x706164646f666662

// OffboardingInterval is the interval of the deletion round (plan M17 decision 5).
const OffboardingInterval = time.Minute

// OffboardingBackoffCap is the longest wait between two attempts of a failing step. The wait doubles from the round
// interval up to it; reaching it raises PaddockOrganizationDeletionStuck (requirement of main, 2026-11-14): the job
// keeps retrying at the cap, so a dependency that comes back still finishes the deletion by itself.
const OffboardingBackoffCap = 30 * time.Minute

var (
	metricOffboardingStepFailing = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "paddock_offboarding_step_failing",
		Help: "Organizations whose deletion step failed at the last round, by step and error code.",
	}, []string{"step", "error_code"})
	metricOffboardingRetryCapped = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_offboarding_retry_capped",
		Help: "Organizations whose failing deletion step is retried at the longest backoff.",
	})
	metricOffboardingCapReached = promauto.NewCounter(prometheus.CounterOpts{
		Name: "paddock_offboarding_retry_cap_reached_total",
		Help: "Times a failing deletion step reached the longest backoff.",
	})
	metricOffboardingFinalizeBusy = promauto.NewCounter(prometheus.CounterOpts{
		Name: "paddock_offboarding_finalize_busy_total",
		Help: "Rounds in which an organization's tombstone waited for organization transactions older than the deletion.",
	})
)

// offboarder is the organization deletion (app.Offboarding).
type offboarder interface {
	StartDue(ctx context.Context) ([]uuid.UUID, error)
	Pending(ctx context.Context) ([]pgstore.Organization, error)
	Advance(ctx context.Context, org uuid.UUID) (bool, error)
}

// leaderLocker runs a function under a leader lock (db.PlatformPool).
type leaderLocker interface {
	WithLeaderLock(ctx context.Context, key int64, fn func(ctx context.Context) error) (bool, error)
}

// offboardingRetry is the backoff of one organization's failing step, kept in memory: a new leader retries at once,
// which costs one attempt.
type offboardingRetry struct {
	failures int
	next     time.Time
	capped   bool
}

// Offboarding is the round worker.Offboarding (plan M17 decision 5): under its leader lock it starts every due
// deletion and runs one step of every organization being deleted.
type Offboarding struct {
	job      offboarder
	lock     leaderLocker
	interval time.Duration
	now      func() time.Time
	retries  map[uuid.UUID]*offboardingRetry
}

// NewOffboarding creates the round; lock is the worker's platform pool, whose lock pool holds the leader lock.
func NewOffboarding(job offboarder, lock leaderLocker) *Offboarding {
	return &Offboarding{job: job, lock: lock, interval: OffboardingInterval, now: time.Now,
		retries: map[uuid.UUID]*offboardingRetry{}}
}

// WithClock replaces time.Now (tests).
func (o *Offboarding) WithClock(now func() time.Time) *Offboarding {
	o.now = now
	return o
}

// Run runs the round at start and then every interval until ctx ends.
func (o *Offboarding) Run(ctx context.Context) error {
	tick := time.NewTicker(o.interval)
	defer tick.Stop()
	for {
		if err := o.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "organization deletion round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round starts the due deletions and advances each pending one by one step; a failing organization does not stop the
// others. The lock is held only while the round runs (amendment c point 3).
func (o *Offboarding) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	leader, err := o.lock.WithLeaderLock(sys, offboardingLockKey, func(ctx context.Context) error {
		started, err := o.job.StartDue(ctx)
		if err != nil {
			return err
		}
		for _, id := range started {
			slog.InfoContext(ctx, "organization deletion started", "organization", id)
		}
		orgs, err := o.job.Pending(ctx)
		if err != nil {
			return err
		}
		o.observe(orgs)
		pending := map[uuid.UUID]bool{}
		for _, org := range orgs {
			pending[org.ID] = true
			o.advance(ctx, org.ID)
		}
		capped := 0
		for id, r := range o.retries {
			if !pending[id] {
				delete(o.retries, id)
			} else if r.capped {
				capped++
			}
		}
		metricOffboardingRetryCapped.Set(float64(capped))
		return nil
	})
	if err == nil && !leader {
		// Another replica leads now and exports the deletions' state; this one's last values would keep the alert firing.
		metricOffboardingRetryCapped.Set(0)
		metricOffboardingStepFailing.Reset()
		clear(o.retries)
	}
	return err
}

// observe sets the failing gauge from the stored error codes, the ongoing view of a failure whose audit event is
// recorded once per code.
func (o *Offboarding) observe(orgs []pgstore.Organization) {
	metricOffboardingStepFailing.Reset()
	for _, org := range orgs {
		if org.Status == organization.StatusDeleting && org.OffboardingErrorCode != nil && org.OffboardingStep != nil {
			metricOffboardingStepFailing.WithLabelValues(*org.OffboardingStep, *org.OffboardingErrorCode).Inc()
		}
	}
}

// advance runs one step of org unless its backoff has not elapsed.
func (o *Offboarding) advance(ctx context.Context, org uuid.UUID) {
	now := o.now()
	r := o.retries[org]
	if r != nil && now.Before(r.next) {
		return
	}
	_, err := o.job.Advance(ctx, org)
	switch {
	case err == nil:
		delete(o.retries, org)
	case errors.Is(err, app.ErrOffboardingWaiting):
		metricOffboardingFinalizeBusy.Inc()
		delete(o.retries, org)
	case ctx.Err() != nil:
	default:
		if r == nil {
			r = &offboardingRetry{}
			o.retries[org] = r
		}
		r.failures++
		delay := o.backoff(r.failures)
		r.next = now.Add(delay)
		if delay >= OffboardingBackoffCap && !r.capped {
			r.capped = true
			metricOffboardingCapReached.Inc()
			slog.ErrorContext(ctx, "organization deletion step keeps failing; retried at the longest backoff",
				"organization", org, "failures", r.failures, "backoff", delay, "error", err)
		}
	}
}

// backoff is the wait after the n-th consecutive failure: the round interval, doubled per failure, at most the cap.
func (o *Offboarding) backoff(n int) time.Duration {
	d := o.interval
	for i := 1; i < n && d < OffboardingBackoffCap; i++ {
		d *= 2
	}
	return min(d, OffboardingBackoffCap)
}

// auditFinalRecorder applies the audit writer's acknowledgements (app.Offboarding).
type auditFinalRecorder interface {
	RecordAuditFinal(ctx context.Context, ack offboarding.AuditRetired) error
}

// AuditRetirements consumes worker.offboarding, the audit writer's acknowledgements of retired organizations (plan M17
// amendment 2026-11-15 o point 6). The worker never connects to the audit database: this queue is how step audit_final
// learns the outcome of the final verification. Only the audit writer may publish to paddock.offboarding, so a message
// here is the writer's (the broker's permissions are the guarantee).
type AuditRetirements struct {
	job   auditFinalRecorder
	pause time.Duration
}

// NewAuditRetirements creates the consumer.
func NewAuditRetirements(job auditFinalRecorder) *AuditRetirements {
	return &AuditRetirements{job: job, pause: RetryPause}
}

// Handle is the mq.ConsumeFunc of queue worker.offboarding.
func (a *AuditRetirements) Handle(ctx context.Context, _ *amqp.Channel, deliveries <-chan amqp.Delivery) error {
	return consume(ctx, deliveries, a.pause, func(ctx context.Context, d amqp.Delivery) outcome {
		return a.process(ctx, d.Body)
	})
}

func (a *AuditRetirements) process(ctx context.Context, body []byte) outcome {
	var m offboarding.AuditRetired
	if err := json.Unmarshal(body, &m); err != nil || m.Validate() != nil {
		return poison
	}
	if err := a.job.RecordAuditFinal(ctx, m); err != nil {
		slog.WarnContext(ctx, "recording the final audit verification failed; retrying", "organization", m.OrganizationID,
			"error", err)
		return retry
	}
	return ack
}
