package notifier

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// Metrics are the notifier's Prometheus metrics (plan M9 decision 25).
type Metrics struct {
	deliveries *prometheus.CounterVec
	stalled    *prometheus.GaugeVec
	lag        *prometheus.GaugeVec
	rounds     prometheus.Histogram
	mu         sync.Mutex
	// types remembers the label of each destination whose gauges are set, to remove them once it is gone.
	types map[uuid.UUID]string
}

// NewMetrics creates the metrics and registers them with reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		deliveries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "paddock_notify_deliveries_total",
			Help: "Deliveries attempted by the notifier (events, heartbeats, tests) by destination type and result.",
		}, []string{"type", "result"}),
		stalled: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "paddock_notify_destination_stalled",
			Help: "1 while a notification destination is stalled (deliveries failing longer than the stall threshold), else 0.",
		}, []string{"destination_id", "type"}),
		lag: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "paddock_notify_lag_seconds",
			Help: "Age of the oldest matching audit event a notification destination has not received yet; 0 when caught up.",
		}, []string{"destination_id"}),
		rounds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "paddock_notify_round_seconds",
			Help:    "Duration of one notifier round over every organization and the platform.",
			Buckets: prometheus.ExponentialBuckets(0.05, 2, 12),
		}),
		types: map[uuid.UUID]string{},
	}
	reg.MustRegister(m.deliveries, m.stalled, m.lag, m.rounds)
	return m
}

func (m *Metrics) delivery(t outbound.Type, ok bool) {
	result := "success"
	if !ok {
		result = "failure"
	}
	m.deliveries.WithLabelValues(string(t), result).Inc()
}

func (m *Metrics) round(d time.Duration) { m.rounds.Observe(d.Seconds()) }

// destination sets the gauges of a destination from the state the store holds after the round.
func (m *Metrics) destination(d Destination, lag float64) {
	m.remember(d)
	m.lag.WithLabelValues(d.ID.String()).Set(lag)
}

// stall sets the stalled gauge of a destination.
func (m *Metrics) stall(d Destination, stalled bool) {
	v := 0.0
	if stalled {
		v = 1
	}
	m.remember(d)
	m.stalled.WithLabelValues(d.ID.String(), string(d.Type)).Set(v)
}

func (m *Metrics) remember(d Destination) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.types[d.ID] = string(d.Type)
}

// forget removes the gauges of destinations that were not served in the round (deleted or disabled).
func (m *Metrics) forget(seen map[uuid.UUID]bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, t := range m.types {
		if !seen[id] {
			m.stalled.DeleteLabelValues(id.String(), t)
			m.lag.DeleteLabelValues(id.String())
			delete(m.types, id)
		}
	}
}
