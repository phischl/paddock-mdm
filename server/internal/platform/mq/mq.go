// Package mq wraps RabbitMQ (AMQP 0-9-1): connection with reconnect, a publisher with publisher confirms and
// mandatory routing, a consumer helper and the topology provisioning. Only core RabbitMQ features are used so the
// topology runs unchanged on Amazon MQ (ADR 0003).
package mq

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

// Topology names (plan M0 §6.8, plan M2a step 2, architecture §8.1).
const (
	ExchangeAudit   = "paddock.audit"
	ExchangeIngest  = "paddock.ingest"
	ExchangeState   = "paddock.state"
	ExchangeCommand = "paddock.command"
	ExchangeDLX     = "paddock.dlx"
	QueueAudit      = "audit.writer"
	QueueAuditDLQ   = "dlq.audit.writer"
	AuditBindingKey = "audit.#"
	// QueueCommandIssued receives the command.issued messages of the outbox (routing key CommandIssuedKey); the worker
	// signs and delivers the commands (plan M4a decision 2).
	QueueCommandIssued = "command.issued"
	CommandIssuedKey   = "issued"
	// QueueRevocationApproved receives the revocation.approved messages of the outbox; the revocation-issuer, its
	// single active consumer, verifies and issues them (plan M4c decision 8).
	ExchangeRevocation      = "paddock.revocation"
	QueueRevocationApproved = "revocation.approved"
	RevocationApprovedKey   = "approved"
)

// Ingest kinds (M2a, M4a); each has the queue ingest.<kind> and routing keys ingest.<kind>.<organization_id>.
const (
	IngestEnroll        = "enroll"
	IngestHeartbeat     = "heartbeat"
	IngestEvent         = "event"
	IngestCommandResult = "command_result"
	IngestEscrow        = "escrow"
)

// IngestKinds are the provisioned ingest kinds.
var IngestKinds = []string{IngestEnroll, IngestHeartbeat, IngestEvent, IngestCommandResult, IngestEscrow}

// IngestQueue is the queue of an ingest kind.
func IngestQueue(kind string) string { return "ingest." + kind }

// IngestRoutingKey is the routing key of an ingest message of org.
func IngestRoutingKey(kind string, org uuid.UUID) string {
	return "ingest." + kind + "." + org.String()
}

// StatePartitions is the number of state partition queues.
const StatePartitions = 16

// StatePriority is the routing key of the priority state queue.
const StatePriority = "priority"

// StatePartition is the routing key of org's state events: p00…p15 = fnv32a(organization_id) mod 16, computed over
// the canonical string form of the ID.
func StatePartition(org uuid.UUID) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(org.String()))
	return fmt.Sprintf("p%02d", h.Sum32()%StatePartitions)
}

// StateRoutingKeys are p00…p15 and priority.
func StateRoutingKeys() []string {
	keys := make([]string, 0, StatePartitions+1)
	for i := range StatePartitions {
		keys = append(keys, fmt.Sprintf("p%02d", i))
	}
	return append(keys, StatePriority)
}

// StateQueue is the queue of a state routing key.
func StateQueue(key string) string { return "state." + key }

// Config locates the broker.
type Config struct {
	URL      string // amqp://host:5672/vhost
	User     string
	Password string
}

// dialURL merges the credentials into the URL.
func (c Config) dialURL() (string, error) {
	u, err := url.Parse(c.URL)
	if err != nil {
		return "", fmt.Errorf("mq: parse url: %w", err)
	}
	if c.User != "" {
		u.User = url.UserPassword(c.User, c.Password)
	}
	return u.String(), nil
}

// Dial opens one connection.
func Dial(c Config) (*amqp.Connection, error) {
	u, err := c.dialURL()
	if err != nil {
		return nil, err
	}
	return amqp.DialConfig(u, amqp.Config{Heartbeat: 10 * time.Second, Locale: "en_US",
		Properties: amqp.Table{"connection_name": "paddock-server"}})
}

// Message is one message to publish.
type Message struct {
	RoutingKey string
	MessageID  string
	Body       []byte
}

// ErrReturned means the broker could not route a mandatory message.
var ErrReturned = errors.New("mq: message returned as unroutable")

// ErrNacked means the broker refused the message (negative confirm, e.g. queue full with reject-publish).
var ErrNacked = errors.New("mq: message negatively confirmed")

// Publisher publishes with publisher confirms (delivery_mode=2, mandatory=true). It reconnects lazily.
type Publisher struct {
	cfg Config

	mu      sync.Mutex
	conn    *amqp.Connection
	ch      *amqp.Channel
	returns chan amqp.Return
}

// NewPublisher creates a publisher; the connection is opened on first use.
func NewPublisher(cfg Config) *Publisher { return &Publisher{cfg: cfg} }

func (p *Publisher) channel() (*amqp.Channel, chan amqp.Return, error) {
	if p.ch != nil && !p.ch.IsClosed() {
		return p.ch, p.returns, nil
	}
	p.closeLocked()
	conn, err := Dial(p.cfg)
	if err != nil {
		return nil, nil, err
	}
	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	if err := ch.Confirm(false); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	p.conn, p.ch = conn, ch
	p.returns = ch.NotifyReturn(make(chan amqp.Return, 1024))
	return ch, p.returns, nil
}

func (p *Publisher) closeLocked() {
	if p.conn != nil {
		_ = p.conn.Close()
	}
	p.conn, p.ch, p.returns = nil, nil, nil
}

// Connected reports whether the publisher currently holds an open channel.
func (p *Publisher) Connected() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ch != nil && !p.ch.IsClosed()
}

// Ping opens the connection if necessary.
func (p *Publisher) Ping() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, _, err := p.channel()
	return err
}

// Close closes the connection.
func (p *Publisher) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked()
}

// PublishBatch publishes msgs in order and waits for every confirm. The result has one entry per message: nil when
// the broker confirmed and routed it, otherwise the reason. A connection-level error is returned as err and the
// result is nil (nothing may be considered published).
func (p *Publisher) PublishBatch(ctx context.Context, exchange string, msgs []Message) ([]error, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ch, returns, err := p.channel()
	if err != nil {
		return nil, err
	}
	// Drop stale returns of earlier batches.
	for len(returns) > 0 {
		<-returns
	}
	confirms := make([]*amqp.DeferredConfirmation, len(msgs))
	for i, m := range msgs {
		dc, err := ch.PublishWithDeferredConfirmWithContext(ctx, exchange, m.RoutingKey, true, false, amqp.Publishing{
			ContentType:  "application/json",
			DeliveryMode: amqp.Persistent,
			MessageId:    m.MessageID,
			Timestamp:    time.Now(),
			Body:         m.Body,
		})
		if err != nil {
			p.closeLocked()
			return nil, err
		}
		confirms[i] = dc
	}
	results := make([]error, len(msgs))
	for i, dc := range confirms {
		acked, err := dc.WaitContext(ctx)
		if err != nil {
			p.closeLocked()
			return nil, err
		}
		if !acked {
			results[i] = ErrNacked
		}
	}
	// basic.return precedes the basic.ack of the same message, so all returns are buffered by now.
	returned := map[string]bool{}
	for len(returns) > 0 {
		r := <-returns
		returned[r.MessageId] = true
	}
	for i, m := range msgs {
		if results[i] == nil && returned[m.MessageID] {
			results[i] = ErrReturned
		}
	}
	return results, nil
}

// ProvisionOptions are the tunables of the topology.
type ProvisionOptions struct {
	AuditQueueMaxBytes  int64
	IngestQueueMaxBytes int64 // per ingest queue; 0 = DefaultIngestQueueMaxBytes
}

// DefaultIngestQueueMaxBytes is the byte limit of each ingest queue when none is configured.
const DefaultIngestQueueMaxBytes = 256 << 20

// queueSpec is one quorum queue with its dead-letter queue.
type queueSpec struct {
	name     string
	exchange string
	keys     []string // binding keys on exchange; dead-lettered messages keep them
	args     amqp.Table
}

// Provision declares the topology idempotently (vhost from the URL): exchanges paddock.audit, paddock.ingest,
// paddock.state and paddock.dlx, every queue with its dlq.<queue> (architecture §8.1). Redeclaring with different
// arguments fails with PRECONDITION_FAILED, which is reported, never silently changed.
func Provision(ctx context.Context, cfg Config, o ProvisionOptions) error {
	if o.IngestQueueMaxBytes == 0 {
		o.IngestQueueMaxBytes = DefaultIngestQueueMaxBytes
	}
	conn, err := Dial(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer func() { _ = ch.Close() }()

	exchanges := []struct{ name, kind string }{
		{ExchangeAudit, amqp.ExchangeTopic}, {ExchangeIngest, amqp.ExchangeTopic},
		{ExchangeState, amqp.ExchangeDirect}, {ExchangeCommand, amqp.ExchangeDirect},
		{ExchangeRevocation, amqp.ExchangeDirect}, {ExchangeDLX, amqp.ExchangeTopic},
	}
	for _, ex := range exchanges {
		if err := ch.ExchangeDeclare(ex.name, ex.kind, true, false, false, false, nil); err != nil {
			return fmt.Errorf("declare exchange %s: %w", ex.name, err)
		}
	}
	for _, q := range topology(o) {
		if err := declare(ch, q); err != nil {
			return err
		}
	}
	slog.InfoContext(ctx, "rabbitmq topology provisioned", "audit_max_bytes", o.AuditQueueMaxBytes,
		"ingest_max_bytes", o.IngestQueueMaxBytes)
	return nil
}

func topology(o ProvisionOptions) []queueSpec {
	qs := []queueSpec{{
		name: QueueAudit, exchange: ExchangeAudit, keys: []string{AuditBindingKey},
		args: amqp.Table{
			amqp.QueueOverflowArg:    amqp.QueueOverflowRejectPublish,
			amqp.QueueMaxLenBytesArg: o.AuditQueueMaxBytes,
		},
	}}
	for _, kind := range IngestKinds {
		qs = append(qs, queueSpec{
			name: IngestQueue(kind), exchange: ExchangeIngest, keys: []string{"ingest." + kind + ".*"},
			args: amqp.Table{
				amqp.QueueOverflowArg:    amqp.QueueOverflowRejectPublish,
				amqp.QueueMaxLenBytesArg: o.IngestQueueMaxBytes,
			},
		})
	}
	for _, key := range StateRoutingKeys() {
		qs = append(qs, queueSpec{
			name: StateQueue(key), exchange: ExchangeState, keys: []string{key},
			args: amqp.Table{"x-single-active-consumer": true},
		})
	}
	return append(qs, queueSpec{name: QueueCommandIssued, exchange: ExchangeCommand, keys: []string{CommandIssuedKey}},
		queueSpec{name: QueueRevocationApproved, exchange: ExchangeRevocation, keys: []string{RevocationApprovedKey},
			args: amqp.Table{"x-single-active-consumer": true}})
}

func declare(ch *amqp.Channel, q queueSpec) error {
	args := amqp.Table{
		amqp.QueueTypeArg:        amqp.QueueTypeQuorum,
		"x-delivery-limit":       int64(20),
		"x-dead-letter-exchange": ExchangeDLX,
	}
	for k, v := range q.args {
		args[k] = v
	}
	if _, err := ch.QueueDeclare(q.name, true, false, false, false, args); err != nil {
		return fmt.Errorf("declare queue %s: %w", q.name, err)
	}
	dlq := "dlq." + q.name
	if _, err := ch.QueueDeclare(dlq, true, false, false, false, amqp.Table{amqp.QueueTypeArg: amqp.QueueTypeQuorum}); err != nil {
		return fmt.Errorf("declare queue %s: %w", dlq, err)
	}
	for _, key := range q.keys {
		if err := ch.QueueBind(q.name, key, q.exchange, false, nil); err != nil {
			return fmt.Errorf("bind %s: %w", q.name, err)
		}
		if err := ch.QueueBind(dlq, key, ExchangeDLX, false, nil); err != nil {
			return fmt.Errorf("bind %s: %w", dlq, err)
		}
	}
	return nil
}

// ConsumeFunc handles one consumer session. It returns when the channel closes or ctx ends.
type ConsumeFunc func(ctx context.Context, ch *amqp.Channel, deliveries <-chan amqp.Delivery) error

// Consumer consumes one queue with manual acknowledgements and reconnects with back-off.
type Consumer struct {
	cfg      Config
	queue    string
	prefetch int

	mu        sync.Mutex
	connected bool
}

// NewConsumer creates a consumer.
func NewConsumer(cfg Config, queue string, prefetch int) *Consumer {
	return &Consumer{cfg: cfg, queue: queue, prefetch: prefetch}
}

// Connected reports whether a consumer session is active.
func (c *Consumer) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *Consumer) setConnected(v bool) {
	c.mu.Lock()
	c.connected = v
	c.mu.Unlock()
}

// Run consumes until ctx ends, reconnecting after failures (1 s → 30 s).
func (c *Consumer) Run(ctx context.Context, handle ConsumeFunc) error {
	backoff := time.Second
	for ctx.Err() == nil {
		err := c.session(ctx, handle)
		c.setConnected(false)
		if ctx.Err() != nil {
			return nil
		}
		slog.WarnContext(ctx, "consumer session ended; reconnecting", "queue", c.queue, "error", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
	return nil
}

func (c *Consumer) session(ctx context.Context, handle ConsumeFunc) error {
	conn, err := Dial(c.cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	if err := ch.Qos(c.prefetch, 0, false); err != nil {
		return err
	}
	deliveries, err := ch.ConsumeWithContext(ctx, c.queue, "", false, false, false, false, nil)
	if err != nil {
		return err
	}
	c.setConnected(true)
	slog.InfoContext(ctx, "consuming", "queue", c.queue, "prefetch", c.prefetch)
	return handle(ctx, ch, deliveries)
}
