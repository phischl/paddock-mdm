// Package mq wraps RabbitMQ (AMQP 0-9-1): connection with reconnect, a publisher with publisher confirms and
// mandatory routing, a consumer helper and the topology provisioning. Only core RabbitMQ features are used so the
// topology runs unchanged on Amazon MQ (ADR 0003).
package mq

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// Topology names (plan M0 §6.8, step 5).
const (
	ExchangeAudit   = "paddock.audit"
	ExchangeDLX     = "paddock.dlx"
	QueueAudit      = "audit.writer"
	QueueAuditDLQ   = "dlq.audit.writer"
	AuditBindingKey = "audit.#"
)

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

// ProvisionOptions are the tunables of the audit topology.
type ProvisionOptions struct {
	AuditQueueMaxBytes int64
}

// Provision declares the audit topology idempotently (vhost from the URL). Redeclaring with different arguments
// fails with PRECONDITION_FAILED, which is reported, never silently changed.
func Provision(ctx context.Context, cfg Config, o ProvisionOptions) error {
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

	for _, ex := range []string{ExchangeAudit, ExchangeDLX} {
		if err := ch.ExchangeDeclare(ex, amqp.ExchangeTopic, true, false, false, false, nil); err != nil {
			return fmt.Errorf("declare exchange %s: %w", ex, err)
		}
	}
	if _, err := ch.QueueDeclare(QueueAudit, true, false, false, false, amqp.Table{
		amqp.QueueTypeArg:        amqp.QueueTypeQuorum,
		amqp.QueueOverflowArg:    amqp.QueueOverflowRejectPublish,
		amqp.QueueMaxLenBytesArg: o.AuditQueueMaxBytes,
		"x-delivery-limit":       int64(20),
		"x-dead-letter-exchange": ExchangeDLX,
	}); err != nil {
		return fmt.Errorf("declare queue %s: %w", QueueAudit, err)
	}
	if err := ch.QueueBind(QueueAudit, AuditBindingKey, ExchangeAudit, false, nil); err != nil {
		return fmt.Errorf("bind %s: %w", QueueAudit, err)
	}
	if _, err := ch.QueueDeclare(QueueAuditDLQ, true, false, false, false, amqp.Table{
		amqp.QueueTypeArg: amqp.QueueTypeQuorum,
	}); err != nil {
		return fmt.Errorf("declare queue %s: %w", QueueAuditDLQ, err)
	}
	if err := ch.QueueBind(QueueAuditDLQ, AuditBindingKey, ExchangeDLX, false, nil); err != nil {
		return fmt.Errorf("bind %s: %w", QueueAuditDLQ, err)
	}
	slog.InfoContext(ctx, "rabbitmq topology provisioned", "exchange", ExchangeAudit, "queue", QueueAudit,
		"dlq", QueueAuditDLQ, "max_bytes", o.AuditQueueMaxBytes)
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
