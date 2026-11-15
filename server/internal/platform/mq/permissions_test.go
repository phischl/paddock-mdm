package mq_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/mqtest"
)

const definitionsPath = "../../../../deploy/compose/rabbitmq/definitions.json.tmpl"

// applyDefinitions creates users with the permissions the deployment's definitions give them.
func applyDefinitions(t *testing.T, broker *mqtest.Broker, users ...string) {
	t.Helper()
	raw, err := os.ReadFile(definitionsPath)
	if err != nil {
		t.Fatal(err)
	}
	var defs struct {
		Permissions []struct {
			User, Vhost, Configure, Write, Read string
		} `json:"permissions"`
	}
	if err := json.Unmarshal(raw, &defs); err != nil {
		t.Fatal(err)
	}
	for _, user := range users {
		found := false
		for _, p := range defs.Permissions {
			if p.User != user {
				continue
			}
			found = true
			broker.Ctl(t, "add_user", user, user+"-pw")
			broker.Ctl(t, "set_permissions", "-p", p.Vhost, user, p.Configure, p.Write, p.Read)
		}
		if !found {
			t.Fatalf("definitions grant %s nothing", user)
		}
	}
}

// refused asserts that err is the broker's 403 ACCESS_REFUSED.
func refused(t *testing.T, what string, err error) {
	t.Helper()
	var amqpErr *amqp.Error
	if !errors.As(err, &amqpErr) || amqpErr.Code != amqp.AccessRefused {
		t.Errorf("%s: got %v, want ACCESS_REFUSED", what, err)
	}
}

// publishRefused publishes one message as cfg's user and returns the error that closes the channel.
func publishRefused(t *testing.T, cfg mq.Config, exchange, key string) error {
	t.Helper()
	conn, err := mq.Dial(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ch, err := conn.Channel()
	if err != nil {
		t.Fatal(err)
	}
	closed := ch.NotifyClose(make(chan *amqp.Error, 1))
	if err := ch.PublishWithContext(context.Background(), exchange, key, false, false, amqp.Publishing{Body: []byte(`{}`)}); err != nil {
		return err
	}
	select {
	case e := <-closed:
		if e == nil {
			return errors.New("channel closed without an error")
		}
		return e
	case <-time.After(10 * time.Second):
		return errors.New("publish was not refused")
	}
}

// consume starts a consumer on queue as cfg's user and returns the broker's answer.
func consume(t *testing.T, cfg mq.Config, queue string) (<-chan amqp.Delivery, error) {
	t.Helper()
	conn, err := mq.Dial(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ch, err := conn.Channel()
	if err != nil {
		t.Fatal(err)
	}
	return ch.Consume(queue, "", false, false, false, false, nil)
}

// TestOffboardingChannelPermissions: with the deployment's definitions, the audit writer may publish only to
// paddock.offboarding and consume only audit.writer, and the worker reads worker.offboarding but publishes nowhere (plan
// M17 amendment 2026-11-15 o point 4). Only the audit writer can therefore send the worker an acknowledgement.
func TestOffboardingChannelPermissions(t *testing.T) {
	broker := mqtest.Start(t)
	applyDefinitions(t, broker, "audit_writer", "worker")
	writer, worker := broker.As("audit_writer", "audit_writer-pw"), broker.As("worker", "worker-pw")
	ctx := context.Background()

	pub := mq.NewPublisher(writer)
	defer pub.Close()
	org := uuid.New()
	res, err := pub.PublishBatch(ctx, mq.ExchangeOffboarding, []mq.Message{
		{RoutingKey: mq.AuditRetiredRoutingKey(org), MessageID: "ack-1", Body: []byte(`{}`)}})
	if err != nil || res[0] != nil {
		t.Fatalf("audit writer publish to %s: %v %v", mq.ExchangeOffboarding, res, err)
	}
	for _, ex := range []string{mq.ExchangeAudit, mq.ExchangeIngest, mq.ExchangeState, mq.ExchangeCommand,
		mq.ExchangeRevocation, mq.ExchangeDLX, ""} {
		refused(t, "audit writer publish to "+ex, publishRefused(t, writer, ex, "audit_retired."+org.String()))
	}
	_, err = consume(t, writer, mq.QueueWorkerOffboarding)
	refused(t, "audit writer consume "+mq.QueueWorkerOffboarding, err)
	if _, err := consume(t, writer, mq.QueueAudit); err != nil {
		t.Errorf("audit writer consume %s: %v", mq.QueueAudit, err)
	}

	deliveries, err := consume(t, worker, mq.QueueWorkerOffboarding)
	if err != nil {
		t.Fatalf("worker consume %s: %v", mq.QueueWorkerOffboarding, err)
	}
	select {
	case d := <-deliveries:
		if d.MessageId != "ack-1" {
			t.Errorf("worker got %q", d.MessageId)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the worker received no acknowledgement")
	}
	for _, ex := range []string{mq.ExchangeOffboarding, mq.ExchangeAudit, ""} {
		refused(t, "worker publish to "+ex, publishRefused(t, worker, ex, "audit_retired."+org.String()))
	}
	for _, q := range []string{mq.QueueAudit, "dlq." + mq.QueueWorkerOffboarding} {
		_, err = consume(t, worker, q)
		refused(t, "worker consume "+q, err)
	}
}
