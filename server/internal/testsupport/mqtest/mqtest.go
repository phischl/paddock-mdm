// Package mqtest starts a RabbitMQ test container (image pinned in versions.env) with vhost paddock.
package mqtest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// Broker is a running RabbitMQ.
type Broker struct {
	Config    mq.Config
	container testcontainers.Container
}

// Start starts RabbitMQ and provisions the audit topology.
func Start(t testing.TB) *Broker {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        pgtest.Image(t, "RABBITMQ_IMAGE"),
			ExposedPorts: []string{"5672/tcp"},
			Env: map[string]string{
				"RABBITMQ_DEFAULT_USER":  "test",
				"RABBITMQ_DEFAULT_PASS":  "test",
				"RABBITMQ_DEFAULT_VHOST": "paddock",
			},
			WaitingFor: wait.ForLog("Server startup complete").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatalf("mqtest: start rabbitmq: %v", err)
	}
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := c.MappedPort(ctx, "5672/tcp")
	if err != nil {
		t.Fatal(err)
	}
	b := &Broker{
		Config:    mq.Config{URL: fmt.Sprintf("amqp://%s:%s/paddock", host, port.Port()), User: "test", Password: "test"},
		container: c,
	}
	if err := mq.Provision(ctx, b.Config, mq.ProvisionOptions{AuditQueueMaxBytes: 1 << 30}); err != nil {
		t.Fatalf("mqtest: provision: %v", err)
	}
	return b
}

// StopApp stops the RabbitMQ application inside the container (the port stays mapped).
func (b *Broker) StopApp(t testing.TB) { b.ctl(t, "stop_app") }

// StartApp starts the RabbitMQ application again.
func (b *Broker) StartApp(t testing.TB) {
	b.ctl(t, "start_app")
	b.ctl(t, "await_startup")
}

func (b *Broker) ctl(t testing.TB, cmd string) {
	t.Helper()
	code, _, err := b.container.Exec(context.Background(), []string{"rabbitmqctl", cmd})
	if err != nil || code != 0 {
		t.Fatalf("mqtest: rabbitmqctl %s: exit %d, %v", cmd, code, err)
	}
}
