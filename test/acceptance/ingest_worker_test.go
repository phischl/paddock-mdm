package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// ingestQueues are the queues a dedicated ingest worker (PADDOCK_WORKER_MODE=ingest) must hold consumers on.
var ingestQueues = []string{"ingest.enroll", "ingest.heartbeat", "ingest.event", "ingest.command_result", "ingest.escrow"}

// composeContainers lists the containers (running or not) of one service of the dev stack.
func composeContainers(ctx context.Context, service string) ([]string, error) {
	out, err := stack.Docker(ctx, nil, "ps", "-aq",
		"--filter", "label=com.docker.compose.project="+stack.Project(),
		"--filter", "label=com.docker.compose.service="+service)
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}

type containerState struct {
	Status       string
	Health       string
	RestartCount int
	IP           string
}

func inspectContainer(ctx context.Context, id string) (containerState, error) {
	out, err := stack.Docker(ctx, nil, "inspect", id)
	if err != nil {
		return containerState{}, err
	}
	var parsed []struct {
		RestartCount int
		State        struct {
			Status string
			Health *struct{ Status string }
		}
		NetworkSettings struct {
			Networks map[string]struct{ IPAddress string }
		}
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil || len(parsed) != 1 {
		return containerState{}, fmt.Errorf("docker inspect %s: %v: %s", id, err, out)
	}
	st := containerState{Status: parsed[0].State.Status, RestartCount: parsed[0].RestartCount,
		IP: parsed[0].NetworkSettings.Networks[stack.Network("data")].IPAddress}
	if parsed[0].State.Health != nil {
		st.Health = parsed[0].State.Health.Status
	}
	return st, nil
}

// rabbitmqctlJSON runs rabbitmqctl in the broker container and decodes its JSON list output.
func rabbitmqctlJSON(ctx context.Context, broker string, out any, args ...string) error {
	res, err := stack.Docker(ctx, nil, append([]string{"exec", broker, "rabbitmqctl", "-q", "--formatter", "json"}, args...)...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(res), out); err != nil {
		return fmt.Errorf("rabbitmqctl %s: %w: %s", args[0], err, res)
	}
	return nil
}

// ingestConsumerQueues returns the ingest queues on which a connection from peer holds a consumer.
func ingestConsumerQueues(ctx context.Context, broker, peer string) (map[string]bool, error) {
	var conns []struct {
		Pid      string `json:"pid"`
		PeerHost string `json:"peer_host"`
	}
	var channels []struct {
		Pid        string `json:"pid"`
		Connection string `json:"connection"`
	}
	var consumers []struct {
		Queue   string `json:"queue_name"`
		Channel string `json:"channel_pid"`
	}
	if err := rabbitmqctlJSON(ctx, broker, &conns, "list_connections", "pid", "peer_host"); err != nil {
		return nil, err
	}
	if err := rabbitmqctlJSON(ctx, broker, &channels, "list_channels", "-p", "paddock", "pid", "connection"); err != nil {
		return nil, err
	}
	if err := rabbitmqctlJSON(ctx, broker, &consumers, "list_consumers", "-p", "paddock", "queue_name", "channel_pid"); err != nil {
		return nil, err
	}
	connOf := map[string]string{}
	for _, c := range conns {
		if c.PeerHost == peer {
			connOf[c.Pid] = c.PeerHost
		}
	}
	chanOK := map[string]bool{}
	for _, ch := range channels {
		if _, ok := connOf[ch.Connection]; ok {
			chanOK[ch.Pid] = true
		}
	}
	queues := map[string]bool{}
	for _, c := range consumers {
		if chanOK[c.Channel] {
			queues[c.Queue] = true
		}
	}
	return queues, nil
}

// TestIngestWorkerConsumes proves that a dedicated ingest worker (PADDOCK_WORKER_INGEST_REPLICAS, PDK-1031) starts
// and stays up, and that it holds consumers on every ingest queue: a worker that crashes at startup (PDK-1070,
// PDK-1017's nil dependencies in every mode) never connects its consumers and restarts in a loop. It skips on a stack
// without an ingest worker; CI starts one shard's stack with PADDOCK_WORKER_INGEST_REPLICAS=1.
func TestIngestWorkerConsumes(t *testing.T) {
	ctx := testContext(t, 5*time.Minute)
	ids, err := composeContainers(ctx, "paddock-worker-ingest")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) == 0 {
		t.Skip("no paddock-worker-ingest container: start the stack with PADDOCK_WORKER_INGEST_REPLICAS=1 to run this gate")
	}
	brokers, err := composeContainers(ctx, "rabbitmq")
	if err != nil || len(brokers) != 1 {
		t.Fatalf("rabbitmq container: %v, %v", brokers, err)
	}

	for _, id := range ids {
		deadline := time.Now().Add(3 * time.Minute)
		for {
			st, err := inspectContainer(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if st.RestartCount > 0 || st.Status == "restarting" || st.Status == "exited" {
				t.Fatalf("ingest worker %.12s crashes: status %s, %d restarts (docker logs shows why)", id, st.Status, st.RestartCount)
			}
			if st.Status == "running" && st.Health == "healthy" {
				queues, err := ingestConsumerQueues(ctx, brokers[0], st.IP)
				if err != nil {
					t.Fatal(err)
				}
				var missing []string
				for _, q := range ingestQueues {
					if !queues[q] {
						missing = append(missing, q)
					}
				}
				if len(missing) == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("ingest worker %.12s (%s) holds no consumer on %v", id, st.IP, missing)
				}
			} else if time.Now().After(deadline) {
				t.Fatalf("ingest worker %.12s not healthy within 3 minutes: status %s, health %q", id, st.Status, st.Health)
			}
			time.Sleep(3 * time.Second)
		}
	}
}
