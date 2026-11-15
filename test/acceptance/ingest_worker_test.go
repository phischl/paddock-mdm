package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
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

// ingestConsumerQueues returns the ingest queues on which a connection from peer holds a consumer, and the broker's
// numbers (see channelNumber) of the channels that carry them.
func ingestConsumerQueues(ctx context.Context, broker, peer string) (map[string]bool, map[string]bool, error) {
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
		return nil, nil, err
	}
	if err := rabbitmqctlJSON(ctx, broker, &channels, "list_channels", "-p", "paddock", "pid", "connection"); err != nil {
		return nil, nil, err
	}
	if err := rabbitmqctlJSON(ctx, broker, &consumers, "list_consumers", "-p", "paddock", "queue_name", "channel_pid"); err != nil {
		return nil, nil, err
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
	queues, numbers := map[string]bool{}, map[string]bool{}
	for _, c := range consumers {
		if chanOK[c.Channel] {
			queues[c.Queue] = true
			numbers[channelNumber(c.Channel)] = true
		}
	}
	return queues, numbers, nil
}

var channelNumberRe = regexp.MustCompile(`(\d+\.\d+)\D*$`)

// channelNumber reduces a channel's process ID to its "<id>.<serial>" part: rabbitmqctl prints the pid with the node's
// number in front (Pid(#PID<14601.1329.0>)), the metrics endpoint with a local 0 (<0.1329.0>).
func channelNumber(pid string) string {
	if m := channelNumberRe.FindStringSubmatch(pid); m != nil {
		return m[1]
	}
	return pid
}

var ackedRe = regexp.MustCompile(`rabbitmq_detailed_channel_messages_acked_total\{channel=\\*"<0\.(\d+\.\d+)>\\*",vhost=\\*"paddock\\*",queue=\\*"([^"\\]+)\\*"\} (\d+)`)

// ackedByIngestWorker sums the messages the given channels acknowledged on the ingest queues. Only a worker that
// processed a delivery acknowledges it, so the sum rises only by what the ingest worker handled. The numbers come from
// the broker's Prometheus plugin, queried inside the broker where the endpoint is always reachable.
func ackedByIngestWorker(ctx context.Context, broker string, channels map[string]bool) (int, error) {
	out, err := stack.Docker(ctx, nil, "exec", broker, "rabbitmqctl", "-q", "eval",
		`inets:start(), {ok,{_,_,B}} = httpc:request("http://127.0.0.1:15692/metrics/detailed?family=channel_queue_metrics"), io:format("~s", [B]).`)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, m := range ackedRe.FindAllStringSubmatch(out, -1) {
		n, _ := strconv.Atoi(m[3])
		if channels[m[1]] && strings.HasPrefix(m[2], "ingest.") {
			total += n
		}
	}
	return total, nil
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
				queues, channels, err := ingestConsumerQueues(ctx, brokers[0], st.IP)
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
					processesMessages(t, brokers[0], channels)
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

// processesMessages drives ingest messages (a device enrolls and checks in; each check-in publishes a heartbeat) until
// the ingest worker's channels have acknowledged at least one of them. The full worker consumes the same queues, so
// not every message reaches the ingest worker; the broker, however, hands each message to the next consumer with free
// prefetch, so a healthy ingest worker receives about every second one and the chance that none of ~45 messages in
// two minutes reaches it is below 2^-40. Only a worker that consumes and processes lets the count rise, so the gate
// fails on a consumer that is connected but does not work.
func processesMessages(t *testing.T, broker string, channels map[string]bool) {
	t.Helper()
	ctx := testContext(t, 4*time.Minute)
	before, err := ackedByIngestWorker(ctx, broker, channels)
	if err != nil {
		t.Fatal(err)
	}
	d := activeDevice(t, login(t, env.Alice), "", "ingest-smoke-"+uniqueSuffix())
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if _, res, err := d.Checkin(ctx); err != nil || res.Status != http.StatusOK {
			t.Fatalf("checkin: %v HTTP %d %s", err, res.Status, res.Body)
		}
		time.Sleep(2600 * time.Millisecond)
		after, err := ackedByIngestWorker(ctx, broker, channels)
		if err != nil {
			t.Fatal(err)
		}
		if after > before {
			t.Logf("ingest worker acknowledged %d messages", after-before)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the ingest worker acknowledged no message in 2 minutes of heartbeats (acked %d)", after)
		}
	}
}
