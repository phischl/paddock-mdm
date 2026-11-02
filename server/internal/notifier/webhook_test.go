package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

func testMessage(dest uuid.UUID) outbound.Message {
	return outbound.Message{Schema: outbound.MessageSchema, Kind: outbound.KindTest, DeliveryID: uuid.NewString(),
		DestinationID: dest.String(), OrganizationID: uuid.NewString(), Organization: "acme",
		SentAt: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC), Events: []outbound.MessageEvent{}}
}

// TestWebhookHeaders: the request carries the signed body and the headers of plan M9 §6.4; the signature verifies
// with the destination's secret.
func TestWebhookHeaders(t *testing.T) {
	type got struct {
		header http.Header
		body   []byte
	}
	reqs := make(chan got, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		reqs <- got{header: r.Header.Clone(), body: body}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	w := NewWebhook(true, "1.2.3")
	at := time.Unix(1_790_000_000, 0)
	w.now = func() time.Time { return at }
	d := Destination{ID: uuid.Must(uuid.NewV7()), URL: srv.URL + "/hook?token=x", Secret: []byte("whsec-test")}
	m := testMessage(d.ID)
	if err := w.Deliver(context.Background(), d, m); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	r := <-reqs
	ts := strconv.FormatInt(at.Unix(), 10)
	for name, want := range map[string]string{
		"Content-Type": "application/json", "User-Agent": "paddock-notifier/1.2.3",
		outbound.HeaderTimestamp: ts, outbound.HeaderDelivery: m.DeliveryID, outbound.HeaderDestination: d.ID.String(),
		outbound.HeaderSignature: outbound.Signature([]byte("whsec-test"), at.Unix(), r.body),
	} {
		if got := r.header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	var back outbound.Message
	if err := json.Unmarshal(r.body, &back); err != nil || back.DeliveryID != m.DeliveryID || back.Kind != outbound.KindTest {
		t.Errorf("body %s: %v", r.body, err)
	}
}

// TestWebhookFailures: a redirect, a 500 and a refused address are failures with their class only, never the URL.
func TestWebhookFailures(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer big.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/elsewhere", http.StatusFound)
	}))
	defer redirect.Close()
	bare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusFound) }))
	defer bare.Close()

	dev := NewWebhook(true, "dev")
	for _, c := range []struct {
		name string
		w    *Webhook
		url  string
		want string
	}{
		{"server error", dev, big.URL, "http_500"},
		{"redirect", dev, redirect.URL, "redirect"},
		{"redirect without location", dev, bare.URL, "redirect"},
		{"private address in production", NewWebhook(false, "prod"), strings.Replace(redirect.URL, "http:", "https:", 1), "denied_address"},
		{"plain http in production", NewWebhook(false, "prod"), "http://sink.example/hook", "denied_address"},
		{"refused connection", dev, "http://127.0.0.1:1/", "dial"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := Destination{ID: uuid.Must(uuid.NewV7()), URL: c.url, Secret: []byte("s")}
			err := c.w.Deliver(context.Background(), d, testMessage(d.ID))
			if got := ErrorClass(err); got != c.want {
				t.Fatalf("class %q (%v), want %q", got, err, c.want)
			}
			if strings.Contains(err.Error(), c.url) || strings.Contains(err.Error(), "127.0.0.1") {
				t.Errorf("error %q names the URL", err)
			}
		})
	}
}

// countingBody is an endless response body that counts what was read from it.
type countingBody struct{ n int }

func (b *countingBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	b.n += len(p)
	return len(p), nil
}

func (*countingBody) Close() error { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestWebhookDrainsAtMost4KiB: an answer body is read up to 4 KiB and discarded.
func TestWebhookDrainsAtMost4KiB(t *testing.T) {
	body := &countingBody{}
	w := NewWebhook(true, "dev")
	w.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body, Header: http.Header{}}, nil
	})
	d := Destination{ID: uuid.Must(uuid.NewV7()), URL: "https://sink.example/", Secret: []byte("s")}
	if err := w.Deliver(context.Background(), d, testMessage(d.ID)); err != nil {
		t.Fatal(err)
	}
	if body.n == 0 || body.n > 4<<10 {
		t.Errorf("read %d bytes of the answer, want 1 to 4096", body.n)
	}
}
