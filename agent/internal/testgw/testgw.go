// Package testgw is a fake device API gateway for agent tests: it verifies request signatures like the real gateway
// and answers with programmable responses.
package testgw

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/client"
	"github.com/paddock-mdm/paddock/agent/internal/config"
	"github.com/paddock-mdm/paddock/agent/internal/identity"
	"github.com/paddock-mdm/paddock/agent/internal/paths"
	"github.com/paddock-mdm/paddock/agent/internal/state"
	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// Gateway is the fake. Lock Mu when changing the programmable fields while requests may run.
type Gateway struct {
	*httptest.Server
	t *testing.T

	Mu           sync.Mutex
	EnrollStatus protocol.EnrollStatus // answer of GET /v1/enroll/{id}
	CheckinFail  int                   // HTTP status of the next check-ins (0 = success)
	Checkin      protocol.CheckinResponse
	EventsFail   int
	Files        map[string][]byte // GET /files/<name> (presigned downloads)

	keys     map[string]*ecdsa.PublicKey // key ID → key (enrolled keys)
	Enrolls  []protocol.EnrollRequest
	Checkins []Checkin
	Events   []protocol.Event
	seq      int64
}

// Checkin is a received check-in with its Paddock-Seq header.
type Checkin struct {
	Seq int64
	Req protocol.CheckinRequest
}

// New starts a TLS fake gateway.
func New(t *testing.T) *Gateway {
	g := &Gateway{t: t, keys: map[string]*ecdsa.PublicKey{}, Files: map[string][]byte{},
		EnrollStatus: protocol.EnrollStatus{Status: protocol.EnrollProcessing}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", g.enroll)
	mux.HandleFunc("GET /v1/enroll/{id}", g.status)
	mux.HandleFunc("POST /v1/checkin", g.checkin)
	mux.HandleFunc("POST /v1/events", g.events)
	mux.HandleFunc("GET /files/{name}", func(w http.ResponseWriter, r *http.Request) {
		g.Mu.Lock()
		data, ok := g.Files[r.PathValue("name")]
		g.Mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	})
	g.Server = httptest.NewTLSServer(mux)
	t.Cleanup(g.Close)
	return g
}

// URL of a file served under /files/.
func (g *Gateway) FileURL(name string) string { return g.URL + "/files/" + name }

func (g *Gateway) verify(w http.ResponseWriter, r *http.Request, pub *ecdsa.PublicKey) ([]byte, protocol.Headers, bool) {
	body, _ := io.ReadAll(r.Body)
	h, err := protocol.ParseHeaders(r.Header)
	if err == nil && pub == nil {
		pub = g.keys[h.KeyID]
	}
	if err != nil || pub == nil || protocol.Verify(pub, r.Method, r.URL.RequestURI(), h, body) != nil {
		g.t.Errorf("%s %s: bad signature (%v)", r.Method, r.URL.Path, err)
		problem(w, http.StatusUnauthorized, protocol.CodeInvalidSignature)
		return nil, h, false
	}
	return body, h, true
}

func (g *Gateway) enroll(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req protocol.EnrollRequest
	_ = json.Unmarshal(body, &req)
	spki, _ := base64.StdEncoding.DecodeString(req.PublicKey)
	pub, err := protocol.ParsePublicKey(spki)
	h, herr := protocol.ParseHeaders(r.Header)
	if err != nil || herr != nil || h.Device != protocol.EnrollDevice || h.KeyID != protocol.KeyID(spki) ||
		protocol.Verify(pub, r.Method, r.URL.RequestURI(), h, body) != nil {
		g.t.Errorf("enroll: invalid proof of possession")
		problem(w, http.StatusUnauthorized, protocol.CodeInvalidSignature)
		return
	}
	g.Mu.Lock()
	g.keys[h.KeyID] = pub
	g.Enrolls = append(g.Enrolls, req)
	g.Mu.Unlock()
	writeJSON(w, http.StatusAccepted, protocol.EnrollAccepted{EnrollmentID: "0190f000-0000-7000-8000-000000000001"})
}

func (g *Gateway) status(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") != "0190f000-0000-7000-8000-000000000001" {
		problem(w, http.StatusNotFound, protocol.CodeNotFound)
		return
	}
	if _, _, ok := g.verify(w, r, nil); !ok {
		return
	}
	g.Mu.Lock()
	defer g.Mu.Unlock()
	writeJSON(w, http.StatusOK, g.EnrollStatus)
}

func (g *Gateway) checkin(w http.ResponseWriter, r *http.Request) {
	body, h, ok := g.verify(w, r, nil)
	if !ok {
		return
	}
	g.Mu.Lock()
	defer g.Mu.Unlock()
	var req protocol.CheckinRequest
	_ = json.Unmarshal(body, &req)
	g.Checkins = append(g.Checkins, Checkin{Seq: h.Seq, Req: req})
	if g.CheckinFail != 0 {
		problem(w, g.CheckinFail, "internal")
		return
	}
	g.seq++
	out := g.Checkin
	out.Seq, out.ServerTime = g.seq, time.Now().UTC()
	writeJSON(w, http.StatusOK, out)
}

func (g *Gateway) events(w http.ResponseWriter, r *http.Request) {
	body, _, ok := g.verify(w, r, nil)
	if !ok {
		return
	}
	g.Mu.Lock()
	defer g.Mu.Unlock()
	if g.EventsFail != 0 {
		problem(w, g.EventsFail, "internal")
		return
	}
	var req protocol.EventsRequest
	_ = json.Unmarshal(body, &req)
	if len(req.Events) == 0 || len(req.Events) > protocol.MaxEventsPerBatch {
		problem(w, http.StatusBadRequest, protocol.CodeInvalidRequest)
		return
	}
	g.Events = append(g.Events, req.Events...)
	w.WriteHeader(http.StatusAccepted)
}

// EventTypes returns the types of the received events in order.
func (g *Gateway) EventTypes() []string {
	g.Mu.Lock()
	defer g.Mu.Unlock()
	out := make([]string, len(g.Events))
	for i, e := range g.Events {
		out[i] = e.Type
	}
	return out
}

func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(protocol.Problem{Type: "urn:paddock:problem:" + code, Title: strings.ToLower(http.StatusText(status)), Status: status, Code: code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// TrustKey is the bundle-signing key the fake trusts (seeded, so tests can sign bundles).
var TrustKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

// OrgID and DeviceID of the fake enrollment.
const (
	OrgID    = "0190f000-0000-7000-8000-00000000000a"
	DeviceID = "0190f000-0000-7000-8000-00000000000d"
)

// EnrollmentConfig returns an enrollment configuration that points to the fake.
func (g *Gateway) EnrollmentConfig() protocol.EnrollmentConfig {
	return protocol.EnrollmentConfig{
		ServerURL: g.URL, OrganizationID: OrgID, Token: "secret-token",
		BundleKeys: []protocol.BundleKey{{KeyID: "bundle-signing:v1", PublicKey: base64.StdEncoding.EncodeToString(TrustKey.Public().(ed25519.PublicKey))}},
	}
}

// Enrolled prepares a layout in a temporary root as `paddockd enroll` leaves it for an active device, registers
// the key with the fake and returns the layout and key.
func (g *Gateway) Enrolled(t *testing.T) (paths.Layout, identity.Key) {
	t.Helper()
	l := paths.Layout{Root: t.TempDir()}
	ec := g.EnrollmentConfig()
	if err := config.SaveAgent(l.AgentConfig(), config.Agent{ServerURL: ec.ServerURL, OrganizationID: OrgID, DriftInterval: config.DefaultDriftInterval}); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveTrust(l.Trust(), ec.BundleKeys); err != nil {
		t.Fatal(err)
	}
	key, err := identity.LoadOrCreate(l.IdentityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Save(l.State(), state.State{EnrollmentID: "0190f000-0000-7000-8000-000000000001", DeviceID: DeviceID, Status: state.StatusActive}); err != nil {
		t.Fatal(err)
	}
	pub, _ := protocol.ParsePublicKey(key.SPKI)
	g.Mu.Lock()
	g.keys[key.KeyID] = pub
	g.Mu.Unlock()
	return l, key
}

// Client returns a device API client for key that trusts the fake's certificate.
func (g *Gateway) Client(key identity.Key) *client.Client {
	return client.NewWithHTTP(g.URL, g.Server.Client(), key, time.Now)
}
