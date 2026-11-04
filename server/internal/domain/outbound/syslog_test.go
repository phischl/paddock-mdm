package outbound_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

var update = flag.Bool("update", false, "rewrite the golden files of testdata/")

// rfc5424 is the header of RFC 5424 section 6 with a nil STRUCTURED-DATA, as FormatSyslog writes it.
var rfc5424 = regexp.MustCompile(`^<(\d{1,3})>1 (\S+) (\S{1,255}) (\S{1,48}) (\S{1,128}) (\S{1,32}) - (.*)$`)

type parsedSyslog struct {
	pri                                     int
	timestamp, hostname, app, procID, msgID string
	msg                                     []byte
}

// parseSyslog checks the octet-counting frame (RFC 6587 section 3.4.1) and the RFC 5424 header and returns the
// fields; MSG is returned without the BOM, which it must start with.
func parseSyslog(t *testing.T, frame []byte) parsedSyslog {
	t.Helper()
	n, rest, ok := bytes.Cut(frame, []byte(" "))
	if !ok {
		t.Fatalf("no MSG-LEN: %q", frame)
	}
	length, err := strconv.Atoi(string(n))
	if err != nil || length != len(rest) {
		t.Fatalf("MSG-LEN %q, message has %d octets", n, len(rest))
	}
	m := rfc5424.FindSubmatch(rest)
	if m == nil {
		t.Fatalf("not RFC 5424: %q", rest)
	}
	pri, _ := strconv.Atoi(string(m[1]))
	msg, ok := bytes.CutPrefix(m[7], []byte("\xef\xbb\xbf"))
	if !ok {
		t.Fatalf("MSG does not start with the BOM: %q", m[7])
	}
	if _, err := time.Parse(time.RFC3339Nano, string(m[2])); err != nil {
		t.Errorf("TIMESTAMP %q: %v", m[2], err)
	}
	return parsedSyslog{pri: pri, timestamp: string(m[2]), hostname: string(m[3]), app: string(m[4]),
		procID: string(m[5]), msgID: string(m[6]), msg: msg}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) //nolint:gosec // a fixed test file
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s:\n got %q\nwant %q", name, got, want)
	}
}

func syslogMessage() outbound.Message {
	return outbound.Message{
		Schema: outbound.MessageSchema, Kind: outbound.KindEvents,
		DeliveryID:     "0193a1b2-0000-7000-8000-000000000001",
		DestinationID:  "0193a1b2-0000-7000-8000-000000000002",
		OrganizationID: "0193a1b2-0000-7000-8000-000000000003", Organization: "acme",
		SentAt: time.Date(2026, 11, 4, 9, 30, 0, 0, time.UTC),
	}
}

func syslogEvent(code audit.Code, outcome audit.Outcome) outbound.MessageEvent {
	return outbound.MessageEvent{ForwardSeq: 41, CommitSeq: 1207, Event: audit.Event{
		Schema: "paddock.audit.v1", EventID: uuid.MustParse("0193a1b2-0000-7000-8000-0000000000aa"),
		OrganizationID: uuid.MustParse("0193a1b2-0000-7000-8000-000000000003"),
		OccurredAt:     time.Date(2026, 11, 4, 9, 29, 58, 123456789, time.FixedZone("CET", 3600)),
		Code:           code, Outcome: outcome, Source: "portal", CorrelationID: "req-1",
		Actor:  audit.Actor{Type: "admin", Display: "alice"},
		Params: map[string]any{"name": "laptop-17"},
	}}
}

// TestFormatSyslog: one RFC 5424 message per event with octet-counting framing; PRI 132 (local0.warning) for failure
// and denied, 133 (local0.notice) otherwise; TIMESTAMP occurred_at in UTC with at most six fractional digits; MSGID the
// code; MSG the BOM and the JSON of ADR 0031 amendment item 2.
func TestFormatSyslog(t *testing.T) {
	m := syslogMessage()
	for _, tc := range []struct {
		name    string
		outcome audit.Outcome
		pri     int
	}{
		{"syslog_event_success", audit.OutcomeSuccess, 133},
		{"syslog_event_failure", audit.OutcomeFailure, 132},
		{"syslog_event_denied", audit.OutcomeDenied, 132},
	} {
		ev := syslogEvent("device.wipe_requested", tc.outcome)
		frame := outbound.FormatSyslog(m, ev, "admin.paddock.example.org")
		golden(t, tc.name, frame)
		p := parseSyslog(t, frame)
		if p.pri != tc.pri || p.hostname != "admin.paddock.example.org" || p.app != "paddock" || p.procID != "acme" ||
			p.msgID != "device.wipe_requested" || p.timestamp != "2026-11-04T08:29:58.123456Z" {
			t.Errorf("%s: header %+v", tc.name, p)
		}
		var msg struct {
			Schema     string      `json:"schema"`
			ForwardSeq int64       `json:"forward_seq"`
			CommitSeq  int64       `json:"commit_seq"`
			DeliveryID string      `json:"delivery_id"`
			Event      audit.Event `json:"event"`
		}
		if err := json.Unmarshal(p.msg, &msg); err != nil {
			t.Fatalf("%s: MSG is not JSON: %v", tc.name, err)
		}
		if msg.Schema != "paddock.audit.v1" || msg.ForwardSeq != 41 || msg.CommitSeq != 1207 ||
			msg.DeliveryID != m.DeliveryID || msg.Event.EventID != ev.Event.EventID || msg.Event.Code != ev.Event.Code {
			t.Errorf("%s: MSG %+v", tc.name, msg)
		}
	}
}

// TestFormatSyslogHeaderLimits: a code longer than the 32 characters RFC 5424 allows for MSGID is sent under its fixed
// alias (the MSG keeps the full code); the platform scope's PROCID is "platform"; an empty host name is the nil value.
func TestFormatSyslogHeaderLimits(t *testing.T) {
	m := syslogMessage()
	m.Organization = outbound.PlatformOrganization
	ev := syslogEvent(audit.CodeNotificationDestinationSecretRotated, audit.OutcomeSuccess)
	p := parseSyslog(t, outbound.FormatSyslog(m, ev, ""))
	if p.msgID != "notification.dest_secret_rotated" || p.procID != "platform" || p.hostname != "-" {
		t.Errorf("header %+v", p)
	}
	if !bytes.Contains(p.msg, []byte(`"code":"notification.destination_secret_rotated"`)) {
		t.Errorf("MSG lost the full code: %s", p.msg)
	}
}

// TestSyslogMsgIDsDistinct: every registered code reaches the frame with its registry MSGID, and none collides with
// the MSGID of a control message, so a receiver can tell events from heartbeats, tests and checkpoints by MSGID alone.
func TestSyslogMsgIDsDistinct(t *testing.T) {
	control := map[string]bool{outbound.MsgIDHeartbeat: true, outbound.MsgIDCheckpoint: true, outbound.MsgIDTest: true}
	m := syslogMessage()
	for _, d := range audit.Definitions() {
		p := parseSyslog(t, outbound.FormatSyslog(m, syslogEvent(d.Code, audit.OutcomeSuccess), "h"))
		if p.msgID != d.Code.MsgID() {
			t.Errorf("%s: frame MSGID %q, registry %q", d.Code, p.msgID, d.Code.MsgID())
		}
		if control[p.msgID] {
			t.Errorf("%s: MSGID %q collides with a control message", d.Code, p.msgID)
		}
	}
}

// TestFormatSyslogControl: heartbeat, test and checkpoint messages carry MSGID paddock.<kind>, PRI 133, sent_at and the
// envelope paddock.notification.v1 as MSG.
func TestFormatSyslogControl(t *testing.T) {
	test := syslogMessage()
	test.Kind, test.Events = outbound.KindTest, []outbound.MessageEvent{}
	frame := outbound.FormatSyslogControl(test, "admin.paddock.example.org")
	golden(t, "syslog_control_test", frame)

	heartbeat := outbound.Heartbeat(40, 1206)
	heartbeat.DeliveryID, heartbeat.Organization, heartbeat.SentAt = test.DeliveryID, "acme", test.SentAt
	checkpoint := outbound.Checkpoint("2026-11-03", 12, "ab12", "sig", 1)
	checkpoint.DeliveryID, checkpoint.Organization, checkpoint.SentAt = test.DeliveryID, "acme", test.SentAt
	for want, m := range map[string]outbound.Message{
		"paddock.test": test, "paddock.heartbeat": heartbeat, "paddock.checkpoint": checkpoint,
	} {
		p := parseSyslog(t, outbound.FormatSyslogControl(m, "admin.paddock.example.org"))
		if p.msgID != want || p.pri != 133 || p.timestamp != "2026-11-04T09:30:00Z" {
			t.Errorf("%s: header %+v", want, p)
		}
		var env outbound.Message
		if err := json.Unmarshal(p.msg, &env); err != nil || env.Schema != outbound.MessageSchema || env.Kind != m.Kind {
			t.Errorf("%s: MSG %s (%v)", want, p.msg, err)
		}
	}
}

// testCAPEM returns a self-signed CA certificate as PEM.
func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestValidateSyslogDestination covers the syslog branch of plan M12 decision 17: host (deny list), port, PEM, server
// name, heartbeat, and checkpoints allowed for webhook and syslog but refused for e-mail.
func TestValidateSyslogDestination(t *testing.T) {
	ctx := context.Background()
	p := outbound.Policy{Resolver: stubResolver{
		"siem.example.org":   []netip.Addr{netip.MustParseAddr("93.184.215.14")},
		"siem.internal.corp": []netip.Addr{netip.MustParseAddr("10.0.0.5")},
	}}
	ca := testCAPEM(t)
	syslog := func(mut func(*outbound.Destination)) outbound.Destination {
		d := outbound.Destination{Type: outbound.TypeSyslog, Name: "SIEM", FilterMode: outbound.FilterSecurity,
			SyslogHost: "siem.example.org"}
		if mut != nil {
			mut(&d)
		}
		return d
	}
	for name, d := range map[string]outbound.Destination{
		"defaults":     syslog(nil),
		"port 1":       syslog(func(d *outbound.Destination) { d.SyslogPort = 1 }),
		"port 65535":   syslog(func(d *outbound.Destination) { d.SyslogPort = 65535 }),
		"public ip":    syslog(func(d *outbound.Destination) { d.SyslogHost = "93.184.215.14" }),
		"ca":           syslog(func(d *outbound.Destination) { d.SyslogCAPEM = ca }),
		"two cas":      syslog(func(d *outbound.Destination) { d.SyslogCAPEM = ca + ca }),
		"server name":  syslog(func(d *outbound.Destination) { d.SyslogServerName = "collector.example.org" }),
		"heartbeat":    syslog(func(d *outbound.Destination) { d.HeartbeatIntervalS = 60 }),
		"checkpoints":  syslog(func(d *outbound.Destination) { d.Checkpoints = true }),
		"webhook ckpt": {Type: outbound.TypeWebhook, Name: "w", FilterMode: outbound.FilterAll, URL: "https://93.184.215.14/x", Checkpoints: true},
	} {
		if err := p.ValidateDestination(ctx, d); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		d    outbound.Destination
		want error
	}{
		"no host":       {syslog(func(d *outbound.Destination) { d.SyslogHost = "" }), outbound.ErrInvalidSyslogHost},
		"host with url": {syslog(func(d *outbound.Destination) { d.SyslogHost = "tls://siem.example.org" }), outbound.ErrInvalidSyslogHost},
		"host port":     {syslog(func(d *outbound.Destination) { d.SyslogHost = "siem.example.org:6514" }), outbound.ErrInvalidSyslogHost},
		"private ip":    {syslog(func(d *outbound.Destination) { d.SyslogHost = "192.168.1.10" }), outbound.ErrSyslogHostDenied},
		"loopback":      {syslog(func(d *outbound.Destination) { d.SyslogHost = "127.0.0.1" }), outbound.ErrSyslogHostDenied},
		"private name":  {syslog(func(d *outbound.Destination) { d.SyslogHost = "siem.internal.corp" }), outbound.ErrSyslogHostDenied},
		"unresolvable":  {syslog(func(d *outbound.Destination) { d.SyslogHost = "nowhere.example.org" }), outbound.ErrSyslogHostLookup},
		"port 0 below":  {syslog(func(d *outbound.Destination) { d.SyslogPort = -1 }), outbound.ErrInvalidSyslogPort},
		"port 65536":    {syslog(func(d *outbound.Destination) { d.SyslogPort = 65536 }), outbound.ErrInvalidSyslogPort},
		"pem garbage":   {syslog(func(d *outbound.Destination) { d.SyslogCAPEM = "not a certificate" }), outbound.ErrInvalidSyslogCA},
		"pem key": {syslog(func(d *outbound.Destination) {
			d.SyslogCAPEM = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
		}), outbound.ErrInvalidSyslogCA},
		"pem trailing":  {syslog(func(d *outbound.Destination) { d.SyslogCAPEM = ca + "junk" }), outbound.ErrInvalidSyslogCA},
		"pem too large": {syslog(func(d *outbound.Destination) { d.SyslogCAPEM = ca + strings.Repeat(" ", outbound.MaxSyslogCAPEM) }), outbound.ErrInvalidSyslogCA},
		"server name":   {syslog(func(d *outbound.Destination) { d.SyslogServerName = "bad name" }), outbound.ErrInvalidServerName},
		"heartbeat 59":  {syslog(func(d *outbound.Destination) { d.HeartbeatIntervalS = 59 }), outbound.ErrInvalidHeartbeat},
		"email checkpoints": {outbound.Destination{Type: outbound.TypeEmail, Name: "e", FilterMode: outbound.FilterAll,
			Recipients: []string{"a@example.org"}, EmailMinIntervalS: 300, Checkpoints: true}, outbound.ErrCheckpointsEmail},
		"webhook syslog field": {outbound.Destination{Type: outbound.TypeWebhook, Name: "w", FilterMode: outbound.FilterAll,
			URL: "https://93.184.215.14/x", SyslogHost: "siem.example.org"}, outbound.ErrSyslogOnly},
	} {
		if err := p.ValidateDestination(ctx, tc.d); !errors.Is(err, tc.want) {
			t.Errorf("%s: err %v, want %v", name, err, tc.want)
		}
	}
	dev := outbound.Policy{AllowPrivate: true}
	if err := dev.ValidateDestination(ctx, syslog(func(d *outbound.Destination) { d.SyslogHost = "127.0.0.1" })); err != nil {
		t.Errorf("development policy refused a private address: %v", err)
	}
}
