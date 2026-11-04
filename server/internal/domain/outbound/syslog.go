package outbound

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// AuditSchema is the schema of the MSG of a syslog event message (ADR 0031 amendment 2026-11-04 item 2).
const AuditSchema = "paddock.audit.v1"

// Fields of the RFC 5424 header of a syslog message (ADR 0031 amendment 2026-11-04 item 2).
const (
	SyslogAppName = "paddock"
	// MsgIDHeartbeat, MsgIDCheckpoint and MsgIDTest are the MSGID of the control messages.
	MsgIDHeartbeat  = "paddock.heartbeat"
	MsgIDCheckpoint = "paddock.checkpoint"
	MsgIDTest       = "paddock.test"
	// PRI = facility local0 (16) × 8 + severity: notice (5) or warning (4).
	SyslogPRINotice  = 16*8 + 5
	SyslogPRIWarning = 16*8 + 4
)

// Lengths of the RFC 5424 header fields (section 6).
const (
	maxHostname = 255
	maxProcID   = 128
	maxMsgID    = audit.MaxMsgIDLen
)

// syslogBOM starts every MSG: RFC 5424 section 6.4 marks UTF-8 content with it.
const syslogBOM = "\xef\xbb\xbf"

// syslogEvent is the MSG of one forwarded event.
type syslogEvent struct {
	Schema     string      `json:"schema"`
	ForwardSeq int64       `json:"forward_seq"`
	CommitSeq  int64       `json:"commit_seq"`
	DeliveryID string      `json:"delivery_id"`
	Event      audit.Event `json:"event"`
}

// FormatSyslog returns the RFC 5424 message of one forwarded event with octet-counting framing (RFC 6587 section
// 3.4.1): PRI local0.warning for the outcomes failure and denied, local0.notice otherwise; TIMESTAMP the event's
// occurred_at; HOSTNAME hostname; APP-NAME paddock; PROCID the organization slug of m; MSGID the audit code or, for
// a code longer than 32 characters, its fixed alias (audit.Code.MsgID); STRUCTURED-DATA nil; MSG the BOM and the
// JSON of schema paddock.audit.v1, which always carries the full code.
func FormatSyslog(m Message, ev MessageEvent, hostname string) []byte {
	pri := SyslogPRINotice
	if ev.Event.Outcome == audit.OutcomeFailure || ev.Event.Outcome == audit.OutcomeDenied {
		pri = SyslogPRIWarning
	}
	body, err := json.Marshal(syslogEvent{
		Schema: AuditSchema, ForwardSeq: ev.ForwardSeq, CommitSeq: ev.CommitSeq, DeliveryID: m.DeliveryID, Event: ev.Event,
	})
	if err != nil {
		// Params come from the audit index as JSON and always encode; the fallback keeps the numbering visible to
		// the receiver should one ever not.
		body, _ = json.Marshal(map[string]any{
			"schema": AuditSchema, "forward_seq": ev.ForwardSeq, "commit_seq": ev.CommitSeq,
			"delivery_id": m.DeliveryID, "error": "event not encodable",
		})
	}
	return syslogFrame(pri, ev.Event.OccurredAt, hostname, m.Organization, ev.Event.Code.MsgID(), body)
}

// FormatSyslogControl returns the RFC 5424 message of a heartbeat, test or checkpoint with octet-counting framing:
// PRI local0.notice, TIMESTAMP sent_at, MSGID paddock.<kind>, MSG the BOM and the JSON envelope
// paddock.notification.v1 of m (plan M9 §6.4).
func FormatSyslogControl(m Message, hostname string) []byte {
	var msgID string
	switch m.Kind {
	case KindHeartbeat:
		msgID = MsgIDHeartbeat
	case KindCheckpoint:
		msgID = MsgIDCheckpoint
	case KindTest:
		msgID = MsgIDTest
	default:
		msgID = "paddock." + m.Kind
	}
	body, err := json.Marshal(m)
	if err != nil {
		body = []byte(`{"schema":"` + MessageSchema + `","kind":"` + m.Kind + `"}`)
	}
	return syslogFrame(SyslogPRINotice, m.SentAt, hostname, m.Organization, msgID, body)
}

// syslogFrame assembles "MSG-LEN SP <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - BOM MSG".
func syslogFrame(pri int, at time.Time, hostname, procID, msgID string, body []byte) []byte {
	var b strings.Builder
	b.WriteString("<" + strconv.Itoa(pri) + ">1 ")
	if at.IsZero() {
		b.WriteString("-")
	} else {
		// RFC 5424 allows at most six fractional digits.
		b.WriteString(at.UTC().Format("2006-01-02T15:04:05.999999Z07:00"))
	}
	b.WriteString(" " + headerField(hostname, maxHostname))
	b.WriteString(" " + SyslogAppName)
	b.WriteString(" " + headerField(procID, maxProcID))
	b.WriteString(" " + headerField(msgID, maxMsgID))
	b.WriteString(" - " + syslogBOM)
	b.Write(body)
	msg := b.String()
	return []byte(strconv.Itoa(len(msg)) + " " + msg)
}

// headerField is v as an RFC 5424 header field: printable US-ASCII only (anything else becomes "_"), at most max
// characters, the nil value "-" when empty.
func headerField(v string, limit int) string {
	if v == "" {
		return "-"
	}
	out := []byte(v)
	for i, c := range out {
		if c < 33 || c > 126 {
			out[i] = '_'
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return string(out)
}
