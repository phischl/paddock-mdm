# Notifications

Paddock tells a person outside the portal when something security-relevant happens: a signed HTTPS webhook or an
e-mail to a list of addresses (ADR 0031, plan M9). A destination receives audit events from the organization's own
audit log; the platform has destinations of its own for platform events. For a SIEM that pulls instead, see
[siem.md](siem.md). What leaves the server and who receives it: [privacy.md](../compliance/privacy.md), "What leaves
the server".

| | Organization destinations | Platform destinations |
| --- | --- | --- |
| Portal | *Organization* → *Notifications* (`/settings/notifications`) | *Platform* → *Platform notifications* (`/platform/notifications`) |
| Events | the organization's audit events | the platform's events: rollouts, releases, vulnerability data, the IP allow list, chain verification |
| Create, change, delete, test | organization administrators, each with a step-up | platform administrators, each with a step-up |
| View | administrators and auditors (never a URL or secret) | platform administrators |
| API | `/api/v1/notification-destinations` | `/api/platform/v1/notification-destinations` |

The service that delivers is the role `paddock-notifier` on the control plane. It is the only role that can decrypt a
destination's URL and secret; it needs the database role `paddock_notifier`, the OpenBao AppRole `paddock-notifier`
and the Transit keys `notification-wrap` and `notification-pseudonym`. A new installation has all of it; a cluster that
was initialized earlier follows [upgrade.md](upgrade.md), "Notifications on a cluster initialized before them".

## Create a destination

*Add destination* opens the form. Every create, change, delete, secret replacement and test asks for your second
factor first (step-up, valid for 5 minutes).

| Field | Meaning |
| --- | --- |
| *Type* | *Webhook* or *E-mail*. *E-mail* is offered only when the installation has an SMTP relay ([E-mail](#e-mail)). |
| *Name* | 1 to 64 characters: letters, digits, spaces, `.`, `_`, `-`; starts with a letter or digit; unique per scope. |
| *Webhook URL* | an `https` address, see [Webhook URLs](#urls). Stored encrypted; the portal and the API show only `url_display` (scheme, host and `/…`), never the URL. |
| *Recipients* | e-mail only: 1 to 20 plain addresses, no display names. |
| *Events* | the filter, see [Which events](#which-events). |
| *Replace user names with pseudonyms* | organization destinations only, see [Privacy options](#privacy-options). |
| *Include event parameters* | e-mail only: add each event's parameters to the message body. |
| *Heartbeat interval (seconds)* | webhook only: 0 (off, the default) or 60 to 3600. |
| *Minimum interval between e-mails (seconds)* | e-mail only: 60 to 3600, default 300. |
| *Enabled* | a disabled destination receives nothing. |

A webhook's signing secret is shown **once**, after the create and after *Replace secret*; copy it into the receiver
at once. Paddock cannot show it again, and anyone who reads it can forge messages. A new destination starts at the
newest event: it never replays history.

Enabling a disabled destination asks where delivery resumes: *Deliver the events since it was disabled* (`continue`) or
*Skip them and continue with the newest event* (`skip`). Both choices are audited with the change.

*Send test* delivers one test message (webhook: the signed envelope with `kind: test` and no events; e-mail: "[Paddock]
<organization>: test notification") with exactly one attempt and shows the result inline; the portal waits up to
30 seconds. The notifier delivers it in its next round, so the answer takes up to one poll interval
(`PADDOCK_NOTIFY_POLL_INTERVAL`, default 30 s).

Limits you may meet: one test per destination can be pending, and one pseudonym lookup per organization (unresolved and
younger than 10 minutes). A further request answers 409 `invalid_state` until the pending one resolves or expires.
A test for a disabled destination stays pending until the destination is enabled.

## Which events

*Events* selects one of three filters:

- *Security events* (`security`): the preset below.
- *All events* (`all`): every audit event, routine changes included.
- *Selected events* (`custom`): 1 to 200 registered audit codes you pick ([audit-codes.md](../compliance/audit-codes.md);
  the server refuses an unregistered code with 400 `unknown_code`).

An event with outcome `unknown` (the result of the action is open) is delivered in every mode. The first run's
inventory of existing role members (`admin.role_granted` with `baseline: true`) is never delivered.

The preset is versioned with the audit code registry: every registered code of these groups belongs to it, so codes
added to a group later join it without a configuration change.

- Groups: `device.tamper_*`, `permission_profile.*`, `profile_assignment.*`, `api_token.*`, `revocation.*`,
  `organization.*`, `settings.*`, `notification.destination_*`, `finding.*`.
- Single codes: `device.clone_suspected`, `device.bundle_rejected`, `device.agent_events_dropped`,
  `device.agent_rollback_failed`, `device.stale_critical`, `device.presumed_self_locked`,
  `device.revocation_trust_pinned_tofu`, `device.revocation_confirmed`, `device.revocation_refused`,
  `device.event_gap`, `device.event_seq_reset`, `device.clock_drift`, `device.retired`,
  `device.uninstall_requested`, `device.escrow_destroyed`, `local_admin.revealed`, `local_admin.login`,
  `disk.recovery_key_revealed`, `disk.header_downloaded`, `user_group.member_added`, `user_group.member_removed`,
  `user.locked`, `user.unlocked`, `admin.login`, `admin.role_granted`, `admin.role_revoked`,
  `admin.mcp_write_enabled`, `admin.mcp_write_disabled`, `admin.sessions_revoked`, `agent_rollout.halted`,
  `agent_release.published`, `audit.chain_verification_failed`, `audit.export_requested`,
  `audit.export_downloaded`, `config.applied`, `managed_file.sensitive_confirmed`, `notification.pseudonym_resolved`,
  `platform.osv_stale`, `platform.ip_allowlist_changed`, `platform.ip_allowlist_disabled`,
  `platform.ip_allowlist_denied`, `platform.mcp_policy_changed`, `platform.sessions_ended`,
  `platform.auto_unseal_enabled`, `platform.auto_unseal_disabled`, `vulnerability.critical_summary`.

Not in the preset, because they end a condition or are routine: `device.event_gap_filled`, `device.clock_drift_cleared`,
`audit.chain_verified`, `audit.export_completed`, `retention.purged`, `device.inventory_purged`,
`device.inventory_host_kept`, `device.uninstalled`, `device.uninstall_cancelled`, the `device.disk_conversion_*` and
`device.encrypt_*` codes, `enrollment_token.*`, `agent_rollout.*` other than `halted`, `agent_release.*` other than
`published`, `notification.delivered`, `notification.test_requested`, `notification.test_sent`.
`config_rollout.halted` joins the preset when the change that registers it lands.

`vulnerability.critical_summary` is one event per organization and UTC day that lists the critical vulnerabilities
first seen since the previous summary (count, devices, up to 20 CVE IDs). A CVE that was re-rated to critical after it
was first seen is not in a summary in this release (follow-up PDK-639).

## Webhook

### URLs

Paddock calls a webhook only with these rules, checked when you save and again at every call:

- scheme `https`, no user name or password in the URL, port 443 or 1024 to 65535;
- the host is a public address: a host name whose every address, or an IP literal, is outside the denied networks
  (this host, private, shared, link-local, benchmark, documentation, multicast and reserved ranges, IPv4-mapped IPv6,
  NAT64, 6to4, Teredo and the discard prefix; `DeniedPrefixes` in `server/internal/domain/outbound/url.go`);
- the connection goes to the checked address; redirects are never followed; 10 seconds to connect, 30 seconds in total;
  TLS 1.2 or newer, the certificate is verified.

So a receiver inside your network (a private address) cannot be a destination of a production installation: put an
internet-reachable relay in front, or use e-mail. Only the development stack lifts this (`PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE`);
`./paddock check` refuses it in production.

**Known limitation (alpha.7):** the notifier does not use an outbound HTTP proxy (`HTTP_PROXY` and `NO_PROXY` are not
applied to webhook calls); the control-plane host must reach the receiver directly (follow-up PDK-625).

### Envelope and headers

A delivery is a `POST` with the JSON body below (`schema: paddock.notification.v1`) and these headers:

| Header | Value |
| --- | --- |
| `Content-Type` | `application/json` |
| `User-Agent` | `paddock-notifier/<version>` |
| `X-Paddock-Timestamp` | Unix time in seconds when the call was made |
| `X-Paddock-Signature` | `v1=` and the hex HMAC-SHA256 over `<timestamp>.<body>`, see [Verify the signature](#verify-the-signature) |
| `X-Paddock-Delivery` | the delivery ID (the same on a retry of the same batch) |
| `X-Paddock-Destination` | the destination ID |

```json
{
  "schema": "paddock.notification.v1",
  "kind": "events",
  "delivery_id": "0199…",
  "destination_id": "0199…",
  "organization_id": "0199…",
  "organization": "acme",
  "sent_at": "2026-10-31T08:15:00Z",
  "forward_seq": { "from": 41, "to": 43 },
  "events": [
    {
      "forward_seq": 41,
      "commit_seq": 1290,
      "links": { "device": "https://admin.example.org/devices/0199…" },
      "event": {
        "schema": "paddock.audit.v1", "event_id": "0199…", "organization_id": "0199…",
        "occurred_at": "2026-10-31T08:14:58Z", "recorded_at": "2026-10-31T08:14:59Z",
        "code": "device.tamper_sudoers_d_file", "outcome": "success", "source": "device",
        "actor": { "type": "device", "id": "0199…", "step_up": false },
        "target": { "type": "device", "id": "0199…", "display": "lt-01" },
        "params": { "file": "/etc/sudoers.d/90-extra" },
        "correlation_id": "0199…"
      }
    }
  ]
}
```

- `kind` is `events`, `heartbeat` or `test`; a heartbeat and a test carry `"events": []`. A heartbeat has
  `forward_seq: {"last": N}` and the audit `cursor`. (`checkpoint` is reserved for a later release.)
- `organization` is the organization's slug, `"platform"` for a platform destination.
- `events` are in audit commit order. `forward_seq` counts the events this destination received, without gaps;
  `commit_seq` is the event's position in the organization's audit commit order (the same number as in the
  [audit feed](siem.md)). `event` is the stored audit event.
- `links.device` is present for events whose target is a device; it points into the portal under
  `PADDOCK_PUBLIC_ADMIN_URL`.
- A webhook always carries the event's parameters, whatever *Include event parameters* says (that field shapes e-mails).
  Pseudonymization is applied to `event` before the message is signed.
- At most `PADDOCK_NOTIFY_BATCH` events (default and maximum 100) travel in one delivery.

### Verify the signature

The key is the secret string exactly as shown (43 characters of base64url): use its bytes as they are, do not decode
it. Sign `timestamp + "." + raw body`, compare in constant time, and refuse a timestamp that is more than a few minutes
old. A receiver answers `2xx` once it has stored the message; anything else is a failed delivery and is retried.

A fixed test vector, to check your code before you trust it: with the secret `whsec-test`, the timestamp `1700000000`
and the body `{"kind":"test"}` the header is

```
X-Paddock-Signature: v1=454143f1532cdf4875295398c04b1ff35f08766b374f6de114b2f6d26914931d
```

Python:

```python
import hashlib
import hmac
import time


def verify(secret: str, headers, body: bytes, tolerance_s: int = 300) -> bool:
    timestamp = headers["X-Paddock-Timestamp"]
    if abs(time.time() - int(timestamp)) > tolerance_s:
        return False
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest("v1=" + mac, headers["X-Paddock-Signature"])
```

Go:

```go
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

func verify(secret string, timestamp, signature string, body []byte, tolerance time.Duration) bool {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || time.Since(time.Unix(ts, 0)).Abs() > tolerance {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	return hmac.Equal([]byte("v1="+hex.EncodeToString(mac.Sum(nil))), []byte(signature))
}
```

Read the body as bytes before you parse it: the signature covers the exact bytes Paddock sent.

Delivery is at least once. After a crash or a lost answer the same batch is sent again with the same `delivery_id` and
`forward_seq` range; a receiver that must not process an event twice keeps the last `forward_seq` (or the `event_id`s)
it has stored. A jump in `forward_seq` means events were lost between Paddock and you; it should not happen, see
[Limits](#limits-and-known-limitations).

### Try it on the development stack

The development stack lifts the public-address rule (`PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE=true`, plain `http`). Start a
receiver that checks the signature, create a destination for it and send a test:

```python
# receiver.py: python3 receiver.py <secret>
import hashlib, hmac, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = sys.argv[1]


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        timestamp = self.headers["X-Paddock-Timestamp"]
        mac = hmac.new(SECRET.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest("v1=" + mac, self.headers["X-Paddock-Signature"]) and abs(time.time() - int(timestamp)) < 300
        print("signature", "OK" if ok else "MISMATCH", body[:120])
        self.send_response(204 if ok else 401)
        self.end_headers()


HTTPServer(("0.0.0.0", 8099), Handler).serve_forever()
```

The notifier container reaches the host as `acceptance-host` (`extra_hosts: acceptance-host:host-gateway` in
`compose.dev.yaml`). Create the destination with the URL `http://acceptance-host:8099/`, copy the shown secret, start
`receiver.py` with it, and press *Send test*: the receiver prints `signature OK` within a poll interval (5 s on the
development stack).

## E-mail

An e-mail destination sends through **your** SMTP relay; Paddock has no mail server. The relay is platform
configuration of `paddock-notifier`, set in `.env` ([install.md](install.md), "E-mail relay"):

| Variable | Meaning |
| --- | --- |
| `PADDOCK_SMTP_HOST` | the relay; empty means e-mail destinations are refused (409 `email_not_configured`) and the portal does not offer the type |
| `PADDOCK_SMTP_PORT` | default 587, or 465 with `implicit` |
| `PADDOCK_SMTP_TLS` | `starttls` (default; a relay that does not offer it is refused) or `implicit`; `none` only on a development stack |
| `PADDOCK_SMTP_USERNAME` | optional; with it the password comes from `PADDOCK_SMTP_PASSWORD_FILE` (`.secrets/smtp_password`) |
| `PADDOCK_SMTP_FROM` | required with a host: the sender address |
| `PADDOCK_SMTP_TIMEOUT` | default `30s` |
| `PADDOCK_SMTP_CA_FILE` | optional PEM file with the CA of a relay whose certificate is not publicly trusted; added to the system roots, verification stays on |
| `PADDOCK_SMTP_ENABLED` | on the api: `true` exactly when the host is set; `./paddock check` fails when they disagree |

TLS is mandatory: the certificate is always verified, and credentials are sent only over TLS (the notifier refuses to
start with a username and `PADDOCK_SMTP_TLS=none`). Authentication uses `PLAIN` when the relay advertises it, else `LOGIN`,
else `CRAM-MD5`.

A message is plain text (no HTML, no attachments) with the headers `From`, `To` (every recipient), `Subject`
(`[Paddock] <organization or "platform">: <n> security events`), `Date`, `Message-ID`, `Auto-Submitted: auto-generated`,
`X-Paddock-Delivery`, `X-Paddock-Destination` and `X-Paddock-Forward-Seq: <from>-<to>`. The body has one block per event:
time, code, outcome, the device or target, the actor, a portal link for device events and, with *Include event
parameters*, the parameters. A message shows at most 50 events in detail; the rest is a per-code count and the line
"and N more events; see the portal". After a delivery the destination waits *Minimum interval between e-mails* before the
next one, so a burst becomes one digest. E-mail destinations never send heartbeats.

## Delivery, retry and stalling

Every enabled destination is served in rounds every `PADDOCK_NOTIFY_POLL_INTERVAL` (default 30 s, minimum 5 s). The
notifier reads the audit events after the destination's cursor, keeps the ones the filter matches, sends up to
`PADDOCK_NOTIFY_BATCH` of them in one delivery, and moves the cursor only after the receiver accepted the delivery.
Deliveries of one destination are strictly sequential, destinations are independent: a stalled one never delays another.

- **Retry.** A failed delivery is retried with a growing pause (5 s, 10 s, 20 s, … up to 10 minutes). The same batch is
  retried until it succeeds; nothing is dropped.
- **Stalled.** When deliveries have failed for `PADDOCK_NOTIFY_STALL_AFTER` (default 15 minutes, minimum 1 minute), the
  destination becomes *Stalled* and Paddock records `notification.destination_stalled`; it keeps retrying. The first
  success records `notification.destination_resumed` and the destination catches up in order.
- **Audit.** Each successful events delivery records `notification.delivered` (destination, `forward_seq` range, count,
  attempts). Heartbeats and tests are not recorded as delivered; a test records `notification.test_requested` and
  `notification.test_sent`.
- **Heartbeat.** With a heartbeat interval, a webhook receives a `heartbeat` message whenever that long has passed
  without a delivery. A receiver that sees neither events nor heartbeats knows that Paddock or the path to it is down.
- **Round budget.** Each destination gets 60 seconds per round: no new delivery starts after 60 s. A requested test and a
  delivery started just before that bound can each take the 30 s webhook timeout, so the worst case is about 120 s per
  destination and round. Up to 16 destinations are served in parallel, and at most 20 deliveries per destination and
  round; the rest of a slow destination's backlog follows in the next round.

The portal list shows per destination the state (*Active*, *Stalled*, *Disabled*), *Last delivery* and *Lag*. The lag
there is the time since the first failure of the current series of failed deliveries (0 while deliveries succeed). The
metric `paddock_notify_lag_seconds` is different: the age of the oldest event the destination has not received yet
([monitoring.md](monitoring.md)).

## Privacy options

What a destination receives is audit events, which name administrators, devices and, for some codes, device users.

- *Replace user names with pseudonyms* (organization destinations) replaces a user name with `u_` and the first 24 hex
  characters of an HMAC-SHA256 over the lower-cased name, keyed per organization, in `actor.display` of administrators,
  `target.display` of users and administrator accounts and the parameters `username`, `user`, `display_name`,
  `requested_by`, `approved_by`, `created_by`, `members` and `users`. `actor.ip` and `actor.id` of administrators are
  removed. Host names, device names and the other parameters stay. The same name gives the same pseudonym for the
  whole organization, so a receiver can still correlate events of one person. Platform destinations do not offer it
  (platform events carry no end-user names).
- *Include event parameters* decides whether an e-mail lists the parameters (file names, units, counts).

An organization administrator turns a pseudonym back into a name with *Resolve pseudonym* on the notifications page
(select the destination, enter `u_` and 24 hex characters, confirm with the step-up). The notifier computes the
pseudonym of every user and administrator of the organization and answers within a poll interval; the result is shown
once. Every resolution is audited as `notification.pseudonym_resolved` and is part of the security preset. It answers
409 `invalid_state` while no destination pseudonymizes user names.

## Limits and known limitations

- **Events between a skip and the next round are skipped as well.** A new destination and a destination enabled with
  *Skip them* start at the newest event, and the notifier determines that position in its next round; events committed
  between your request and that round (at most one poll interval) are skipped for that destination too. It is an
  accepted trade-off of alpha.7.
- **A destination stalled longer than the audit index retention loses the purged events.** The notifier reads events
  from the audit index, which keeps them for `PADDOCK_AUDIT_INDEX_RETENTION_DAYS`. When a destination stays stalled
  longer, events of its pending batch that were already purged from the index are not sent, while the message still
  carries the batch's full `forward_seq` range (follow-up PDK-649). The WORM log still holds them. Fix a stalled
  destination well within that period.
- **No outbound proxy for webhooks** (follow-up PDK-625), see [Webhook URLs](#urls).
- **A CVE re-rated to critical later is not in the daily summary** (follow-up PDK-639).
- The retention of the delivery tables is not automated yet: [retention.md](../compliance/retention.md).

## Troubleshooting

`last_error` of a destination (portal: the stalled state, `GET …/notification-destinations/{id}` → `state.last_error`)
names only the class of the failure, never the URL or an address.

| `last_error` | Cause | What to check |
| --- | --- | --- |
| `dns` | the host name does not resolve from the control-plane host | the name, the host's resolver |
| `dial` | no connection (refused, unreachable, reset) | firewall and routing from the control plane to the receiver; the notifier does not use an HTTP proxy |
| `tls` | the TLS handshake or certificate failed | the receiver's certificate chain, name and expiry; the control-plane host must trust its CA |
| `timeout` | no answer within 30 s | the receiver's load; answer first, process later |
| `http_<status>` | the receiver answered something other than 2xx (for example `http_401`, `http_500`) | the receiver's log; a signature check failing with 401 usually means the secret was not updated after *Replace secret* |
| `redirect` | the receiver answered 3xx; redirects are never followed | the exact URL, including `https` and the final path |
| `denied_address` | the host resolves to a private or reserved address, or the stored URL is not `https` | use a public address; [Webhook URLs](#urls) |
| `smtp_dial` | no connection to the relay | host and port, firewall |
| `smtp_tls` | no TLS: the relay does not offer STARTTLS, the certificate does not verify, or credentials would travel without TLS | `PADDOCK_SMTP_TLS` and port, the relay's certificate, `PADDOCK_SMTP_CA_FILE` for a private CA |
| `smtp_auth` | authentication failed or the relay offers no mechanism Paddock supports | `PADDOCK_SMTP_USERNAME` and `.secrets/smtp_password`, the relay's logs |
| `smtp_timeout` | the relay did not answer within `PADDOCK_SMTP_TIMEOUT` | the relay |
| `smtp_<code>` | the relay answered with that 4xx or 5xx code (for example `smtp_550`: recipient or sender refused) | the relay's policy for `PADDOCK_SMTP_FROM` and the recipients |
| `internal` | something failed before anything was sent (a ciphertext that does not decrypt, a stored batch that cannot be read) | the notifier's log; OpenBao sealed or the AppRole of `paddock-notifier` |

A destination that shows no deliveries at all may be *Disabled*, filtered too narrowly, or waiting for its next round.
Metrics and the alert `PaddockNotificationStalled`: [monitoring.md](monitoring.md). The notifier's own log is
`./paddock logs paddock-notifier` on the control plane.
