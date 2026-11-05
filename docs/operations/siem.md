# Feeding a SIEM: the audit cursor feed

A SIEM or an auditor's tool pulls an organization's audit events from the **cursor feed**, `GET /api/v1/audit-events/feed`
(ADR 0031, plan M9). It reads the audit index in the order the events were committed and hands out every event once to
a consumer that remembers its cursor. It is a pull: Paddock connects to nobody, the SIEM connects to Paddock. To be told
the moment something happens instead, use a [notification destination](notifications.md).

## What the feed gives you

| | |
| --- | --- |
| Request | `GET /api/v1/audit-events/feed?after=<n>&limit=<k>` |
| `after` | integer, 0 or more, default 0: the `commit_seq` of the last event you already stored; 0 starts at the beginning |
| `limit` | integer 1 to 1000, default 100 |
| Access | an organization session or an [API token](api-tokens.md) with the role `org_auditor` (or `org_admin`); a token only ever sees its own organization |
| Errors | 400 `invalid_request` (`after` below 0 or `limit` outside 1 to 1000), 401, 403 |

```json
{
  "schema": "paddock.audit.feed.v1",
  "events": [
    { "commit_seq": 1290, "event": { "event_id": "0199…", "organization_id": "0199…", "occurred_at": "…",
        "recorded_at": "…", "code": "device.tamper_sudoers_d_file", "outcome": "success", "source": "device",
        "actor": { "type": "device", "id": "0199…" }, "target": { "type": "device", "id": "0199…", "display": "lt-01" },
        "params": { "file": "…" }, "correlation_id": "0199…" } }
  ],
  "next_after": 1290,
  "latest": 1305
}
```

- `events` are in ascending `commit_seq`. The event is the stored audit event, the same fields as `GET /api/v1/audit-events`
  without the portal's device enrichment. Codes are stable English identifiers ([audit-codes.md](../compliance/audit-codes.md)).
- `next_after` is the `commit_seq` of the last event in the page (your `after` when the page is empty). Pass it as the
  next `after`.
- `latest` is the highest `commit_seq` of the organization; the consumer is caught up when `next_after` equals `latest`.
- `commit_seq` is a per-organization counter that the audit writer assigns in commit order under a lock, so an event
  never appears behind a cursor that has already passed it.
- The feed is not shown in the portal and not offered to the MCP.

## Read every event exactly once

Persist `next_after` **after** you have stored the page's events durably, then ask for the next page with it:

1. Start with `after=0` (or the cursor you saved).
2. Fetch a page, store its events (keyed by `event_id`), then save `next_after`.
3. Repeat until the page is empty (`next_after == latest`); poll again after a pause (30 to 60 seconds is plenty).

Every event is delivered once to a consumer that follows this order. If your process dies between storing and saving
the cursor, the next run reads that page again: key your store by `event_id` and a repeat is harmless (at-least-once on
a crash, exactly once otherwise).

**Catch-up is bounded by the audit index retention.** The feed reads the audit index, which keeps events for
`PADDOCK_AUDIT_INDEX_RETENTION_DAYS` (at least 400 days). A cursor older than the oldest retained event is answered
with the oldest retained events, not with an error; events that were purged from the index before you read them are
not in the feed any more. They are still in the WORM log and in an [evidence export](audit-bucket.md); a SIEM that
stays offline for more than the retention period must be seeded from an export.

## A pull loop with `curl`

Create an API token with the role `org_auditor` (*Organization* → *API tokens*, [api-tokens.md](api-tokens.md)) and keep
its secret in a file with mode 0600. The loop below needs `curl` and `jq`, writes one JSON line per event
(`{"organization", "commit_seq", "event"}`, the element of the page plus the organization's slug) and keeps its cursor
in `feed.cursor`:

```sh
#!/bin/sh
set -eu
base=https://admin.example.org   # the portal's address
org=acme                         # the organization's slug, as in the syslog PROCID
token=$(cat /etc/paddock-feed/token)
cursor=$(cat /var/lib/paddock-feed/feed.cursor 2>/dev/null || echo 0)

while :; do
  page=$(curl -fsS -H "Authorization: Bearer $token" "$base/api/v1/audit-events/feed?after=$cursor&limit=1000")
  count=$(printf '%s' "$page" | jq '.events | length')
  [ "$count" -eq 0 ] && break
  printf '%s' "$page" | jq -c --arg org "$org" '.events[] | {organization: $org, commit_seq, event}' >> /var/lib/paddock-feed/events.jsonl
  cursor=$(printf '%s' "$page" | jq '.next_after')
  printf '%s' "$cursor" > /var/lib/paddock-feed/feed.cursor
done
```

Run it every minute from `cron` or a systemd timer. The same read is `paddockctl audit feed --after N --limit L`, with
`--follow` to keep polling ([paddockctl.md](paddockctl.md)): one `{"commit_seq", "event"}` line per event on stdout
(without `organization`), the cursor as `next_after=<n>` on stderr.

## SIEM pointers

- **Wazuh.** Decoders and rules ship in `integrations/wazuh/` ([Wazuh](#wazuh)): receive the syslog push, or run the
  loop (or `paddockctl audit feed`) as a `command` wodle or from a systemd timer on the manager and let a `localfile`
  of format `syslog` read `events.jsonl`.
- **Splunk.** Receive the syslog push with a TCP+TLS input in front of Splunk (rsyslog as in
  [Push over syslog](#push-over-syslog)), or use the loop as a scripted input (interval 60 s) that prints the new events to stdout, with
  `sourcetype=_json` and the event's `occurred_at` as the time field; or let a heavy forwarder monitor `events.jsonl`.
- **Anything else.** Any tool that can run a script and read JSON lines, or call an HTTP API with a bearer token, can
  poll the feed.

The token is a credential that reads the organization's whole audit log: store it like a password, give it a short
expiry, and revoke it in the portal when the collector is retired.

## Push instead of pull

A webhook destination with the filter *All events* pushes the same events as they are committed, signed, in batches
of up to 100 ([notifications.md](notifications.md)); it carries each event's `commit_seq`, so a push and a pull can be
reconciled. A syslog destination pushes the same events over TLS as RFC 5424 messages
([notifications.md](notifications.md#syslog)); its `MSGID` is the audit code, or a fixed alias for the few codes
longer than 32 characters ([Syslog MSGID aliases](../compliance/audit-codes.md#syslog-msgid-aliases)), and
`event.code` in the message body is always the full code. Syslog confirms delivery at TCP level only: a receiver that
acknowledges a batch and then drops part of it unread is not detected by Paddock (RR-113), so check `forward_seq` for
gaps on the receiver and reconcile with the checkpoint message (sent from a later alpha.9 change), which a receiver can compare with the WORM hash
chain. The feed's format `paddock.audit.feed.v1` does not change with it.

## Push over syslog

A syslog destination ([notifications.md](notifications.md#syslog)) opens one TLS connection per delivery, writes
RFC 5424 messages with octet-counting framing and closes. The receiver must accept TLS 1.2 or newer and
octet-counting framing; there is no client certificate.

### rsyslog

`imtcp` with the `gtls` driver detects the octet count itself. The receiver certificate must be valid for the name or
the *TLS server name* entered in the destination, and chain to the CA entered as *CA certificate* (or a public CA).

rsyslog truncates messages above its default `maxMessageSize` of 8 KiB, and a truncated body is invalid JSON that no
rule can classify. Device reports can carry events of 25 KiB and more, so the first statement raises the limit to 64 KiB:

```text
global(maxMessageSize="64k")
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1" StreamDriver.Authmode="anon")
global(
  DefaultNetstreamDriver="gtls"
  DefaultNetstreamDriverCAFile="/etc/rsyslog.d/tls/ca.pem"
  DefaultNetstreamDriverCertFile="/etc/rsyslog.d/tls/server.pem"
  DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/tls/server.key"
)
input(type="imtcp" port="6514" ruleset="paddock")

template(name="paddockRaw" type="string" string="%rawmsg%\n")

ruleset(name="paddock") {
  if $app-name == "paddock" then {
    action(type="omfile" file="/var/log/paddock/audit.log" template="paddockRaw")
    stop
  }
}
```

`Authmode="anon"` means the server presents its certificate and does not ask the client for one, which is what
Paddock sends. Each message is one line in `audit.log`: the JSON body never contains a raw line break.

### Wazuh

The Wazuh `<remote>` syslog listener accepts plain TCP only: it does not terminate TLS and does not understand
octet counting. The push therefore reaches Wazuh through a relay: rsyslog on the manager host terminates TLS, removes the
octet count and hands each message on over the loopback as one line. The decoders accept the message with or without
the octet count and the `<PRI>`.

Replace the three certificate paths (`/etc/rsyslog.d/tls/...`) with your own files before you load the configuration:
`server.pem` is the receiver certificate (with the chain), valid for the name or *TLS server name* of the destination;
`ca.pem` is the CA entered as *CA certificate* in the destination (use your own CA's file; it is only read for
optional client verification, which Paddock does not do). Save the file as `/etc/rsyslog.d/30-paddock-wazuh.conf`:

```text
# rsyslog's default of 8 KiB would truncate large events (device reports) into invalid JSON that no rule classifies;
# 64 KiB is also the largest message the Wazuh syslog listener reads.
global(maxMessageSize="64k")

module(load="imtcp"
  StreamDriver.Name="gtls"
  StreamDriver.Mode="1"
  StreamDriver.Authmode="anon")

global(
  DefaultNetstreamDriver="gtls"
  DefaultNetstreamDriverCAFile="/etc/rsyslog.d/tls/ca.pem"
  DefaultNetstreamDriverCertFile="/etc/rsyslog.d/tls/server.pem"
  DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/tls/server.key"
)

# Octet-counted framing (RFC 6587) is what Paddock sends; imtcp accepts it by default, the switch is explicit here.
input(type="imtcp" port="6514" ruleset="paddock" supportOctetCountedFraming="on")

# The message as received, without the octet count, one line per message.
template(name="paddockRaw" type="string" string="%rawmsg%\n")

ruleset(name="paddock") {
  if $app-name == "paddock" then {
    action(type="omfwd" target="127.0.0.1" port="514" protocol="tcp"
           template="paddockRaw" TCP_Framing="traditional"
           queue.type="LinkedList" queue.filename="paddock_wazuh" queue.saveOnShutdown="on"
           action.resumeRetryCount="-1")
    stop
  }
}
```

The disk-assisted queue (`queue.filename`) needs rsyslog's `workDirectory`, which the Debian, Ubuntu and RHEL packages
set; without it rsyslog falls back to a memory-only queue and loses undelivered messages on a restart.

The matching listener in `/var/ossec/etc/ossec.conf` on the manager (restart the manager after the change):

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>127.0.0.1</allowed-ips>
  <local_ip>127.0.0.1</local_ip>
</remote>
```

Check the relay before you create the destination:

```bash
rsyslogd -N1 -f /etc/rsyslog.conf          # the configuration parses
systemctl restart rsyslog wazuh-manager
ss -ltn '( sport = :6514 or sport = :514 )'   # 6514 on all addresses, 514 on 127.0.0.1 only
```

Then use *Send test message* on the destination in the portal and watch it arrive:

```bash
tail -f /var/ossec/logs/archives/archives.json | grep paddock.test
```

(`<logall_json>yes</logall_json>` is required for that file); the arrived entry must show `decoder.name`
`paddock-ctl`, and a test that does not arrive is a failed relay, not a failed decoder. The `full_log` of that entry is
what `remoted` handed to the analysis engine; use it for the `wazuh-logtest` checks below.

Alternatively let a `localfile` of format `syslog` read `/var/log/paddock/audit.log` (the file written by the rsyslog
example above) and skip the second hop.

### Deduplication

Delivery is at least once ([notifications.md](notifications.md#syslog)): after a retry or a replay the receiver sees
an event twice with the same `event.event_id` and the same `forward_seq`. Deduplicate on `event_id`. `forward_seq` is
contiguous per destination: a gap on the receiver means a message was lost after the connection was acknowledged
(RR-113), so alert on a gap and reconcile it with the checkpoint ([below](#reconcile-a-checkpoint)) and fill it ([Replay](#replay)).

The SIEM copy is not evidence ([residual-risks.md](../compliance/residual-risks.md), RR-111): only the WORM chain
and an [evidence export](audit-bucket.md) are.

## Wazuh

The content is in `integrations/` of the repository ([README](../../integrations/README.md)):

| File | Install path on the manager |
| --- | --- |
| `integrations/wazuh/decoders/0900-paddock_decoders.xml` | `/var/ossec/etc/decoders/` |
| `integrations/wazuh/rules/0900-paddock_rules.xml` | `/var/ossec/etc/rules/` |

The decoders hand the JSON body to Wazuh's `JSON_Decoder`, so every key is a field under its dotted name:
`event.code`, `event.outcome`, `event.actor.type`, `event.actor.display`, `event.target.display`,
`event.params.<name>`, `forward_seq`, `commit_seq`, and `organization` (the slug from `PROCID`). A line of the pull
loop is taken by Wazuh's built-in `json` decoder and yields the same names, so a pushed and a pulled event fire the
same rule (100900 is the base of the push, 100901 of the pull). Levels: tamper and revocation 12, reveals and root
grants 10, denied 7, sign-in and configuration 5. The rules key on the full `event.code` of the message body, never on
the `MSGID`, so the nine aliased codes behave like all others. A replayed event that the audit index no longer holds
(`MSGID` `paddock.missing`) fires rule 100904 at level 7. Sigma twins of the detections for other engines are in
`integrations/sigma/`.

Restart `wazuh-manager`, then check with `/var/ossec/bin/wazuh-logtest`, one line each, that:

- a pushed `device.tamper_sudoers_d_file` frame (the `full_log` of an archived event, or one line of `audit.log` with the
  plain receiver; `remoted` may have stripped the `<PRI>`, which leaves `1 TIMESTAMP ...`) fires rule 100910 at level 12 and shows
  `organization`, `event.code` and `event.params.*`;
- a frame with an aliased `MSGID` ([Syslog MSGID aliases](../compliance/audit-codes.md#syslog-msgid-aliases)), for example `device.tamper_file_changed` for `device.tamper_protected_file_changed`, fires the rule of its full
  `event.code` (100910 at level 12);
- a line of `events.jsonl` from the pull loop is decoded as `json` and fires the same rule as its pushed twin;
- a `paddock.checkpoint` message fires rule 100903;
- the line of `server/internal/siemcontent/testdata/syslog_missing.golden` (without the octet count) fires rule 100904.

### Reconcile a checkpoint

A checkpoint message (`kind` `checkpoint`, sent after each sealed day) carries `day` and `event_count`. Wazuh cannot
count a day in a rule, so compare in the indexer. This counts the distinct events stored for the organization and the
day (`event_id` removes the duplicates of at-least-once delivery). It counts by `recorded_at`, the time the audit
writer stored the event, because the checkpoint's `event_count` does: a device event spooled offline is counted on the
day it arrived, not on the day it happened. It needs the events in the alerts index (rules 100900 and 100901 alert at
level 3, so every audit event is there) or in the archives index; `wazuh-archives-*` exists only when the manager
writes `<logall_json>yes</logall_json>` **and** Filebeat's archives input is enabled
(`archives: enabled: true` in `/etc/filebeat/filebeat.yml`):

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": { "bool": { "filter": [
    { "term":   { "data.event.organization_id": "<organization id>" } },
    { "prefix": { "data.event.recorded_at": "<day>" } }
  ] } },
  "aggs": { "events": { "cardinality": { "field": "data.event.event_id", "precision_threshold": 40000 } } }
}
```

`events.value` equal to the checkpoint's `event_count` means the SIEM holds every event of the day. A smaller number
means events are missing: find the gap by `forward_seq` and fill it ([Replay](#replay)). The checkpoint's `day` is a
UTC day and `recorded_at` is always sent in UTC, so the prefix `<day>` selects exactly that day.

## Replay

Replaying a destination from a `forward_seq` is added to Paddock in a later alpha.9 change; until
it ships, [notifications.md](notifications.md) says a destination never replays history, and a SIEM that lost events
is filled from the pull feed above (the feed keeps `commit_seq`, so a replayed push and a pull can be reconciled) or
from an [evidence export](audit-bucket.md). Once the replay exists it resends the stored batches under the original
`forward_seq` and `delivery_id`, so deduplication by `event_id` makes it harmless; an event purged from the audit index
arrives as `{forward_seq, event_id, missing: true}`.
