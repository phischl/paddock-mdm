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
its secret in a file with mode 0600. The loop below needs `curl` and `jq`, writes one JSON event per line and keeps its
cursor in `feed.cursor`:

```sh
#!/bin/sh
set -eu
base=https://admin.example.org   # the portal's address
token=$(cat /etc/paddock-feed/token)
cursor=$(cat /var/lib/paddock-feed/feed.cursor 2>/dev/null || echo 0)

while :; do
  page=$(curl -fsS -H "Authorization: Bearer $token" "$base/api/v1/audit-events/feed?after=$cursor&limit=1000")
  count=$(printf '%s' "$page" | jq '.events | length')
  [ "$count" -eq 0 ] && break
  printf '%s' "$page" | jq -c '.events[] | {commit_seq} + .event' >> /var/lib/paddock-feed/events.jsonl
  cursor=$(printf '%s' "$page" | jq '.next_after')
  printf '%s' "$cursor" > /var/lib/paddock-feed/feed.cursor
done
```

Run it every minute from `cron` or a systemd timer. The same read is `paddockctl audit feed --after N --limit L`, with
`--follow` to keep polling ([paddockctl.md](paddockctl.md)): one JSON event per line on stdout, the cursor as
`next_after=<n>` on stderr.

## SIEM pointers

- **Wazuh.** Run the loop (or `paddockctl audit feed`) as a `command` wodle or from a systemd timer on the manager and let
  a `localfile` of format `json` read `events.jsonl`. Wazuh decoders and rules for Paddock's events are not part of this
  release.
- **Splunk.** Use the loop as a scripted input (interval 60 s) that prints the new events to stdout, with
  `sourcetype=_json` and the event's `occurred_at` as the time field; or let a heavy forwarder monitor `events.jsonl`.
- **Anything else.** Any tool that can run a script and read JSON lines, or call an HTTP API with a bearer token, can
  poll the feed.

The token is a credential that reads the organization's whole audit log: store it like a password, give it a short
expiry, and revoke it in the portal when the collector is retired.

## Push instead of pull

A webhook destination with the filter *All events* pushes the same events as they are committed, signed, in batches
of up to 100 ([notifications.md](notifications.md)); it carries each event's `commit_seq`, so a push and a pull can be
reconciled. A later release (M12) adds forwarding to syslog on the same engine and a daily checkpoint message that a
receiver can compare with the WORM hash chain. The feed's format `paddock.audit.feed.v1` does not change with it.
