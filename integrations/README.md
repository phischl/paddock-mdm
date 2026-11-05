# SIEM content

Detection content for the audit events Paddock sends to a SIEM ([siem.md](../docs/operations/siem.md)). It reads the
two shapes an operator can feed: the RFC 5424 syslog push and the JSON lines of the pull loop.

| Path | What |
| --- | --- |
| `wazuh/decoders/0900-paddock_decoders.xml` | decoders for the syslog push (audit events, replayed `paddock.missing` events, heartbeat, test and checkpoint messages); the pull lines go through Wazuh's built-in `json` decoder |
| `wazuh/rules/0900-paddock_rules.xml` | rules `100900` to `100999`, groups `paddock`, `paddock_tamper`, `paddock_privilege`, `paddock_identity`, `paddock_platform`, `paddock_integrity` |
| `sigma/paddock_*.yml` | one Sigma rule per detection of the Wazuh rules (the two frequency rules have no Sigma twin); `logsource: product: paddock, service: audit` |

## Install (Wazuh)

Copy the files to the manager and restart it:

```sh
cp wazuh/decoders/0900-paddock_decoders.xml /var/ossec/etc/decoders/
cp wazuh/rules/0900-paddock_rules.xml /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/decoders/0900-paddock_decoders.xml /var/ossec/etc/rules/0900-paddock_rules.xml
systemctl restart wazuh-manager
```

Check a message with `/var/ossec/bin/wazuh-logtest` before relying on it.

## Levels

| Level | Events |
| --- | --- |
| 12 | `device.tamper_*`, `revocation.*`, `device.revocation_*`, `audit.chain_verification_failed` |
| 10 | revealed recovery keys, headers and local administrator passwords, confirmed root grants, device event gaps and clone suspicion, repeated failed sign-ins and repeated refused API tokens |
| 7 | any denied action, failed sign-ins, a refused API token, platform protections reduced, a replayed event the audit index no longer holds |
| 5 | sign-ins, identity, platform and configuration events |
| 3 | every other audit event |

## Keyed on the code, not on the MSGID

Nine codes are longer than the 32 characters RFC 5424 allows for `MSGID` and travel under a fixed alias
([audit-codes.md](../docs/compliance/audit-codes.md#syslog-msgid-aliases)). The decoders read the full `code` from the
message body, so a rule never sees the alias and a code added to Paddock later is decoded without a change here. The
Go tests under `server/internal/siemcontent` (run by `make test`) decode a frame of every registered code, require
every security-relevant code to fire a level 10 or 12 rule, and fail when a new code falls to the base rule without
being listed as informational.

Decoded fields: Wazuh's `JSON_Decoder` turns every key of the message body into a field under its dotted name, for
example `forward_seq`, `commit_seq`, `event.code`, `event.outcome`, `event.actor.type`, `event.actor.display`,
`event.target.display`, `event.recorded_at` and `event.params.<name>`; `organization` is the slug from the syslog
`PROCID` (the pull loop writes it into each line). The pull lines carry no `forward_seq`. The Sigma rules name the
fields of the audit event itself (`code`, `outcome`, `actor.type`, `params.*`); map them to `event.*` for a backend
that reads these lines.
