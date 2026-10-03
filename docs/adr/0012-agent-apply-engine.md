# 0012 — Agent apply engine
Status: Proposed

## Context
F1 requires reconciling drift; the agent is a static binary; the concept's layout mentions Ansible roles.
Decided by the product owner: native Go reconcilers, Ansible optional.

## Options
- **Native Go reconcilers only.** + Static, testable, idempotent. − Limited extensibility.
- **ansible-pull.** + Flexible. − Python dependency on every device; contradicts design contract 9.
- **Go reconcilers for the core + optional `playbook` resource.** + Core stays static and safe; organizations can extend.
  − Playbooks run as root and could touch protected areas.

## Decision
Fixed reconciler set (`file`, `sudo`, `login`, `local_admin`, `apt_hold`, `updates`, `systemd_unit`, `luks`, `time`)
with `Plan()`/`Apply()`. Optional `playbook` resource (off by default) runs signed archives with locally installed
`ansible-core`, always last, followed by re-verification of protected areas.

## Consequences
+ Idempotency gate testable per reconciler. − Operators who need Ansible install `ansible-core` themselves.
The product repository contains no `ansible/roles/`.
