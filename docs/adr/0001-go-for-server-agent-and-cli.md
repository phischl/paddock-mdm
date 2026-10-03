# 0001 — Go for server, agent and CLI
Status: Proposed

## Context
The agent MUST be a static binary without runtime dependencies (design contract 9), which effectively
means Go. The server still needed a language. The bundle format, request signatures, canonical JSON and
command envelopes are security-critical code that both sides must implement identically.

## Options
- **Go everywhere.** + One implementation of protocol, bundle and crypto code (`pkg/`), shared types, one
  toolchain, one review discipline; strong stdlib crypto; small stateless containers; Fleet is Go as well.
  − Less expressive domain modelling than JVM/PHP frameworks; no batteries-included admin framework.
- **PHP / Symfony server.** + Team expertise, Doctrine filters, Messenger. − Protocol and crypto code twice
  (PHP + Go), long-running worker processes need extra care, two dependency ecosystems to audit.
- **TypeScript / Node server.** + Same language as the portal. − Protocol code twice; weaker crypto story.
- **Kotlin / JVM server.** + Robust typing. − Heavier runtime, protocol code twice.

## Decision
Go (current stable, minimum 1.25) for `paddock-server`, `paddockd`, `paddock-supervisor`, `paddock-revoke`
and `paddockctl`, in one `go.work` workspace with a shared `pkg` module. Libraries: stdlib `net/http`
routing, `pgx/v5` + `sqlc`, `goose`, `amqp091-go` (RabbitMQ), `valkey-go`, `oapi-codegen`, `log/slog`, OpenTelemetry Go SDK.

## Consequences
+ Protocol drift between server and agent is impossible by construction.
− Portal is a separate TypeScript codebase (ADR 0015); its API client is generated from OpenAPI.
Follow-up: lint and security tooling (`golangci-lint`, `govulncheck`, `gosec`) in CI from M0.
