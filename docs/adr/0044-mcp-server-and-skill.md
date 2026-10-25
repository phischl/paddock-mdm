# 0044 — MCP server for platform and organization administrators
Status: Proposed (architect, 2026-10-25; the two open questions in §"Open questions" have defaults and do not block
implementation)

## Context

The maintainer wants AI assistants (MCP clients such as Claude) to operate Paddock (PDK-433, decided 2026-10-25):
"MCP für Platform-Admins und Org-Admins. Es soll für die jeweilige Zielgruppe einstellbar sein was man alles darf.
Schreibender Zugriff muss darüber hinaus explizit im Benutzerkontext freigegeben werden. Ansonsten soll man alles
dürfen was die API hergibt." Four requirements follow: (1) both administrator populations are served; (2) each scope
— the platform, and every organization for itself — configures what the MCP may do; (3) write access additionally
needs an explicit, per-user opt-in that is off by default; (4) otherwise the MCP offers everything the admin API
offers, generated from the contract, not a hand-picked subset. A Claude skill ("operate Paddock") accompanies it.

Facts about the code that bound the design (checked 2026-10-25, `main` at `f71378b9`):

- The admin API is one OpenAPI 3.1 contract (`api/openapi/admin.yaml`, 153 operations, 34 collection lists). Every
  privileged operation carries `x-paddock-audit: <code>`; the server's `privileged` route table
  (`server/internal/transport/http/admin/server.go`) maps `METHOD /pattern` to its `app.ActionSpec`, and
  `TestOpenAPISpec` keeps contract and table equal. Requests rejected before a handler runs are still recorded once
  through that table (`server.rejected` → `ActionRunner.RecordRejected`).
- Two credentials exist: the portal session (cookie, server-side record in Valkey, step-up with WebAuthn) and the
  organization-scoped API token (`Authorization: Bearer pdk_…`, 43 random characters, SHA-256 at rest, one role at
  or below the creator's, step-up to create, at most 365 days, `paddockctl` is its client). **There are no platform
  tokens** (plan M6c decision, `docs/operations/api-tokens.md`): restore commands run on the host. A request
  authenticated with an API token never satisfies a step-up (ADR 0034 decision 3, `ActionRunner.checkStepUp`).
- Eighteen `ActionSpec`s always require a step-up (`RequiresStepUp: true`): API token creation, auto-unseal
  enable/disable, IP allow list changes, in-place encryption request/cancel, disk recovery key reveal, LUKS header
  download, operator roots, root-grant and sensitive-file confirmations, local administrator reveal, uninstall,
  Lock/Destroy requests and their approve/reject/cancel, end all sessions. Three use cases step up conditionally
  (`rootgrant.go`, `dms.go`, `managedconfig.go`: a profile that is root-equivalent in effect, the dead man's switch,
  a file on a sensitive path).
- The audit event (`paddock.audit.v1`) carries `source ∈ {portal, platform, system, device, api}` derived from the
  actor type (`audit.SourceForActor`); the RabbitMQ binding is `audit.#`, the index column `source text`, so a new
  source value needs no topology or audit-schema migration. Read access is not audited; plan M10 (PDK-139, not yet
  implemented) adds opt-in recording of sensitive views at the handler level.
- The portal's step-up pattern: an action refused with 403 `step_up_required` sends the browser through
  `/api/auth/stepup?return_to=…` and repeats the call once on return (`server/web/src/lib/stepUp.ts`).
- `paddockctl` (`cli/`, module without third-party dependencies apart from `oasdiff/yaml`) is a static binary with a
  plain HTTP client of the admin API (`cli/internal/client`); `make acceptance` builds and exercises it.
- Platform-scoped tables without `organization_id` live in the `paddock_platform` pool only and are listed in the RLS
  lint allow list (`server/internal/platform/db/rlslint_test.go`).
- MCP (Model Context Protocol) in the versions `2025-06-18` and `2025-11-25`: JSON-RPC 2.0; transports stdio
  (newline-delimited messages) and streamable HTTP; the server capability `tools` with `tools/list` and `tools/call`;
  tool names match `^[A-Za-z0-9_.-]{1,64}$`; a tool has `inputSchema` (JSON Schema), optional `outputSchema`,
  optional `annotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`); a result has
  `content` (text blocks) and optional `structuredContent`; `isError: true` marks a tool-level failure. Remote
  servers authenticate with OAuth 2.1 (protected-resource metadata, RFC 9728) — hosted clients need this, local
  clients (Claude Code, Claude Desktop) run stdio servers from a command line.

## Options

### A. Transport and hosting
- **A1 — stdio server in `paddockctl mcp`, authenticated with an API token, talking HTTPS to the existing admin
  API.** + No new network surface on the api: the IP allow list, the bearer path, RLS, `ActionRunner` and the body
  limits apply unchanged; the identity is the token's creator, exactly one user; works offline from any hosted
  service; a static binary like the rest of the CLI. − Hosted MCP clients (claude.ai in the browser) cannot use it;
  platform administrators have no token today (new credential needed); an API token is a long-lived secret on the
  administrator's machine.
- **A2 — remote streamable-HTTP endpoint `/mcp` on the api with OAuth 2.1 against Authentik.** + Hosted clients
  work; the identity is the OIDC login itself (MFA at sign-in, Authentik session revocation); short-lived access
  tokens. − A second authentication stack on the api (resource server, audience checks, protected-resource metadata,
  client registration in Authentik, CORS, SSE session state in Valkey, a new ingress route); the open-source
  Authentik has no dynamic client registration, so every MCP client is registered by hand; hosted clients would send
  every tool result through a third party's infrastructure, which is a privacy decision for operators
  (`docs/compliance/privacy.md`) before it is a technical one.
- **A3 — both in alpha.7.** − Doubles the surface and the review for one release.

### B. Credential for the MCP channel
- **B1 — any API token.** + Nothing new. − The server cannot tell MCP from CI; the MCP policy and the write opt-in
  would depend on a client-declared header, and the audit trail could not truthfully say "mcp".
- **B2 — a token *channel* chosen at creation (`api` or `mcp`), enforced on the server for every request made with
  that token, whatever the client claims.** + The policy, the opt-in and the audit source bind to the credential,
  not to a header; an `mcp` token used by curl is still restricted; the portal shows the purpose. − One more field
  on the token and in the portal form.
- **B3 — a short-lived, browser-issued CLI session (device-code or loopback login) instead of a token.** + No
  long-lived secret; MFA at every login. − New BFF endpoints, session issuance for non-browser clients, a new
  decision ADR 0034 explicitly deferred ("a short-lived, step-up-bound session token for `paddockctl` … needs its own
  decision"). Right design for later, too large for alpha.7.

### C. Platform administrators
- **C1 — no MCP for the platform scope in alpha.7.** − Contradicts the maintainer's first requirement.
- **C2 — platform MCP tokens: a platform-scoped token table, channel `mcp` only, created by a platform administrator
  with a step-up, at most 90 days.** + Reuses the token model; the restore commands stay host-only (no `api` channel
  for the platform, M6c decision kept); platform write actions that matter (releases publish/rollout are not
  step-up today, but end-all, auto-unseal and the IP allow list are) stay behind the step-up rule. − A long-lived
  platform credential exists for the first time; mitigated by the 90-day cap, the step-up at creation, the write
  opt-in and the policy.
- **C3 — platform `api` tokens too.** − Reverses M6c without a use case.

### D. Tool generation and classification
- **D1 — hand-written tools.** − Drift from the contract; contradicts requirement (4).
- **D2 — tools generated at build time from `api/openapi/admin.yaml` into a Go catalog shared by server and CLI,
  classified by HTTP method with contract overrides.** + One source of truth; `make gen` fails CI on drift; the
  server enforces the same classification it published. GET = read, everything else = write; the contract may say
  `x-paddock-mcp: {expose: false}` for operations the MCP must not offer and `x-paddock-step-up: true` for operations
  that always need a step-up (checked against the route table by the contract test). − A generator to maintain
  (about the size of `audit/gendoc`).
- **D3 — parse the contract at runtime in `paddockctl`.** − Adds an OpenAPI parser to the CLI; the server would
  still need its own view for enforcement.

### E. Three authorization layers (where each is enforced)
- The **role** (unchanged RBAC/RLS): the token's role, at or below the creator's, enforced by `ActionRunner` and
  `RequireOrg`/`RequirePlatform` as today. The MCP never exceeds what the user could do in the portal because it
  never gets another principal.
- The **scope policy**: a settings row per organization (`organization_mcp_settings`) and one for the platform
  (`platform_mcp_settings`): `enabled`, `write_enabled`, `mode ∈ {all, selected}`, `allowed_operations`. Without a
  row: enabled, writes allowed, mode `all` — the maintainer's "otherwise everything the API offers". Set by
  `org_admin` / `platform_admin` with a step-up, audited.
- The **write opt-in**: `mcp_write_enabled_at` on the administrator's own account (`admin_account`,
  `platform_admin`), switched on by that administrator in the portal with a confirmation and a step-up, switched off
  without one (the safe direction is never gated), audited. A token inherits its creator's current state at every
  request (the token lookup already joins the creator for `creator_inactive`).
- Enforcement point: one mux middleware (`mcpGuard`) after authentication and before the handler, keyed on the
  matched route pattern like `rejected`: it applies only to principals whose token channel is `mcp`, classifies
  the operation through the shared catalog and refuses with 403 before any use case runs. Refusals of privileged
  operations are recorded as `denied` through the `privileged` table (exactly one event per attempt); refused reads
  produce no event, as reads do nowhere else.

### F. Step-up operations through the MCP
- **F1 — refuse (keep ADR 0034 decision 3) and do not expose always-step-up operations as tools at all.** + The
  invariant holds by construction: an MCP token cannot Lock, Destroy, reveal, uninstall, end sessions or change the
  allow list, and a prompt injection cannot even attempt them (no `denied` event storm, no target surface);
  conditional step-up refusals (root-equivalent profile, sensitive path, dead man's switch) answer 403
  `step_up_required` with the portal path, and the tool result tells the model to hand over to the human. − The
  assistant cannot finish those actions; the human does them in the portal.
- **F2 — human in the loop: the MCP stages a *pending action*, the administrator confirms it in the portal with a
  step-up.** + The assistant can prepare a Destroy or a rollout halt. − A new persisted entity that replays an
  arbitrary request body under a later principal (confused-deputy shape), expiry and cleanup, a portal inbox, and a
  prompt-injection path that ends with a hurried human confirming what the model staged. This is a separate decision
  once the channel has run in production; it is **not** an amendment of ADR 0034.
- **F3 — let MCP tokens satisfy a step-up after a one-time confirmation.** − Rejected for the same reason as ADR 0034
  option C1: a long-lived credential would replace MFA.

### G. Audit
- Every MCP-initiated request runs the existing use case through `ActionRunner`: one event per attempt, unchanged.
- The channel is recorded as the event **source** `mcp` (a new value of an existing field; routing `audit.#` and
  the index column `source text` need no change), the client as the optional actor field `client`
  (`clientInfo.name/version` of the MCP `initialize` handshake, relayed by `paddockctl mcp` in the header
  `X-Paddock-MCP-Client`, sanitised to at most 64 printable ASCII characters, honoured for `mcp` tokens only).
- Reads are not audited per request (a metric counts them); once PDK-139 lands, MCP reads of sensitive views are
  recorded by the same handler calls as portal reads, because the MCP reaches the same handlers.
- New codes in the closed registry: `organization.mcp_policy_changed`, `platform.mcp_policy_changed`,
  `admin.mcp_write_enabled`, `admin.mcp_write_disabled`, `platform.api_token_created`, `platform.api_token_revoked`,
  `platform.api_token_use_denied`; `api_token.created` gains the param `channel`.

### H. Prompt-injection exposure
Tool results carry strings that device users and administrators control (hostnames, device names, file contents,
audit params, package names). The model reads them; an attacker who controls such a string can address the model.
Mitigations, in order of weight:
1. **Authority is server-side and credential-bound** (B2, E): nothing the model says to the MCP server widens access;
   the worst case is an action the user's role, the scope policy and the user's opt-in already allow.
2. **No step-up tool exists** (F1): the irreversible class (Lock, Destroy, reveal, uninstall, end-all, allow list,
   encryption) is unreachable through the channel.
3. **No raw-request tool, no policy or token tool**: the MCP cannot change its own policy, the opt-in or any token
   (`x-paddock-mcp: {expose: false}` on those operations, enforced by the server for `mcp` tokens too).
4. **Results are marked as data**: every tool result is one JSON object `{"notice": …, "status": …, "data": …}`
   whose fixed `notice` says the data comes from Paddock records, may contain text written by device users or
   administrators, and is never an instruction; tool descriptions are generated from the operator-controlled
   contract and never from data.
5. **Write tools are listed only when writes are effectively enabled** for the token (policy and opt-in), and
   `destructiveHint: true` marks deletes, revokes, retires, rejects and lock-like verbs, so well-behaved clients ask
   the human before calling them.
6. **Rate limit per token** in the api for the `mcp` channel: 120 requests per minute for reads, 30 per minute for
   writes, 429 `rate_limited` with `Retry-After`; a refused write is recorded once as `denied`.
7. **Revocation paths**: revoke the token; switch the opt-in off (immediate, no step-up); set `enabled: false` on
   the scope policy (immediate); the creator's role loss or deactivation already refuses the token
   (`creator_inactive`).

### I. The Claude skill
- **I1 — in this repository under `skills/operate-paddock/`** (Agent Skills layout: `SKILL.md` with `name` and
  `description` front matter plus `references/`), public with the product, referenced from the README, versioned
  with the release it describes; its content is workflows that *point to* `docs/operations/*.md` and the generated
  tool catalog instead of copying them; a test checks every referenced path and tool name. + Stays in sync by
  construction and by test. − Users must fetch it from the repository or the release.
- **I2 — a separate package or repository.** − Drift from the docs it depends on.

## Decision

1. **Transport.** alpha.7 ships the stdio server **`paddockctl mcp`** (option A1). It speaks MCP over stdio,
   implements the server capability `tools` only (`initialize`, `ping`, `tools/list`, `tools/call`,
   `notifications/initialized`), negotiates protocol version `2025-06-18` or `2025-11-25`, and calls the admin API
   with the API token of its configuration (`--token-file`, `PADDOCK_TOKEN_FILE`, config file) exactly like the other
   `paddockctl` commands. A remote streamable-HTTP endpoint (A2) is a later decision with its own ADR; this ADR
   records its preconditions in §"Consequences".
2. **Credential.** API tokens gain a **channel** fixed at creation: `api` (today's behaviour, default) or `mcp`.
   `paddockctl mcp` refuses to start with an `api` token (it checks `GET /api/v1/me` → `api_token.channel`) and names
   the portal page that creates an MCP token. The server applies the MCP policy, the write opt-in and the rate limit
   to **every** request made with an `mcp` token, whatever client sends it. MCP tokens expire after at most
   **90 days**; `api` tokens keep 365.
3. **Platform administrators** get **platform MCP tokens** (option C2): table `platform_api_token`, channel `mcp`
   only, role `platform_admin`, secret prefix `pdkp_`, created with a step-up on the portal page *Platform › MCP
   tokens*, at most 90 days, audited as `platform.api_token_created` / `platform.api_token_revoked` /
   `platform.api_token_use_denied`. The platform keeps no `api`-channel token; `docs/operations/api-tokens.md`
   changes "There are no platform tokens" to "The platform has MCP tokens only".
4. **Tools are generated** (option D2) by `server/cmd/mcpgen` from `api/openapi/admin.yaml` into
   `pkg/mcpcatalog/catalog.gen.go` (`make gen`; CI fails on a diff). Tool name = `operationId`, one to one.
   Classification: `read` for GET, `write` for every other method; `x-paddock-mcp: {expose: false}` removes an
   operation from the catalog; `x-paddock-step-up: true` marks operations that always need a step-up — they are in
   the catalog (the portal's policy page lists them as *portal only*) but **never exposed as tools**. The contract
   test checks: every `x-paddock-step-up: true` operation is in the `privileged` table with `RequiresStepUp: true`
   and vice versa; every exposed `write` tool is in the `privileged` table (so a refusal is audited); the BFF tag
   `auth`, uploads with non-JSON bodies, cursor feeds, the API-token and MCP-settings operations and `me/mcp-write`
   are not exposed. The input schema of a tool is `{path parameters, query parameters, body}` dereferenced from the
   contract, OpenAPI `nullable: true` rewritten to a `null` type union.
5. **Three layers**, enforced as described in option E: role (unchanged), scope policy (`organization_mcp_settings`,
   `platform_mcp_settings`; defaults enabled/all/writes allowed; `org_admin` or `platform_admin` with a step-up),
   per-user write opt-in (`mcp_write_enabled_at` on `admin_account` and `platform_admin`; enable needs a step-up,
   disable does not; both refused for API-token principals and for `org_auditor`). The guard `mcpGuard` refuses
   with 403 `mcp_disabled`, `mcp_tool_not_allowed` or `mcp_write_not_enabled` (the detail names the portal page) and
   with 429 `rate_limited`. `GET /api/v1/mcp/access` tells a client what the token may do right now;
   `GET /api/v1/mcp/catalog` publishes the catalog.
6. **Step-up operations are refused and not exposed** (option F1). ADR 0034 decision 3 stands unchanged. A
   conditional refusal reaches the model as an error result with `code: step_up_required`, the server's detail and a
   `portal_path`; the skill tells the assistant to hand the action to the human.
7. **Audit** as in option G: source `mcp`, actor `client`, the seven new codes, one event per attempt, no per-read
   events.
8. **Prompt-injection mitigations** as in option H, all seven; the residual risk is RR-85.
9. **Skill** as in option I1: `skills/operate-paddock/SKILL.md` with the sections install, upgrade, lab workflow,
   release and rollout, troubleshooting, "what the assistant must hand to the human" (the step-up list), and the
   tool catalog by tag; `test/skill_test.sh` verifies the referenced paths and tool names.
10. **Portal** (ADR 0018 applies): organization page *Settings › MCP* (`/settings/mcp`), platform pages *Platform ›
    MCP* (`/platform/mcp`) and *Platform › MCP tokens* (`/platform/mcp-tokens`, a `DataList`), the channel on the API
    tokens page and form, the user's opt-in in the account menu (`ConfirmDialog` + step-up), and the source/client
    on audit events. The policy page's tool selection is a **settings form** (grouped checkboxes with a filter
    field), not a collection list: the catalog is a fixed enumeration of the contract, not records; the endpoint
    answers `{version, tools}` and is documented as a catalog, not with `x-paddock-list`.

## Consequences

- + Both administrator populations can let an assistant read everything their role reads and, after two explicit
  switches (scope policy, own opt-in), change what their role may change — through the same use cases, RLS and
  audit as the portal; nothing irreversible is reachable; new endpoints become tools with `make gen`.
- + No new Go module, npm package or container image under the default of the open questions below.
- − Hosted MCP clients are not served in alpha.7. Preconditions for the remote endpoint (A2): a privacy decision on
  tool results leaving the operator's network, the OAuth resource-server design on the api, Valkey-backed MCP
  sessions, and the decision on CLI sessions ADR 0034 deferred (B3).
- − A long-lived platform credential exists for the first time (90 days, step-up to create, `mcp` channel only).
- − The MCP policy restricts the *credential*, not the person: an administrator with an `api` token can wire that
  token into any MCP client and bypass the MCP policy and the opt-in with their own role (RR-86).
- − Residual risks (RR-74 to RR-76 are M8b, RR-77 to RR-83 M13a, RR-84 ADR 0043):
  **RR-85** prompt injection through data (an attacker who controls a string the assistant reads can steer it within
  the user's effective MCP rights; mitigations H1–H7; record who may enable writes). **RR-86** channel bypass with an
  `api` token (above; the audit trail shows `source: api` for such calls; organizations that need hard separation
  grant `api` tokens sparingly). **RR-87** a long-lived MCP token on an administrator's workstation (90 days, revoke
  in the portal, `creator_inactive` on role loss; record the workstation baseline). **RR-88** step-up actions are
  only refused, never staged (the assistant can advise, the human acts; a future human-in-the-loop design is a
  separate decision). **RR-89** reads are not audited per call (a metric exists; PDK-139 adds sensitive-view
  recording; record whether your ISMS needs read logging before enabling MCP for auditors).
- Follow-ups: plan `docs/plans/M14-mcp.md`; architecture amendments (§3.2 api row, §9.6 credentials, §14.2 source,
  §17.1 endpoints, §22 test strategy); `docs/operations/mcp.md`; `docs/operations/api-tokens.md`;
  `docs/compliance/privacy.md` (what an assistant on the administrator's machine sees); `docs/compliance/residual-risks.md`
  (RR-85 … RR-89); ADR 0034 cross-reference ("MCP tokens are API tokens: decision 3 applies"); PDK-201 (role switch)
  must keep "one role per token".

## Open questions (with defaults)

1. **MCP SDK.** The official Go SDK `github.com/modelcontextprotocol/go-sdk` (MIT) would implement the protocol,
   including future transports. It is a new Go module and needs architect approval per `CLAUDE.md`. **Default: no
   dependency.** The subset in decision 1 is about 400 lines of stdlib code (JSON-RPC framing, five methods), tested
   against recorded message fixtures; the SDK is reconsidered with the remote endpoint.
2. **Default state of the scope policy.** This ADR follows the maintainer's wording ("otherwise everything the API
   offers"): enabled, writes allowed, mode `all` when no row exists. **Default: as decided.** The alternative
   (disabled until an administrator switches the scope on) is one line in `GetOrDefault` and one sentence in the
   docs if the maintainer prefers fail-closed.
