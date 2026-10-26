# 0044 — MCP server for platform and organization administrators
Status: Accepted (architect, 2026-10-25; maintainer decisions of 2026-10-25 recorded in §"Maintainer decisions
2026-10-25" and §"Amendment 2026-10-25 — MCP login via Authentik", which replaces decisions 2 and 3 below)

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
  row the MCP is **off** for that scope (fail-closed; maintainer decision 2026-10-25): an administrator must save a
  policy with `enabled: true` first. Once enabled, the maintainer's "otherwise everything the API offers" is the
  form's starting point (`write_enabled: true`, mode `all`). Set by `org_admin` / `platform_admin` with a step-up,
  audited.
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
  invariant holds by construction: an MCP session cannot Lock, Destroy, reveal, uninstall, end sessions or change the
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

1. **Transport.** alpha.7 ships the stdio server **`paddockctl mcp`** (option A1). It is built on the official Go
   SDK **`github.com/modelcontextprotocol/go-sdk` v1.8.0** (approved by the maintainer on 2026-10-25, see
   §"Maintainer decisions 2026-10-25"): the SDK's stdio transport, protocol negotiation and `tools` capability
   (`tools/list`, `tools/call`) with Paddock's generated catalog registered as tools; Paddock implements no other
   capability (no resources, prompts, sampling, elicitation). It calls the admin API with the API token of its
   configuration (`--token-file`, `PADDOCK_TOKEN_FILE`, config file) exactly like the other `paddockctl` commands. A
   remote streamable-HTTP endpoint (A2) is a later decision with its own ADR; this ADR records its preconditions in
   §"Consequences".
2. **Credential** — *replaced on 2026-10-25 by the amendment below (MCP login via Authentik).* The original
   decision (API tokens with a `channel` of `api` or `mcp`, MCP tokens ≤ 90 days) is withdrawn: the MCP has no
   tokens; the human signs in through Authentik with `paddockctl mcp login`, and the api keeps a revocable MCP
   session (ADR 0034 decision 4) bound to the channel `mcp`.
3. **Platform administrators** — *replaced on 2026-10-25 by the amendment below.* The original decision (platform
   MCP tokens `pdkp_`, table `platform_api_token`) is withdrawn: a platform administrator signs in like everyone
   else; `ResolveRole` yields the platform role from `paddock.platform.admins`. "There are no platform tokens"
   (plan M6c) stays true.
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
   `platform_mcp_settings`; **off until an administrator saves a policy with `enabled: true`**, for the organization
   and the platform scope alike; `org_admin` or `platform_admin` with a step-up),
   per-user write opt-in (`mcp_write_enabled_at` on `admin_account` and `platform_admin`; enable needs a step-up,
   disable does not; both refused for API-token principals, MCP sessions and `org_auditor`). The guard `mcpGuard`
   applies to principals whose session carries the channel `mcp` and refuses with 403 `mcp_disabled`,
   `mcp_tool_not_allowed` or `mcp_write_not_enabled` (the detail names the portal page) and with 429 `rate_limited`
   (per account). `GET /api/v1/mcp/access` tells a client what the session may do right now;
   `GET /api/v1/mcp/catalog` publishes the catalog.
6. **Step-up operations are refused and not exposed** (option F1). ADR 0034 decision 3 stands and is extended: an
   MCP session never satisfies a step-up, however fresh the Authentik login behind it was (`checkStepUp` refuses
   `Channel == mcp` like it refuses API tokens). A conditional refusal reaches the model as an error result with
   `code: step_up_required`, the server's detail and a `portal_path`; the skill tells the assistant to hand the
   action to the human.
7. **Audit** as in option G: source `mcp`, actor `client`, the seven new codes, one event per attempt, no per-read
   events.
8. **Prompt-injection mitigations** as in option H, all seven; the residual risk is RR-85.
9. **Skill** as in option I1: `skills/operate-paddock/SKILL.md` with the sections install, upgrade, lab workflow,
   release and rollout, troubleshooting, "what the assistant must hand to the human" (the step-up list), and the
   tool catalog by tag; `test/skill_test.sh` verifies the referenced paths and tool names.
10. **Portal** (ADR 0018 applies): organization page *Settings › MCP* (`/settings/mcp`), platform page *Platform ›
    MCP* (`/platform/mcp`), the user's opt-in in the account menu (`ConfirmDialog` + step-up), and the source/client
    on audit events. *(Amended 2026-10-25: no token pages — the MCP has no tokens; the API tokens page is
    unchanged.)* The policy page's tool selection is a **settings form** (grouped checkboxes with a filter
    field), not a collection list: the catalog is a fixed enumeration of the contract, not records; the endpoint
    answers `{version, tools}` and is documented as a catalog, not with `x-paddock-list`.

## Consequences

- + Both administrator populations can let an assistant read everything their role reads and, after two explicit
  switches (scope policy, own opt-in), change what their role may change — through the same use cases, RLS and
  audit as the portal; nothing irreversible is reachable; new endpoints become tools with `make gen`.
- − One new Go module in `cli/`: `github.com/modelcontextprotocol/go-sdk` v1.8.0 with its dependency tree
  (§"Maintainer decisions 2026-10-25"); no npm package or container image. `paddockctl` stays a static binary.
- + Every scope starts with the MCP off; an organization or the platform that never saves a policy is never
  reachable through the channel, whatever tokens exist.
- − Hosted MCP clients are not served in alpha.7. Preconditions for the remote endpoint (A2): a privacy decision on
  tool results leaving the operator's network, the OAuth resource-server design on the api, Valkey-backed MCP
  sessions, and the decision on CLI sessions ADR 0034 deferred (B3).
- − The MCP policy restricts the *channel*, not the person: an administrator with an `api` token can wire that
  token into any MCP client and bypass the MCP policy and the opt-in with their own role (RR-86).
- − Residual risks (RR-74 to RR-76 are M8b, RR-77 to RR-83 M13a, RR-84 ADR 0043):
  **RR-85** prompt injection through data (an attacker who controls a string the assistant reads can steer it within
  the user's effective MCP rights; mitigations H1–H7; record who may enable writes). **RR-86** channel bypass with an
  `api` token (above; the audit trail shows `source: api` for such calls; organizations that need hard separation
  grant `api` tokens sparingly). **RR-87** an Authentik refresh token (8 hours, rotated) and a 30-minute access
  token in a 0600 file on the administrator's workstation (`paddockctl mcp logout` revokes; deactivation, role
  change and end-all end the session; record the workstation baseline; an OS keyring is an open question for the
  maintainer because it needs a dependency). **RR-88** step-up actions are only refused, never staged (the
  assistant can advise, the human acts; a future human-in-the-loop design is a separate decision). **RR-89** reads
  are not audited per call (a metric exists; PDK-139 adds sensitive-view recording; record whether your ISMS needs
  read logging before enabling MCP for auditors).
- Follow-ups: plan `docs/plans/M14-mcp.md`; architecture amendments (§3.2 api row, §9.6 credentials, §14.2 source,
  §17.1 endpoints, §22 test strategy); `docs/operations/mcp.md`; `docs/operations/api-tokens.md`;
  `docs/compliance/privacy.md` (what an assistant on the administrator's machine sees); `docs/compliance/residual-risks.md`
  (RR-85 … RR-89); ADR 0034 cross-reference (MCP sessions are decision-4 sessions; decision 3 applies to them);
  ADR 0007 amendment (third public provider `paddock-mcp`); PDK-201 (role switch) must keep "one role per session".

## Maintainer decisions 2026-10-25

The architect's proposal of 2026-10-25 left three points open with defaults; the maintainer decided them the same
day:

1. **Step-up operations are hidden** (decision 6, option F1) — confirmed as proposed. No pending-action flow in
   alpha.7.
2. **MCP SDK approved.** The maintainer approved the new Go dependency `github.com/modelcontextprotocol/go-sdk`
   for the `cli/` module on 2026-10-25, replacing the hand-written JSON-RPC alternative. Facts checked on
   2026-10-25:
   - Pinned version **v1.8.0**, published 2026-09-04 (seven weeks before the decision; the rule "at least two weeks
     old" holds); requires Go 1.25.0 (the workspace is on Go 1.27).
   - Licence file of v1.8.0: new code and specification contributions under **Apache-2.0**, older contributions
     under **MIT**, documentation under CC-BY-4.0 (documentation is not compiled into `paddockctl`). Copyright
     "Model Context Protocol a Series of LF Projects, LLC". No copyleft.
   - Direct dependencies and their licences: `github.com/golang-jwt/jwt/v5` v5.3.1 (MIT), `github.com/google/go-cmp`
     v0.7.0 (BSD-3-Clause), `github.com/google/jsonschema-go` v0.4.3 (MIT), `github.com/segmentio/encoding` v0.5.4
     (MIT), `github.com/yosida95/uritemplate/v3` v3.0.2 (BSD-3-Clause), `golang.org/x/oauth2` v0.35.0,
     `golang.org/x/time` v0.15.0, `golang.org/x/tools` v0.42.0 (all BSD-3-Clause); indirect:
     `github.com/segmentio/asm` v1.1.3 (MIT), `golang.org/x/sync` v0.20.0, `golang.org/x/sys` v0.41.0 (BSD-3-Clause).
     All are in the licence allow list of `make lint-licenses` (`ALLOWED_LICENSES` in the `Makefile`). The combined
     licence file of the SDK itself is the one thing the gate must confirm at implementation time: if `go-licenses`
     cannot classify it (reports `unknown` or `CC-BY-4.0`), PDK-439 stops and reports instead of adding an
     exception (plan M14 stop condition S10).
   - What the SDK brings that the hand-written variant lacked: protocol-version negotiation maintained upstream,
     argument validation against the tool's `inputSchema` (`jsonschema-go`), the streamable-HTTP transport for the
     later remote endpoint (M14b) without a second implementation.
   - Consequences: the SDK's `golang.org/x/oauth2` and `jwt` packages are linked but unused in alpha.7; `govulncheck`
     (`make lint-vuln`) covers them like every other dependency; `docs/compliance/third-party.md` lists the module.
3. **Scope policy off by default** (fail-closed) for the organization and the platform scope: without a saved row
   `MCPAccessService.Policy` answers `{enabled: false, write_enabled: false, mode: all}`; the portal says so; an
   administrator enables the MCP by saving a policy with a step-up. This replaces the architect's proposed default
   ("enabled, writes allowed, all tools" when no row exists), which had followed the maintainer's wording
   literally; the wording now describes the policy an administrator may choose, not the state before any choice.

RR-86 and RR-87 are narrowed by decision 3 (a scope that never enabled the MCP is unreachable through the channel).

## Amendment 2026-10-25 — MCP login via Authentik (maintainer decision; replaces decisions 2 and 3)

**Decision of the maintainer (2026-10-25):** "MCP login via Authentik" — the MCP authenticates the human through
Authentik (OIDC/OAuth), not with long-lived MCP API tokens. The maintainer wants the central identity for the MCP
as for the portal.

### Options weighed

- **A — remote MCP endpoint (streamable HTTP) on the api with the MCP authorization specification.** OAuth 2.1
  with Authentik as authorization server, PKCE, a dedicated provider/application for MCP clients, audience-bound
  access tokens, protected-resource metadata (RFC 9728). + Hosted clients (claude.ai) work; the SDK's `auth`
  package provides the resource-server middleware. − Open-source Authentik has no dynamic client registration, so
  every MCP client is registered by hand by the platform administrator; the api gains an OAuth resource server, a
  new ingress route and HTTP MCP sessions in Valkey; tool results would travel through the hosted client's
  infrastructure — a privacy decision operators must take first (`docs/compliance/privacy.md`); the step-up
  question reappears in a browser-less client. Larger than alpha.7 allows; **M14b**.
- **B — `paddockctl mcp` (stdio) signs the human in against Authentik itself and calls the admin API with the
  resulting token.** Two sub-variants: the **device authorization grant** (RFC 8628) and **loopback PKCE** (RFC 8252).
  + The identity is the OIDC login (password and second factor through the same `paddock-admin-login` flow as the
  portal); short-lived access tokens with refresh; no new network surface on the api beyond three BFF routes; the
  existing session store, role resolution and revocation rules apply; no secret in the CLI (public client). − The
  CLI keeps a refresh token on disk (0600 file; an OS keyring needs a dependency → open question). **Chosen for
  alpha.7, with the device grant**: Paddock already runs Authentik's device-code flow for device logins (ADR 0019;
  the worker sets the brand's `flow_device_code`; the acceptance helpers `authflow.StartDevice/ApproveDevice/
  PollDeviceToken` exercise it), it needs no redirect URI and no local listener, works over SSH, and the browser
  step runs Authentik's normal flows. Loopback PKCE would need regex redirect URIs for random ports and a local
  HTTP listener; it stays a later convenience.
- **C — keep MCP API tokens next to the Authentik login as an automation fallback.** − Two credential types for one
  channel, two revocation stories, two token lifetimes; the automation use case ("an assistant runs unattended") is
  the explicitly excluded "autonomous agent without a user identity" of the epic. **Rejected**: MCP API tokens and
  platform MCP tokens are dropped entirely; `api_token` and `docs/operations/api-tokens.md` stay as they are.

### Decisions

A1. **Flow.** `paddockctl mcp login` obtains `GET /api/auth/mcp/config` (issuer, client id, scopes, the device
    authorization, token and revocation endpoints), starts the device authorization grant on the public Authentik
    provider `paddock-mcp` with scopes `openid profile email groups offline_access`, shows the verification URL and
    user code (and opens the browser), polls the token endpoint, and then calls `POST /api/auth/mcp/session` with
    the ID token and the access token. The CLI keeps access token, refresh token and expiry in
    `$XDG_STATE_HOME/paddockctl/mcp-session.json` (directory 0700, file 0600) and refreshes before expiry; every
    refreshed token pair is presented to `/api/auth/mcp/session` again. `paddockctl mcp` calls the admin API with
    `Authorization: Bearer <access token>`. No API token is ever used for MCP.
A2. **Token acceptance on the api.** The api verifies the ID token with the `paddock-mcp` provider's JWKS (issuer,
    audience `paddock-mcp`, signature, expiry; `amr` must contain `mfa` as for the portal login) and the access
    token as a JWT with the same verifier (audience `paddock-mcp`); both must carry the same `sub`. The role is
    resolved from the ID token's `groups` claim with `organization.ResolveRole` (ADR 0007) and the account is
    upserted through the same `app.Accounts.Login` use case as the portal, recorded as `admin.login` with the
    params `channel: mcp` (and `renewal: true` for a refreshed token). The session is a `sessions.Record` with
    `Channel: "mcp"` under the key `sess:mcp:<sha256(access token)>`, TTL = the access token's remaining life
    (30 minutes in the shipped blueprint), in the account's set `acct-sess:<account_id>` — so the revocation rules
    of ADR 0034 decision 4 apply unchanged: logout deletes the record, a role change or a deactivation found by the
    worker revokes every record of the account, *End all sessions* bumps the generation. In addition the api reads
    the account row on every MCP request: a `disabled_at`, or a `role` that differs from the record, revokes the
    account's sessions immediately. Every request authenticated this way carries `Channel = mcp` on the principal,
    so the MCP policy, the write opt-in, the per-account rate limit and the audit source `mcp` apply by
    construction. A valid Authentik token without a session record answers 401 `mcp_login_required`. JWKS, not
    introspection: Authentik's introspection needs client credentials the public client does not have, and the
    session record gives revocation the JWT alone could not.
A3. **No MCP tokens.** Option C rejected; decisions 2 and 3 withdrawn. The migration shrinks to the opt-in columns
    and the two policy tables; ticket PDK-436 becomes "MCP login via Authentik".
A4. **Step-up.** Unchanged: hidden operations; `checkStepUp` refuses MCP sessions; the step-up endpoints refuse an
    MCP bearer. A fresh Authentik login in the MCP flow is a *login*, not a *step-up*: the WebAuthn-only step-up
    flow, the `paddock_mfa_classes` check and the 20-second `max_age` (ADR 0034) are not part of it.
A5. **Authentik blueprint** `deploy/compose/authentik/blueprints/paddock-mcp.yaml`: public provider `paddock-mcp`
    (no secret), authentication flow `paddock-admin-login`, the MFA-enforcing authorization flow of the device
    providers (never `implicit-consent`, ADR 0007 amendment 2026-10-04), `sub_mode: hashed_user_id` (the same `sub`
    as the portal), signing key shared, property mappings openid/email/profile/offline_access and the Paddock groups
    mapping, `access_token_validity: minutes=30`, `refresh_token_validity: hours=8` (the portal's absolute session
    lifetime); application `paddock-mcp`. The development overlay applies the blueprint and shortens access tokens
    to one minute for the expiry gate. The api learns the issuer through `PADDOCK_OIDC_MCP_ISSUER` (empty = MCP
    login disabled) and `PADDOCK_OIDC_MCP_CLIENT_ID`. Protected identity configuration: changes follow the blueprint
    pattern and ADR 0007.
A6. **Gates** (plan M14 §9.3): L1 login (success, denied role), L2 expired token (refresh), L3 revoked session
    (logout, deactivation), L4 role change, plus the M0–M10 policy gates.
A7. **SDK.** The MCP SDK v1.8.0 carries `golang.org/x/oauth2`, which the CLI uses for the device grant and the
    refresh; no further dependency. An OS keyring for the session file would need one (for example
    `github.com/zalando/go-keyring`) — **open question for the maintainer; default: the 0600 file**.

### Consequences of the amendment

- + One identity for portal and MCP; MFA at every MCP login; revocation shares the portal's mechanisms; no
  credential to create, rotate or revoke in the portal; the platform scope needs no new token type.
- + Three BFF routes and one blueprint instead of two token tables, a lookup function change and three portal
  token surfaces.
- − A refresh token lives on the administrator's workstation for up to 8 hours (RR-87 reworded).
- − One `admin.login` event per 30-minute renewal (≤ 16 per working day per user), flagged `renewal: true`.
- − Hosted MCP clients remain unserved until M14b; the loopback variant is a later convenience.
- Amended documents: plan M14 (rewritten), tickets PDK-435 … PDK-444, ADR 0007 (third public provider), ADR 0034
  (MCP sessions are decision-4 sessions; decision 3 applies), architecture §3.2, §9.6, §14.2, §17.1, §22.

## Amendment 2026-10-26 (ADR 0045) — the role of an MCP session
- `POST /api/auth/mcp/session` takes `role: "platform" | "organization"` (default `organization`) and narrows the
  resolution of the ID token's groups with `RoleResolution.Active` exactly like the portal callback; a role the groups
  do not grant is refused with 403 `forbidden`, detail `role_not_granted`, one `admin.login` denied event
  (`denial_reason: role_not_granted`). `paddockctl mcp login --platform` sends `role: platform`; the session file
  stores the choice and every renewal repeats it. An MCP session has no `alternate_role` and no switch; the human
  runs `paddockctl mcp login` again to act in the other role. The follow-up "PDK-201 must keep one role per session"
  is satisfied by ADR 0045 decision 4. PDK-436 and PDK-439 implement this amendment.
