# paddockctl: the organization's configuration as code

`paddockctl` exports an organization's configuration as `paddock.yml`, shows a changed file as a plan and applies it
in one transaction, authenticated with an [API token](api-tokens.md) (plan M6c §3.2–3.4, ADR 0011). Every apply is
audited as `config.applied` and recorded as a change set, which the portal page *Change sets* shows with its plan.

## Install

`make paddockctl` builds static binaries without runtime dependencies for Linux into `bin/paddockctl/amd64/paddockctl`
and `bin/paddockctl/arm64/paddockctl`. Copy the one for your architecture into the `PATH`. `paddockctl version` prints
the version.

## Configuration

Flags win over environment variables, and environment variables over the config file. The token itself is never in
the config file; only the path of the file that holds it is.

| Flag | Environment | Config file | Meaning |
| --- | --- | --- | --- |
| `--url` | `PADDOCK_URL` | `url` | Base URL of the admin API, for example `https://admin.example.org` (required; only `https://`, because every request carries the token). |
| `--token-file` | `PADDOCK_TOKEN_FILE` | `token_file` | File holding the token (required). It may not be readable by group or others (`chmod 600`); otherwise paddockctl exits with code 2. |
| `--ca-file` | `PADDOCK_CA_FILE` | `ca_file` | PEM bundle added to the system roots (development stack: `deploy/compose/.secrets/caddy-root.crt`). |
| `--config` | | | Config file; default `$XDG_CONFIG_HOME/paddockctl/config.yaml`, otherwise `~/.config/paddockctl/config.yaml`. A missing default file is fine. |

```yaml
# ~/.config/paddockctl/config.yaml
url: https://admin.example.org
token_file: /home/ops/.config/paddockctl/token
```

Flags come after the command: `paddockctl get config -o json --url https://admin.example.org`.

When the platform administrators keep entries in the IP allow list (`docs/operations/ip-allowlist.md`), `paddockctl`
works only from the listed ranges — from inside the office network or through its VPN — and a CI pipeline needs a
stable egress address on the list (self-hosted runner, NAT gateway or VPN); hosted runners without a fixed address
cannot be allow-listed. A refused request is `403 ip_not_allowed`.

## Commands

| Command | Does |
| --- | --- |
| `paddockctl whoami [-o text\|json]` | Organization, role, token name and expiry of the token. |
| `paddockctl schema` | Prints the JSON Schema of `paddock.yml` (`api/schema/paddock.v1.json`), for editors and validators. |
| `paddockctl get config [-o yaml\|json]` | Exports the configuration with every section, in the order of the schema. |
| `paddockctl apply -f <file\|-> [--dry-run] [--yes] [-o text\|json]` | Reads YAML or JSON and prints the plan. With `--dry-run` it stops there. Without `--yes` a plan that deletes something is refused (exit code 3; paddockctl never asks). Otherwise it applies exactly the plan it showed: the apply carries the plan's SHA-256 (`expected_plan`), and if the configuration changed in between, the server applies nothing and paddockctl exits with code 3; run it again to review the new plan. On success it prints `Applied change set <id>`, or `No changes`. |
| `paddockctl mcp login [--no-browser] [--platform]` | Signs an administrator in to the MCP through Authentik (device authorization grant, password and second factor in the browser) and writes the session file `$XDG_STATE_HOME/paddockctl/mcp-session.json` (0600). No token file: [mcp.md](mcp.md). |
| `paddockctl mcp` | The stdio MCP server for an MCP client such as Claude Code: the admin API operations the session may call as tools, with the administrator's role ([mcp.md](mcp.md)). |
| `paddockctl mcp tools [-o table\|json]` | Lists the tools the MCP session is offered now. |
| `paddockctl mcp logout` | Ends the MCP session, revokes its refresh token and deletes the session file. |
| `paddockctl audit verify-export <file> [--fingerprint <hex>] [-o text\|json]` | Verifies an audit evidence package offline: no configuration, token or network. See [Verifying an evidence package](#verifying-an-evidence-package). |
| `paddockctl devices list [--page N] [--page-size 10\|25\|50\|100] [--sort <field>] [-q <text>] [--state <s>]… [--device-group-id <uuid>] [--disk-state <s>]… [-o table\|json]` | Lists devices with the parameters of the admin API's list contract; `-o json` prints the API's answer unchanged. |
| `paddockctl audit feed [--after N] [--limit L] [--follow]` | Reads the organization's audit events from the cursor feed (`org_admin` or `org_auditor` token): one JSON event per line on stdout, the cursor on stderr as `next_after=<n>` (pass it as `--after` next time). `--limit` is 1 to 1000 (default 100). `--follow` keeps reading, polling every 30 seconds once caught up, until interrupted. A 403 exits with code 1 and the problem code. |
| `paddockctl findings list [--page N] [--page-size 10\|25\|50\|100] [--sort <field>] [-q <text>] [--status <s>]… [--kind <k>] [--cleared] [-o table\|json]` | Lists findings with the list contract of the admin API; cleared findings only with `--cleared`. `-o json` prints the API's answer unchanged. Findings are acted on in the portal only. |

A plan shows one line per created (`+`) and deleted (`-`) item and one line per changed field (`~ settings.login
hello_enabled: false -> true`), then `Plan: N to create, M to update, K to delete`. An item is named by its key, the
JSON array of its parts: `+ managed_files [null,"/etc/motd"]` (`null` = every device), `- package_holds
["kiosks","firefox"]`, `+ profile_assignments ["laptops","ops","group","devs"]`. Every part is quoted, so names may
contain any character. File contents appear only as their SHA-256 and length.

The `mcp` commands authenticate with the MCP session of `paddockctl mcp login`, never with the token file;
`--token-file` and `PADDOCK_TOKEN_FILE` are ignored there, and `paddockctl mcp` and `paddockctl mcp tools` without a
session exit with code 2 (`not signed in: run paddockctl mcp login`).

**Exit codes:** 0 success; 1 API or network error, printed as `error: <code>: <detail> (request <id>)`; 2 usage or
configuration error; 3 apply refused because the plan deletes resources and `--yes` is missing, or because the
configuration changed after the plan was shown (nothing was applied in both cases).

## paddock.yml

`examples/paddock.yml` is a complete example. The document holds the login and update settings, device groups,
permission profiles, managed files and units, package holds and profile assignments. It does not hold the dead man's
switch, users and user groups, enrollment tokens, devices and their groups, or login assignments; manage those in the
portal.

- **A present section is authoritative.** Items it does not list are deleted, and listed items are created or changed
  to match. Leave out a section to keep it as it is. Settings are compared field by field; `settings.login` and
  `settings.updates` need every field when present.
- **Items are identified by natural keys:** device groups and profiles by name; files, units and holds by device
  group and path, unit or package; assignments by profile, subject and device group. Renaming a key deletes the old
  item and creates a new one. `device_group: null` means every device of the organization; `subject` is
  `{type: global}`, `{type: group, slug: …}` or `{type: user, username: …}`.
- **The rules of the portal apply unchanged.** Deleting device groups and changing settings need `org_admin`. Every
  change that needs a step-up in the portal needs one here ([step-up.md](step-up.md)), which a token never has:
  changes that would grant root in effect, alone or in combination, managed files on sensitive paths and operator
  roots. Paths and units are checked as in the portal. One refused item aborts the whole apply, and the error names
  the document path (`/managed_files/2: …`). Nothing is applied. A dry run checks exactly the same and changes
  nothing.
- **Deleting a device group deletes everything scoped to it**: its managed files, units, package holds and profile
  assignments. Each of them must be a deletion in the plan. A document that deletes a group is refused when it leaves
  out one of those sections while the group still has items there (409 `in_use`), or when it still lists an item of
  the group (422 `invalid_document`, naming the item). A group that still has member devices is not deleted (409
  `in_use`, with the number of members). This also applies to a rename, which is a deletion and a creation. Move the
  devices to other groups in the portal first, because `paddock.yml` does not hold group membership.
- Documents are limited to 1 MiB. A schema violation is answered with `invalid_document` and up to 20 paths.

## CI example

Keep `paddock.yml` in a repository: preview on pull requests, apply on the main branch. The token needs `org_operator`
or `org_admin`, and `org_admin` if the file changes settings or deletes device groups.

```yaml
# .github/workflows/paddock.yml
on:
  pull_request: { paths: [paddock.yml] }
  push: { branches: [main], paths: [paddock.yml] }
jobs:
  paddock:
    runs-on: ubuntu-latest
    env:
      PADDOCK_URL: https://admin.example.org
      PADDOCK_TOKEN_FILE: ${{ runner.temp }}/paddock-token
    steps:
      - uses: actions/checkout@v4
      - run: install -m 600 /dev/null "$PADDOCK_TOKEN_FILE" && printf '%s' "$TOKEN" > "$PADDOCK_TOKEN_FILE"
        env: { TOKEN: "${{ secrets.PADDOCK_TOKEN }}" }
      - if: github.event_name == 'pull_request'
        run: paddockctl apply -f paddock.yml --dry-run
      - if: github.event_name == 'push'
        run: paddockctl apply -f paddock.yml --yes
```

Start from `paddockctl get config > paddock.yml` so that the first apply changes nothing.

**Two-step flow for changes that need a step-up.** A token never satisfies a step-up, so an apply whose plan contains
such a change is refused as a whole with 403 `step_up_required` (detail: `this change needs an interactive
administrator: API tokens cannot complete a step-up`), and the dry run on the pull request shows the same refusal.
Split the change:

1. An organization administrator makes the change in the portal, with a step-up.
2. The pull request then commits the same definition to `paddock.yml`. CI's next apply finds that item unchanged,
   needs no step-up for it and applies everything else.

Everything that needs no step-up — device groups, ordinary managed files, units, holds, settings without operator
roots, assignments that grant no root — stays fully automated.

## Restore commands

After a PostgreSQL restore, devices run bundle versions newer than the restored database knows. The restore commands
run on the host with the worker's configuration, not through `paddockctl`: they need privileges the admin API does
not have, and they run while the compiler is stopped (plan M6c decisions 20–23). Run them in this order:

```
docker compose … stop paddock-compiler
docker compose … run --rm --no-deps paddock-worker admin bump-bundle-seq --by 1000000
docker compose … start paddock-compiler
docker compose … run --rm --no-deps paddock-worker admin rebuild-cache
docker compose … run --rm --no-deps paddock-worker admin recompile --all
```

| Command | Does | Audit |
| --- | --- | --- |
| `admin bump-bundle-seq --by N` (1 ≤ N ≤ 1 000 000 000) | Raises the bundle sequence of every device by N, so the next bundle is newer than anything a device accepted. | `platform.bundle_seq_bumped` (`by`, `devices`) |
| `admin rebuild-cache` | Rewrites the gateway's enrollment tokens, device keys and sequence numbers in Valkey from PostgreSQL. The running compiler rewrites bundle pointers and time tickets within 60 s. | `platform.cache_rebuilt` (`organizations`) |
| `admin recompile --all` | Publishes a new bundle version for every active device, also when its content is unchanged. | `organization.recompile_requested`, one per organization |
| `admin security-review` | Prints, per organization, the unconfirmed root grants, the unconfirmed files on sensitive paths and the files on denied paths (ADR 0034); run once after the upgrade that introduced them. | `organization.security_review_required`, one per organization with a count above zero |

Each prints one line (`bumped bundle_seq of 42 devices by 1000000`, `cache rebuilt for 2 organizations`,
`recompile requested for 2 organizations`) and exits with 0, 1 (failure) or 2 (usage). `paddock-server audit verify`
stays the command to verify the audit trail. It needs the audit domain's credentials, which stay on the audit host.

## Verifying an evidence package

An evidence package (a tar file the portal offers for download, ADR 0032) lets an auditor check the audit trail of an
organization without any access to Paddock. `paddockctl audit verify-export` needs no configuration file, no token
and no network; it reads the file twice and never extracts it.

```
paddockctl audit verify-export package.tar --fingerprint <fingerprint recorded by your ISMS>
```

**The fingerprint handshake.** The package carries the public key it was signed with, so on its own it can only prove
that it is consistent with itself. What makes it evidence is the fingerprint (SHA-256 of the audit-chain public key)
that you obtained out of band: from the portal's signing-keys page, from the operator's ISMS record or from an earlier
package. With `--fingerprint` the verifier requires the key of the package signature to match it (a mismatch is the
problem `signing key fingerprint differs from --fingerprint`). Without it the result is still printed, but with a note
that the key is not authenticated. The manifests and the key versions they use are covered by the signed
`export.json`, so one pinned key is enough, also across a key rotation.

**What is checked** (all problems are collected; the verifier does not stop at the first):

1. `export.json` has the schema `paddock.audit-export.v1` and its signature in `export.sig` verifies with the embedded
   key of the stated version; the key matches `--fingerprint`.
2. For every day of the range there is a signed manifest that matches the hash in `export.json`, belongs to the
   organization and the day, and links to the previous day's manifest. The first day's link is reported as the chain
   anchor; verify consecutive packages against each other to extend the chain.
3. Every object listed in a manifest is in the package with the listed SHA-256; no object is unlisted; the object list
   of `export.json` equals the manifests'.
4. `events.jsonl` has the SHA-256 `events_sha256` and equals the decoded objects, in manifest order, byte for byte; its
   line count equals `event_count`; every line is JSON of this organization with schema `paddock.audit.v1`. An object
   whose hash differs or that cannot be decoded (or decodes to more than 256 MiB) is reported and contributes no events.
5. The server's own verification at build time and the nightly runs are reported (`chain verified by the server`,
   `nightly runs`, its problems), but a problem found there is not a problem of the verifier.

`README.md` in the package is informational: it is not covered by the signature and the verifier takes every fact
from `export.json`. Members with an unsafe name (`..`, absolute, backslash, empty or `.` segments), duplicates,
members that are not regular files and members no package contains are reported as problems. The verifier bounds
memory and decompression (256 MiB per object); a package beyond its size limits is refused with exit code 2, and a recording range of more than 36 600
days is reported as a problem (exit code 1).

Output: `OK <organization_id> <from>..<to>: <days> days, <objects> objects, <events> events; signed with audit-chain
v<N> (fingerprint <hex>); chain anchor <hex|none>` or one `FAIL <problem>` line per problem and a `NOT OK` summary.
`-o json` prints `ok`, `organization_id`, `from_day`, `to_day`, `days`, `objects`, `events`, `key_version`,
`fingerprint`, `fingerprint_checked`, `chain_anchor`, `server_verification` (`ok`, `problems`, `runs`,
`runs_with_problems`) and `problems`. `ok` authenticates nothing unless `fingerprint_checked` is true: without
`--fingerprint` it only says the package is consistent with the key it embeds.

| Exit code | Meaning |
| --- | --- |
| 0 | The package verifies. |
| 1 | The package has problems; they are printed. |
| 2 | Usage error, an unreadable file, a file that is not a tar archive, or a package beyond the verifier's size limits. |
