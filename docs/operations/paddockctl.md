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
| `--url` | `PADDOCK_URL` | `url` | Base URL of the admin API, for example `https://admin.example.org` (required). |
| `--token-file` | `PADDOCK_TOKEN_FILE` | `token_file` | File holding the token (required). It may not be readable by group or others (`chmod 600`); otherwise paddockctl exits with code 2. |
| `--ca-file` | `PADDOCK_CA_FILE` | `ca_file` | PEM bundle added to the system roots (development stack: `deploy/compose/.secrets/caddy-root.crt`). |
| `--config` | | | Config file; default `$XDG_CONFIG_HOME/paddockctl/config.yaml`, otherwise `~/.config/paddockctl/config.yaml`. A missing default file is fine. |

```yaml
# ~/.config/paddockctl/config.yaml
url: https://admin.example.org
token_file: /home/ops/.config/paddockctl/token
```

Flags come after the command: `paddockctl get config -o json --url https://admin.example.org`.

## Commands

| Command | Does |
| --- | --- |
| `paddockctl whoami [-o text\|json]` | Organization, role, token name and expiry of the token. |
| `paddockctl schema` | Prints the JSON Schema of `paddock.yml` (`api/schema/paddock.v1.json`), for editors and validators. |
| `paddockctl get config [-o yaml\|json]` | Exports the configuration with every section, in the order of the schema. |
| `paddockctl apply -f <file\|-> [--dry-run] [--yes] [-o text\|json]` | Reads YAML or JSON and prints the plan. With `--dry-run` it stops there. Without `--yes` a plan that deletes something is refused (exit code 3; paddockctl never asks). Otherwise it applies the file and prints `Applied change set <id>`, or `No changes`. |
| `paddockctl devices list [--page N] [--page-size 10\|25\|50\|100] [--sort <field>] [-q <text>] [--state <s>]… [--device-group-id <uuid>] [--disk-state <s>]… [-o table\|json]` | Lists devices with the parameters of the admin API's list contract; `-o json` prints the API's answer unchanged. |

A plan shows one line per created (`+`) and deleted (`-`) item and one line per changed field (`~ settings.login
hello_enabled: false -> true`), then `Plan: N to create, M to update, K to delete`. File contents appear only as their
SHA-256 and length.

**Exit codes:** 0 success; 1 API or network error, printed as `error: <code>: <detail> (request <id>)`; 2 usage or
configuration error; 3 apply refused because the plan deletes resources and `--yes` is missing.

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
- **The rules of the portal apply unchanged.** Deleting device groups and changing settings need `org_admin`. Assigning
  a full profile or changing a profile to full needs a step-up, which a token never has; make those changes in the
  portal. Paths and units are checked as in the portal. One refused item aborts the whole apply, and the error names
  the document path (`/managed_files/2: …`). Nothing is applied. A dry run checks exactly the same and changes
  nothing.
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

Each prints one line (`bumped bundle_seq of 42 devices by 1000000`, `cache rebuilt for 2 organizations`,
`recompile requested for 2 organizations`) and exits with 0, 1 (failure) or 2 (usage). `paddock-server audit verify`
stays the command to verify the audit trail. It needs the audit domain's credentials, which stay on the audit host.
