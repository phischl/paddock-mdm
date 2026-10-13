# Security policy

Paddock manages Linux workstations: it distributes signed configuration, manages identity, sudo rights and disk
encryption, and can revoke data on a device. Security reports are welcome and are handled with priority.

## Supported versions

Paddock is in alpha. Only the latest published pre-release and the `main` branch receive security fixes; there are no
backports to earlier alphas and no upgrade guarantees between them.

| Version                           | Supported |
| --------------------------------- | --------- |
| latest `0.1.0-alpha.N`, `main`    | yes       |
| earlier alphas                    | no        |

## Reporting a vulnerability

Please do **not** open a public issue, discussion or pull request for a vulnerability.

Report it privately through GitHub's private vulnerability reporting:
<https://github.com/phischl/paddock-mdm/security/advisories/new>

Please include, as far as you can:

- the affected component (server role, portal, agent `paddockd`, `paddock-supervisor`, `paddock-revoke`, `paddockctl`,
  the deployment bundle or the release artifacts) and the version or commit;
- a description of the issue and its impact, for example which organization boundary, privilege or protected area on
  the device it crosses;
- steps to reproduce or a proof of concept, and any configuration it needs;
- whether the issue is already public or known to others.

Do not include real secrets, personal data or data of third parties in the report.

## What happens next

Paddock is maintained by a single person, so the times below are targets, not guarantees:

- acknowledgement of the report within 5 working days;
- a first assessment (confirmed or not, severity) within 10 working days;
- a fix or mitigation as soon as possible, coordinated with you, then a release and a GitHub security advisory that
  credits you unless you prefer to stay anonymous.

Please give us up to 90 days from the report before disclosing details publicly, or less once a fixed release is
out. If a vulnerability is actively exploited, we will publish a mitigation earlier.

## Scope

In scope:

- the server and all its roles, including the admin API, the device API and the portal;
- organization isolation (one organization reading or changing another's data);
- the agent, the supervisor and its update path (signature checks, A/B switch, rollback), and the revocation path;
- audit integrity (missing, forged or altered audit events);
- the release artifacts, their signatures and the deployment bundle;
- secrets handling (for example a secret written to a log, an audit event or a response).

Out of scope:

- vulnerabilities in third-party components Paddock runs (Fleet, Authentik, OpenBao, PostgreSQL, RabbitMQ, Valkey,
  Caddy and others): please report those upstream; a report is in scope when Paddock's configuration or integration
  makes them exploitable;
- the development stack and its development settings (`PADDOCK_ENV=development`, dev secrets, test overlays);
- findings that require an attacker who already has root on the managed device or administrator access to the
  server host;
- denial of service by sheer volume, and missing hardening without a demonstrated impact.

## Verifying releases

Agent binaries and packages are signed with the agent release key (minisign); container images, SBOM attestations,
`SHA256SUMS` and the deployment bundle are signed keylessly with Sigstore. How to verify them is described in
[docs/operations/agent-releases.md](docs/operations/agent-releases.md) and
[docs/operations/install.md](docs/operations/install.md). `paddock-revoke` is published unsigned and must be signed
offline with the separate revocation release key before use.

Revocation (lock, destroy, dead man's switch) is disabled by default (`PADDOCK_REVOCATION_ENABLED`) until its code has
passed the second-person review and an installation has passed its hardware acceptance
([docs/operations/revocation-acceptance.md](docs/operations/revocation-acceptance.md)).
