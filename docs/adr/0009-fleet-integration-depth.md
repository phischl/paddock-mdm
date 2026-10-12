# 0009 — Depth of Fleet integration (A10)
Status: Proposed

## Context
A10: Fleet replaceable in principle; Paddock's data model does not leak Fleet concepts; no Fleet premium features.
Fleet free has no team/organization separation.

## Options
- **Fleet behind an `Inventory` port; Paddock imports normalized data into its own tables.** + Replaceable, isolation
  via Paddock RLS. − Data duplicated, sync lag.
- **Portal embeds/proxies Fleet UI and API.** + Less code. − Leaks all organizations; ties UI to Fleet.
- **Own inventory agent.** − Rejected in the concept.

## Decision
Port `Inventory` with a Fleet adapter (REST, read-mostly, pinned version, contract tests). Host matching by
hardware UUID. Fleet UI/API not exposed publicly. osquery policies defined in Paddock and pushed via API.
Only `device_inventory_ref.external_id` stores Fleet IDs.

## Consequences
+ Swapping Fleet means one adapter. − Fleet requires MySQL and Redis in the stack.

## Amendment 2026-10-12 — vulnerability data in development and CI stacks (PDK-054)

Fleet v4.92.3 finds its CPE dictionary, CPE translations and NVD feeds by listing GitHub releases of `fleetdm/nvd` and
`fleetdm/vulnerabilities` through GitHub's API, anonymously (60 requests per hour and address). On shared CI runners a
fresh stack can stay without data past the inventory gate's wait (PDK-053). Verified in Fleet's source at tag v4.92.3:
with `cpe_database_url`, `cpe_translations_url` and `cve_feed_prefix_url` set, `server/vulnerabilities/nvd/cpe.go`,
`cpe_translations.go` and `cve.go` (`downloadNVDCVELegacy`) make no API call and download the given URLs with a plain
client that follows redirects (`http.DefaultClient` in the vendored nvdtools syncer); the feed syncer requests
`<prefix>nvdcve-1.1-<year>.meta` and `.json.gz` for 2002 to the current year plus `recent` and `modified`, all of which
every `fleetdm/vulnerabilities` release carries. `fleetdm/nvd` retains its daily releases (back to January 2024 at
least), `fleetdm/vulnerabilities` keeps about 145 of its hourly ones, so only the former can be pinned. The MSRC, Mac
Office, OVAL and OSV syncs keep using the API; `cmd/fleet/cron.go` logs their failures and continues, and the
inventory gates do not depend on them (Ubuntu findings come through NVD/CPE in the first hour, PDK-053).

Decision:
- **Development and CI stacks fetch Fleet's vulnerability data by direct URLs.** `compose.dev.yaml` sets
  `FLEET_VULNERABILITIES_CPE_DATABASE_URL` and `FLEET_VULNERABILITIES_CPE_TRANSLATIONS_URL` to the assets of one pinned
  `fleetdm/nvd` release (`https://github.com/fleetdm/nvd/releases/download/<tag>/cpe-<sha256>.sqlite.gz` and
  `.../cpe_translations.json`) and `FLEET_VULNERABILITIES_CVE_FEED_PREFIX_URL` to
  `https://github.com/fleetdm/vulnerabilities/releases/latest/download/`. The two pinned URLs live in
  `deploy/compose/versions.env` (`FLEET_CPE_DATABASE_URL`, `FLEET_CPE_TRANSLATIONS_URL`) next to `FLEET_IMAGE` and move
  with it; `compose.yaml` and `compose.prod.yaml` stay unchanged (production keeps Fleet's own lookup of the latest
  data).
- **No CI credential enters a third-party container.** Fleet's `NETWORK_TEST_GITHUB_TOKEN` is not set anywhere, with
  the job's `GITHUB_TOKEN` or any other token; a developer's stack must work without one as well.
- **No fixture mirror of Fleet's data.** `cpe.sqlite.gz` is 146 MB with a schema internal to Fleet, and the syncer
  requires every year's feed (9–10 MB each), so a deterministic fixture like `osv-fixture` is neither small nor
  stable across Fleet versions. The pinned `fleetdm/nvd` release plus the latest feeds are deterministic enough:
  the gates' CVEs are years old and present in every feed release.

Consequences: + gate F3 no longer waits on GitHub's anonymous limit, in CI and on developer machines; + no secret,
no new container. − A Fleet upgrade re-checks the three variables and the pinned release (the inventory gates F0–F4
guard it, as for the image); − a pruned `fleetdm/nvd` release would fail the data wait with a clear message, and the
pin is then moved.

## Amendment 2026-10-12 (b) — CPE download on every run (PDK-054)

With `cpe_database_url` set, Fleet v4.92.3 skips its once-a-day freshness check (`server/vulnerabilities/nvd/cpe.go`,
`DownloadCPEDBFromGithub`) and downloads the CPE database (146 MB) on every run of its vulnerability job. At the
former development period of 5 minutes that is about 40 GB a day per stack. Decision: the development and CI
`FLEET_VULNERABILITIES_PERIODICITY` stays at 1 hour or longer (the default of `compose.yaml`), and the gates that need
a run trigger it themselves, at most every 2 minutes while they wait, which Fleet refuses while a run is pending; a
gate run therefore causes a bounded number of downloads.
