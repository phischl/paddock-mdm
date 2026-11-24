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

## Amendment 2026-11-24 (c) — Ubuntu matching via OSV; minimal OSV seed in the dev/test stack (PDK-1093, PDK-1140)

The amendment of 2026-10-12 rests on the sentence "the inventory gates do not depend on them (Ubuntu findings come
through NVD/CPE in the first hour, PDK-053)". With Fleet v4.96.0 that premise no longer holds. Verified in Fleet's
source at tag `fleet-v4.96.0`:

| Software on an Ubuntu host | Matching source | Where Fleet finds the data |
| --- | --- | --- |
| deb packages (`deb_packages`) | OSV artifact `osv-ubuntu-<release>-<date>.json.gz`, read by `server/vulnerabilities/osv` (`osv_for_vulnerabilities`, on by default); OVAL when that option is off | `https://api.github.com/repos/fleetdm/vulnerabilities/releases/latest` (`server/vulnerabilities/vulnrepo`, `LatestRelease`); OVAL through the API as well (`server/vulnerabilities/oval/sync.go`, `ghNvdFileGetter`). Neither has a URL option. |
| Ubuntu kernel packages (`linux-image-…`) | CPE dictionary and NVD feeds (translated separately in `server/vulnerabilities/nvd/cpe.go`), besides the OSV artifact | direct URLs (`cpe_database_url`, `cpe_translations_url`, `cve_feed_prefix_url`) or the API |
| software from sources OVAL does not cover | CPE dictionary and NVD feeds | as above |

`TranslateSoftwareToCPE` excludes `oval.SupportedSoftwareSources`, which contains `deb_packages`, so a deb package
never gets a finding through the CPE dictionary. The OSV phase (`cmd/fleet/cron.go`, `checkOSVVulnerabilities`) logs a
failed lookup (`updating OSV artifacts`) and goes on to analyze the Ubuntu releases Fleet has recorded for its hosts
with the artifact on disk; without one it logs `no OSV artifact found for osv-ubuntu-<release>` and the hosts of that
release get no package finding. The direct URLs of 2026-10-12 therefore keep the CPE dictionary and the NVD feeds off
GitHub's anonymous limit, but they no longer feed the deb findings gate F3 asserts; on a shared CI runner over the
limit F3 saw none, although every vulnerability run completed (PDK-1093).

On this point the amendment of 2026-10-12 is superseded: the quoted sentence, and the decision "No fixture mirror of
Fleet's data" as far as OSV artifacts are concerned. Its reasons were the size of the CPE database (146 MB), a schema
internal to Fleet and one feed per year; an OSV artifact with the gate's records is a few hundred bytes of one
documented JSON structure (`OSVArtifact` in `server/vulnerabilities/osv/analyzer.go`). The rest of that amendment
stays in force: the direct URLs, no credential in a third-party container, and no fixture for the CPE dictionary and
the NVD feeds.

Options:
- **Seed a minimal OSV artifact from the gate.** + Deterministic, no secret, no container, no change to any compose
  file; Fleet still does the matching. − The gate depends on Fleet's artifact format and file naming, which a Fleet
  upgrade can change.
- **Pass Fleet a GitHub token.** − Rejected on 2026-10-12 (no CI credential in a third-party container; a developer's
  stack must work without one); unchanged.
- **Mirror container that answers for `api.github.com`.** − A new container plus TLS interception inside the stack,
  for two records.
- **Turn `osv_for_vulnerabilities` off.** − Moves Ubuntu to OVAL, which uses the same API.
- **Disable Fleet's data sync and pre-seed all data.** − The stack would no longer exercise Fleet's download at all,
  and the CPE database and the feeds would have to be provided as well.

Decision:
1. **The gate seeds a minimal OSV artifact.** Before it waits, gate F3 writes one artifact in Fleet's format into
   Fleet's vulnerability path (`FLEET_VULNERABILITIES_DATABASES_PATH`). It contains exactly the records for the
   package versions the gate installs, copied from an artifact Fleet published. Fleet's own analyzer does the
   matching; the gate's assertion per organization and its 10-minute bound are unchanged.
2. **The seed exists only in the development and test stack, written by acceptance test code.** It is not a file in
   the repository's deployment tree, not a volume, not an init container and not a Fleet option: `compose.yaml`,
   `compose.prod.yaml`, `compose.dev.yaml` and the operator bundle contain nothing of it. Production Fleet only ever
   has data Fleet downloaded itself.
3. **An artifact Fleet downloads itself always wins over the seed.** The seed's file name carries the date
   2000-01-01. Fleet reads the artifact named for the current day and otherwise the newest one on disk by name
   (`osv/artifact.go`, `readArtifact`; `vulnrepo.NewestLocalAsset`), and after a successful lookup it removes the
   older artifacts of every release it has current data for (`removeOldArtifacts`), the seed included. The seed's date
   is never moved forward, and the development stack never sets Fleet's `disable_data_sync`: wherever GitHub answers,
   the gate runs on Fleet's real data.
4. **Every Fleet upgrade re-checks the matching source and the seed** at the new tag, in addition to the three
   variables and the pinned release of 2026-10-12: the table above (which source matches which software, and where
   Fleet finds that source's data), the artifact structure and file name, and the precedence of point 3. A difference
   is recorded with the upgrade and, where it changes what the gates rest on, decided before the upgrade merges.
5. **"Matching source per platform" is an item of the Fleet upgrade checklist** in `docs/operations/fleet.md`. The
   checks made for the upgrade to v4.96.0 covered Fleet's API towards Paddock and the release notes (PDK-1129); the
   move of deb packages from CPE to OSV was in neither, and green gates on a runner within GitHub's limit do not show
   it. The checklist item is therefore a comparison in Fleet's source, not a gate.
6. **The wait for the CPE dictionary and the NVD feeds stays; its reason changes.** `waitFleetVulnerabilityData`
   keeps waiting for `cpe.sqlite` and the feeds before a device's 10 minutes start. They no longer provide the gate's
   findings; the wait keeps Fleet's first download of them, the long part of a first vulnerability run on a fresh
   stack, out of the 10 minutes, and it still reports a pruned pin with Fleet's download error. The comments in the
   test code that name the CPE dictionary and the feeds as the source of the findings are corrected in a follow-up; no
   assertion changes.
7. **The direct CPE and feed URLs in `compose.dev.yaml` stay.** No gate asserts a finding that comes through them any
   more, but they keep the CPE dictionary and the feeds off the anonymous limit that Fleet's OSV lookup shares, and
   kernel packages and software outside deb packages are still matched through them on developer stacks and test VMs.
   The amendment of 2026-10-12 (b) (period of 1 hour or longer) continues to apply for the same reason.

Consequences: + gate F3 no longer depends on GitHub's anonymous limit for the data its findings need; + no secret, no
new container, no compose change. − The seed copies Fleet's artifact format, so a Fleet upgrade has one more thing to
compare (decision 4); a test without the stack checks that the seed decodes into that structure. − The seed covers the
two findings of acceptance gate F3 only: the system gate on real devices (F4) and every other package on a developer
stack get findings only from an artifact Fleet downloaded.

Operators: production is unchanged by this amendment, and the same behaviour of Fleet applies there. A Fleet that has
never downloaded the artifact for an Ubuntu release reports no package findings for the hosts of that release until
one of its hourly runs gets past GitHub's limit; once an artifact is on disk, a failed lookup leaves the last one in
use. `docs/operations/fleet.md` describes this. Whether operators get a supported way to provide the data without
GitHub's API is a separate decision (PDK-1141), not part of this amendment and not a precondition of it.
