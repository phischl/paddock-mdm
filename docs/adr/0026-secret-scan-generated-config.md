# 0026 — Secret scan: generated configuration without gitleaks' default path allowlist
Status: Accepted (2026-10-12)

## Context
ADR 0025 neutralised gitleaks' default global path allowlist by renaming the copies that `scan-secrets-diff` scans
(`.scan` suffix on 29 extensions, every path component, `?dll`). PDK-074 then probed the remaining entries of that
allowlist with the pinned gitleaks v8.30.1 and found ones a rename cannot neutralise: unanchored patterns
(`gitleaks\.toml`, `verification-metadata\.xml`, `Database.refactorlog` match anywhere in a path), patterns that span
components (`(?:v?env|virtualenv)/lib(?:64)?`, `lib/python3.x/`), and plausible hand-written names that are skipped
outright: `bootstrap.js`, `jquery-*.js`, `swagger-ui*.js`, `javascript.json`, `*.dist-info/`. Those entries skip the
file in **both** scan modes, so a `src/bootstrap.js` holding a credential is never scanned today, in a pull request or
in the weekly history scan of `main`. PDK-074 ended as documentation; the rename list had become a growing set of
special cases with no end.

Facts measured on 2026-10-12 with the pinned image `zricethezav/gitleaks:v8.30.1`:

- `[extend] useDefault = true` appends the default config's allowlists; nothing in `config.go` lets a child drop or
  override them (`c.Allowlists = append(c.Allowlists, extensionConfig.Allowlists...)`); `[extend] disabledRules`
  disables rules only; `[extend] url` is an empty `TODO`. gitleaks has no command that prints its default config.
- The default config is embedded in the binary with `go:embed`: `/usr/bin/gitleaks` holds `config/gitleaks.toml` of
  the tag as one contiguous, uncompressed byte string. Its first line `# This file has been auto-generated. Do not edit
  manually.` occurs exactly once in the binary (offset 9 265 056); the 97 731 bytes from there are byte-identical to
  `config/gitleaks.toml` at tag v8.30.1 (sha256 `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`).
- The default's global allowlist is the singular table `[allowlist]` with `paths` (25 patterns), `regexes` (13) and
  `stopwords` (2), followed by the `[[rules]]`. A child using `[[allowlists]]` next to a parent using `[allowlist]` is
  fine through `[extend] path`; both forms in one file are rejected.
- With the default rules, the global allowlist without its `paths`, and the repository's own `.gitleaks.toml`
  allowlists: a probe tree (`d.png/creds.bin`, `bootstrap.js`, `src/javascript.json`, `node_modules/x/creds.txt`,
  `plain.txt`, each with a fake GitHub token) yields 5 of 5 findings where `useDefault` yields 1 of 5; the
  repository's 1 254 tracked files (9.9 MB, 0.8 s) yield 8 findings, all `generic-api-key` on module lines of
  `server/go.sum` and `test/acceptance/go.sum`, and none elsewhere (icons, fonts, lock file included); with `go.sum`
  and `package-lock.json` allowlisted by path, the tracked files and the whole history of `main` (403 commits,
  `--remerge-diff`, 1.6 s) yield no finding.

## Options
- **Keep the renames and document the rest (PDK-074, status quo).** + No change. − Names like `bootstrap.js` stay
  unscanned in every mode; every image bump re-checks a hand-kept list against the default.
- **Vendor `config/gitleaks.toml` of the pinned tag without the path entries.** + Explicit file. − 3 200 generated
  lines re-vendored at every bump and read by the merge-base review of PDK-065; a stale vendored file is not noticed.
- **Extract the default from the pinned image's binary at scan time, drop the global `paths`, extend it with the
  repository's `.gitleaks.toml` (chosen).** + Always the rules of the image in use; a bump cannot drift unnoticed
  because the extracted bytes are checked against a pinned size and sha256; no vendored blob; one source for the
  repository's allowlists. − Depends on `go:embed` keeping the file contiguous and uncompressed (true for every Go
  release; the sha256 check turns a change into a loud failure); two more pins to update at a bump.
- **Drop only a curated subset of the default's path entries.** − A second hand-kept list, the thing being removed.
- **Scope: the diff scan only, or both scans.** Both (chosen): the history scan skips the same names in git mode, the
  generated config costs it nothing, and measured over the whole history it finds nothing new. Diff scan only
  (rejected) would leave `src/bootstrap.js` unscanned on `main` forever.
- **Lock files after the drop.** Allowlist `go.sum` and `server/web/package-lock.json` by exact path in the
  repository's `.gitleaks.toml` (chosen): generated files, measured as the only noise, explicit and reviewed under
  PDK-065. Keep the default's lock-file entries (rejected: a curated subset again).

## Decision
1. **One generated configuration for both scans.** `make scan-secrets` and `make scan-secrets-diff` run gitleaks with
   a configuration generated into the temporary config directory: the default rules of the pinned image, without
   the `paths` of its global allowlist, extended by the repository's `.gitleaks.toml` taken from `GITLEAKS_CONFIG_REF`
   (PDK-065) as today.
2. **The default comes from the image in use.** The recipe copies `/usr/bin/gitleaks` out of `GITLEAKS_IMAGE`, finds
   the single occurrence of the line `# This file has been auto-generated. Do not edit manually.`, takes
   `GITLEAKS_DEFAULT_CONFIG_BYTES` bytes from that offset and verifies their sha256 against
   `GITLEAKS_DEFAULT_CONFIG_SHA256`. Both values are pinned in `deploy/compose/versions.env` next to `GITLEAKS_IMAGE`
   and are the size and sha256 of `config/gitleaks.toml` at the image's tag (v8.30.1: 97731,
   `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`). A header that occurs zero or several times,
   or a sha256 mismatch, fails the scan with a message naming the two pins; an image bump therefore updates
   `GITLEAKS_IMAGE`, the two pins and the test expectations together. Nothing is vendored.
3. **Only the global `paths` go.** From the table `[allowlist]` up to the first `[[rules]]`, the `paths = [ … ]`
   array is removed; `regexes`, `stopwords` and every rule with its `[[rules.allowlists]]` stay. After the removal the
   recipe asserts that no `paths` key remains before the first `[[rules]]`, and fails otherwise (a future layout
   change of the default must be looked at, not silently scanned with the paths back in).
4. **Composition through `[extend] path`.** The generated child is the merge-base `.gitleaks.toml` whose `[extend]`
   table is replaced by `[extend]` with `path = "<absolute path of the stripped default inside the container>"`; the
   stripped default is written next to it. The repository's `.gitleaks.toml` keeps `useDefault = true` so that a
   plain `gitleaks` call and editor plugins behave as before, and the PDK-065 rule that a repository configuration
   with `[extend] path` fails the scan stays.
5. **Lock files are the repository's own allowlist.** `.gitleaks.toml` gets two path-only allowlists:
   `^(b/)?(?:.+/)?go\.sum$` and `^(b/)?server/web/package-lock\.json$`. They land in their own pull request before the
   generated configuration (PDK-065: a pull request is scanned with the merge base's configuration).
6. **Renames.** The `.scan` rule of ADR 0025 (decision 1 and the directory and `?dll` rules of its amendment) is
   removed together with `GITLEAKS_RENAME_EXT`. The archive rules stay: a last component in `GITLEAKS_ZIP_EXT` gets
   `.zip`, `.tgz` gets `.tar.gz`, and the directory scan runs with `--max-archive-depth 1` (ADR 0025 decisions 2 and
   3), because gitleaks identifies archives by name only, which no configuration changes. Fingerprints and path
   allowlists for renamed archives keep the suffix; no fingerprint carries `.scan` any more.
7. **History scan of `main` (replaces ADR 0025 decision 4).** The history scan uses the generated configuration and
   therefore also covers text under binary-extension names and the names the default skipped. Its remaining gaps are
   binary content (git shows no binary patches), archives, and files whose magic bytes map to `application/*`
   (gitleaks' skip in every mode). No periodic blob scan of `main`'s history is added (PDK-070): those gaps are closed
   by branch protection that lets `main` take pull requests only, which is the maintainer's setting, and
   `docs/operations/secret-scan.md` states that dependency.
8. **Documentation.** `docs/operations/secret-scan.md` describes the generated configuration, the two pins and the
   bump procedure, the lock-file allowlist, the archive renames, and drops the table of skipped default entries
   (PDK-074) and every mention of `.scan`.

## Consequences
+ Every changed file is scanned by content except the documented magic-byte skip; no hand-kept list mirrors the
  default any more; the history scan covers the same names as the pull request scans.
+ A gitleaks bump is a three-line change in `versions.env` that cannot drift: wrong pins fail the scan.
− The recipe reads a Go binary's embedded data; this holds for every Go release to date, and the sha256 check makes a
  change visible at once. − `go.sum` and `package-lock.json` are now skipped by the repository's own choice, which
  the ops documentation names.
Follow-ups: the implementation ticket of this ADR (allowlist pull request first, then recipe, tests, docs); PDK-072
(blob layer search) builds on the shortened `scan_name` afterwards; PDK-070 closes with the dependency documented.
Re-evaluate when gitleaks offers a way to drop entries of the default global allowlist (then the extraction goes) or
identifies archives by content (then the archive renames go).
