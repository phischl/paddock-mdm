# 0025 — Secret scan: coverage of binary-extension files and archives
Status: Accepted (2026-10-12)

## Context
The CI job `secrets` runs gitleaks in two views over a pull request: `make scan-secrets` over its commits
(`--remerge-diff`, PDK-057) and `make scan-secrets-diff` over the final content of every changed file and every
blob the range adds, in layered directories (PDK-068); both take `.gitleaks.toml` and `.gitleaksignore` from the merge
base (PDK-065, trust boundary in `docs/operations/secret-scan.md`). Two gaps remained in every mode:

- gitleaks' default configuration (`[extend] useDefault = true`) carries a global allowlist of path regexes that skip
  whole files by extension: images `bmp|gif|jpe?g|png|svg|tiff?`, fonts `eot|[ot]tf|woff2?`, documents and binaries
  `docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|dll|pdb|exe|gltf`, and `\.gem$`; besides lock files, vendored
  directories and `gitleaks.toml` itself. `extend` only appends allowlists (`config.go`, `extend`:
  `c.Allowlists = append(c.Allowlists, extensionConfig.Allowlists...)`), so a repository configuration cannot remove
  an entry while it uses the default rules. A text file named `creds.bin` is never scanned.
- Archives are opened only with `--max-archive-depth` (default 0), and gitleaks identifies them by file name
  (`sources/file.go`: `archives.Identify(ctx, path, nil)`), not by content.

Measured on 2026-10-12 with the pinned gitleaks v8.30.1 in scratch directories: the repository's 76 tracked
png/svg/woff2 files scanned with the extension allowlist neutralised give 0 findings (1.4 MB, 254 ms); `creds.bin` and
`creds.png` holding a fake token are skipped, the same content under `creds.bin.scan` and `creds.pdf.scan` is found; a
file with PDF magic bytes and a clear-text token is skipped under any name, because gitleaks drops files whose magic
bytes map to an `application/*` MIME type, which no configuration changes; with depth 1, `.zip` and `.tar.gz`
archives are opened and `.jar`, `.docx`, `.xlsx` and extension-less archives are not; a `.docx` renamed to
`.docx.zip` is opened; a zip inside a zip needs depth 2.

## Options
- **Vendor the default configuration without the extension entries.** + Exact control. − About 2 500 generated lines
  to re-vendor at every image bump; the merge-base review of `.gitleaks.toml` (PDK-065) would have to read them.
- **Neutralise the extension allowlist by renaming the copies that `scan-secrets-diff` scans** (chosen). + Ten lines
  in the copy loops that already exist; no configuration change; measured zero false positives on the repository's
  own binary-extension files; the history scan is untouched. − A `.gitleaksignore` fingerprint or a path allowlist
  for such a file must name the renamed path.
- **Accept the gap and document it.** − The fix is cheap and the harness exists; a text secret under a binary
  extension is the demonstrated bypass of PDK-068.
- **Archives:** `--max-archive-depth 1` on the directory scan of `scan-secrets-diff` (chosen) versus depth 2
  (rejected: nested archives are no plausible accidental vector, and every level multiplies the decompression a pull
  request can impose on CI) versus leaving archives out of coverage (rejected: an office document or a zip with a
  pasted credential is a plausible accidental vector). Zip-family extensions gitleaks does not identify get the
  suffix `.zip` so that they are opened too.
- **Where:** PDK-071 (archives) is merged into PDK-069: same recipe, same copy loops, one rename rule with two
  suffixes, one test file.

## Decision
1. `scan-secrets-diff` renames every file it copies into a scan layer (layer 0 and the blob layers) whose name,
   case-insensitively, ends in one of the extensions of gitleaks' default global allowlist, so that the allowlist no
   longer matches: `.bmp .gif .jpg .jpeg .png .svg .tif .tiff .eot .otf .ttf .woff .woff2 .doc .docx .xls .xlsx .pdf
   .bin .socket .vsidx .v2 .suo .wsuo .dll .pdb .exe .gltf .gem` get the suffix `.scan`. The directory and lock-file
   entries of the default allowlist (`node_modules`, `package-lock.json`, `go.sum`, `vendor/`, and the like) stay
   allowlisted: they hold no hand-written content and are allowlisted for noise.
2. Zip-family files that gitleaks does not identify by name get the suffix `.zip` instead: `.jar .war .docx .xlsx
   .pptx .odt .ods .odp`. (`.docx` and `.xlsx` are in both lists; the `.zip` rule wins.)
3. The directory scan of `scan-secrets-diff` runs with `--max-archive-depth 1`. Archives inside archives are not
   opened; that is documented, not tested.
4. The history scan `scan-secrets` (git mode) is unchanged: git shows no binary patches and gitleaks cannot rename
   there. Its gaps — binary content, binary-extension files, archives — are the known gaps of PDK-070 and are
   acceptable only while `main` takes pull requests only.
5. The CI job `secrets` gets `timeout-minutes: 30`, so that an archive bomb or a huge archive in a pull request
   costs a bounded amount of CI time instead of the default six hours.
6. `docs/operations/secret-scan.md` states the coverage precisely: what the renamed scan catches, that files whose
   magic bytes map to `application/*` (real PDFs, fonts, executables, compressed data) are skipped by gitleaks in
   every mode, that only depth 1 is opened, and that a fingerprint or path allowlist for a renamed file names the
   path with its suffix (for example `creds.bin.scan:generic-api-key:1`).

## Consequences
+ The bypass of PDK-068 (`creds.bin`) and a credential inside a zip or an office document are caught in pull
  requests; the repository's own images and fonts stay clean, so no allowlist entry is needed.
− Two extension lists live in the Makefile and must be re-checked when the gitleaks image is bumped (the test cases
  pin `.bin`, `.png`, `.zip` and `.docx`). − Fingerprints for renamed files carry the suffix. − Real PDFs, fonts and
  executables remain out of coverage in every mode (gitleaks' magic-byte skip); a screenshot with a credential was
  never detectable by a regex scanner. − Decompression cost is bounded by the job timeout, not by gitleaks.
Re-evaluate when gitleaks offers a way to drop entries of the default global allowlist or identifies archives by
content; then the renaming goes away.
