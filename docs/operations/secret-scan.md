# Secret scan

The CI job `secrets` runs gitleaks on every pull request and on every push to `main`. Locally, `make scan-secrets`
scans the history of the current branch and `make scan-secrets-diff` the files changed and the blobs added since
`origin/main`. Both run the same generated configuration (see [The scan configuration](#the-scan-configuration)).

## What a pull request is scanned with

- `make scan-secrets` scans the pull request's own commits, merge commits included (`--remerge-diff`, PDK-057).
- `make scan-secrets-diff` scans the final content of every file the pull request changes and every blob the pull
  request adds, also versions a later commit replaced or removed (PDK-068). The history scan skips binary content, so
  a binary file with a secret that the pull request adds and deletes again is caught here. A file over 100 MB fails
  the scan instead of being skipped. It also opens archives one level deep (see
  [Archives and binary content](#archives-and-binary-content)).
- Both read `.gitleaks.toml` and `.gitleaksignore` from the pull request's merge base (`GITLEAKS_CONFIG_REF`, PDK-065).
  A pull request that changes either file is scanned with the base's version. An allowlist for a new false positive
  therefore lands in its own pull request first, and the pull request with the flagged content follows once it is
  merged.
- A `.gitleaksignore` in the scanned tree is never loaded, inline `gitleaks:allow` comments are ignored, and a
  `.gitleaks.toml` that extends another file (`[extend] path`) fails the scan; `useDefault` alone is allowed.
- `.gitleaks.toml` is parsed, not copied (ADR 0026, amendment 2026-10-12). The scan fails before gitleaks reads any
  pull request content when the file holds anything but `title`, `[extend]` with exactly `useDefault = true`, and
  `[[allowlists]]` with `description`, `condition` (`"AND"`/`"OR"`), `paths`, `regexes`, `commits`, `targetRules`
  and `regexTarget` (`"match"`/`"secret"`/`"line"`). Names compare exactly, so `[Extend]`, `disabledRules` or an
  unknown key fail. To silence a rule, write an allowlist.
- The scan also refuses allowlists that act differently than they read: a `paths` or `regexes` entry that is empty,
  matches the empty string (`""`, `^.*$`, `a*`) or that Python's `re` cannot compile (RE2-only constructs such as
  `\pL`; write the pattern without them), an empty `paths` or `regexes` list, and `stopwords`, which gitleaks matches
  as case-insensitive substrings of the secret (`"kia"` silences AWS access keys). What an allowlist means stays the
  code owners' review: broad patterns that do not match the empty string, such as `.` or `[\s\S]`, pass the tool,
  and a reviewer reads them as "everything".

## The scan configuration

gitleaks' default configuration has a global allowlist whose path entries skip whole files and directories in every
scan mode: names such as `src/bootstrap.js`, `javascript.json`, `d.png/creds.bin`, `node_modules/` or anything below a
directory named like a lock file. A repository configuration that extends the default (`useDefault`) cannot drop those
entries. Both scans therefore run a configuration generated for each run (ADR 0026):

1. The default configuration is copied out of the gitleaks binary of `GITLEAKS_IMAGE`, which embeds it unchanged: the
   recipe finds the single line `# This file has been auto-generated. Do not edit manually.` and takes
   `GITLEAKS_DEFAULT_CONFIG_BYTES` bytes from there.
2. Their sha256 must equal `GITLEAKS_DEFAULT_CONFIG_SHA256`. Both pins live in `deploy/compose/versions.env` next to
   `GITLEAKS_IMAGE` and are the size and sha256 of `config/gitleaks.toml` at the image's tag. A header that is missing
   or occurs more than once, or a mismatch, fails the scan with a message naming the two pins.
3. The `paths` of the global `[allowlist]` are removed; its `regexes` and `stopwords` and every rule with its own
   allowlists stay. If a `paths` key is still left before the first `[[rules]]`, also as a dotted key or in an inline
   table, the scan fails: the default's layout changed and needs a look. A parser checks this, and that the
   stripped default still has rules.
4. The repository's `.gitleaks.toml` (from the merge base, see above) is parsed with Python's `tomllib` (Python 3.11
   or later), checked against the whitelist above and written out as a child configuration whose `[extend]` table
   points at the stripped default (`[extend] path`). The file in the repository keeps `useDefault = true`, so a
   plain `gitleaks` call and editor plugins behave as before.
5. A canary run of the generated configuration must report a fake token, generated per run and never printed, under
   `node_modules/` and `vendor/github.com/`, names the default skipped. Otherwise the scan fails with "the generated
   configuration lost its rules or path coverage".

Every file is therefore scanned by content, under its own path, apart from the magic-byte skip below and the
repository's own allowlists. Among those, `.gitleaks.toml` skips two kinds of generated lock files by exact path:
every `go.sum` and `server/web/package-lock.json`, whose hashes are not secrets. A reviewer treats a change to these
files as not scanned; an unusual change to them (anything but module or package hashes) is a reason to ask why.

### Bumping the gitleaks image

An image bump changes three lines of `deploy/compose/versions.env` together, in one pull request:

1. `GITLEAKS_IMAGE`: the new tag and its digest.
2. `GITLEAKS_DEFAULT_CONFIG_BYTES`: the size in bytes of `config/gitleaks.toml` at the new tag of
   `github.com/gitleaks/gitleaks` (`wc -c config/gitleaks.toml`).
3. `GITLEAKS_DEFAULT_CONFIG_SHA256`: its sha256 (`sha256sum config/gitleaks.toml`).

Then run `make scan-secrets` and `make test` (the regression test `test/scan-secrets_test.sh`). A scan that fails with
the pins named means the image does not hold that file as expected: compare the file of the tag with the binary
before changing anything else. Also check the archive formats of the new version against `GITLEAKS_ZIP_EXT` in the
`Makefile` and new path entries of the default against the findings of the first scans.

## Archives and binary content

- gitleaks recognises archives by name only. A file ending in `.jar .war .docx .xlsx .pptx .odt .ods .odp` is scanned
  with the suffix `.zip`, so that it is opened as an archive, and a file ending in `.tgz` with the suffix `.tar.gz`
  (`make scan-secrets-diff` only). These two rules apply to the file name only, not to directories. Archives that
  gitleaks recognises by name, such as `.zip` and `.tar.gz`, keep their name; archives under any other name (for
  example `.7z` renamed to `.dat`, or without an extension) are not opened. No other file is renamed.
- Archives are opened one level deep (`--max-archive-depth 1`): a secret in a file inside a zip, an office document
  or a gzipped tar is found, an archive inside an archive is not opened. The CI job `secrets` stops after 30 minutes,
  which bounds what a huge archive or an archive bomb costs.
- A changed file whose archive copy would overwrite another changed file (for example `creds.docx` and
  `creds.docx.zip` in one pull request) fails the scan with `cannot write a changed file`.
- gitleaks skips every file whose magic bytes map to an `application/*` type, whatever its name and in every scan mode:
  real PDFs, fonts, executables and compressed data are never scanned. Images are scanned; the repository's own icons
  and fonts give no findings.
- Findings, `.gitleaksignore` fingerprints and path allowlists name a file by its own path and an archive by its
  suffixed name, with a file inside it after a `!`, for example `assets/creds.bin:github-pat:1` or
  `creds.docx.zip!word/document.xml:generic-api-key:1`.
- The history scan `make scan-secrets` (git mode) opens no archives and sees no binary content (git shows no binary
  patches); text under any name, binary extensions included, is covered by both scans.

## What the scan relies on

A pull request runs its own `.github/workflows/ci.yml`, `Makefile` (including `deploy/compose/versions.env`, which the
Makefile reads as make syntax and which pins the gitleaks image and its default configuration) and scripts. It can
therefore change how it is scanned, or skip the scan, and no setting inside the repository prevents that. The scan's
integrity rests on code review of `.github/`, the `Makefile`, `deploy/compose/versions.env` and
`deploy/compose/scripts/`.

`.github/CODEOWNERS` names a reviewer for these paths and for `.gitleaks.toml` and `.gitleaksignore`. GitHub enforces
code owners only once branch protection (or a ruleset) on `main` requires a review from code owners; that is a setting
of the maintainer. Recommended for `main`:

- require a pull request with an approving review from code owners;
- require the status checks `secrets` (and the other CI jobs) to pass before merging.

Until those settings are on, a reviewer has to check every change to the paths above by hand.

A direct push to `main` bypasses the pull request scans: only the history scan sees it, and the history scan sees no
binary content and opens no archives (git shows no binary patches). There is no periodic blob scan of `main` to make
up for that (ADR 0026); the gap is closed by the branch protection above, which makes every change to `main` a pull
request.
