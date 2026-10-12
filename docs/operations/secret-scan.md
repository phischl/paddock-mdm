# Secret scan

The CI job `secrets` runs gitleaks on every pull request and on every push to `main`. Locally, `make scan-secrets`
scans the history of the current branch and `make scan-secrets-diff` the files changed and the blobs added since
`origin/main`.

## What a pull request is scanned with

- `make scan-secrets` scans the pull request's own commits, merge commits included (`--remerge-diff`, PDK-057).
- `make scan-secrets-diff` scans the final content of every file the pull request changes and every blob the pull
  request adds, also versions a later commit replaced or removed (PDK-068). The history scan skips binary content, so
  a binary file with a secret that the pull request adds and deletes again is caught here. A file over 100 MB fails
  the scan instead of being skipped. It also covers files under binary extensions and archives one level deep (see
  [Coverage of binary extensions and archives](#coverage-of-binary-extensions-and-archives)).
- Both read `.gitleaks.toml` and `.gitleaksignore` from the pull request's merge base (`GITLEAKS_CONFIG_REF`, PDK-065).
  A pull request that changes either file is scanned with the base's version. An allowlist for a new false positive
  therefore lands in its own pull request first, and the pull request with the flagged content follows once it is
  merged.
- A `.gitleaksignore` in the scanned tree is never loaded, inline `gitleaks:allow` comments are ignored, and a
  `.gitleaks.toml` that extends another file (`[extend] path`) fails the scan; `useDefault` alone is allowed.

## Coverage of binary extensions and archives

gitleaks' default configuration (`useDefault`) skips whole files and whole directories by extension, and a repository
configuration cannot remove those entries (ADR 0025). `make scan-secrets-diff` therefore scans copies under other
names:

- Every path component, directories included, whose name ends, case-insensitively, in `.bmp .gif .jpg .jpeg .png .svg
  .tif .tiff .eot .otf .ttf .woff .woff2 .doc .docx .xls .xlsx .pdf .bin .socket .vsidx .v2 .suo .wsuo .pdb .exe
  .gltf .gem`, or in any one character followed by `dll`, gets the suffix `.scan`: `creds.bin` is scanned as
  `creds.bin.scan` and `assets.png/creds.bin` as `assets.png.scan/creds.bin.scan`. (The default configuration's
  `.dll` entry has an unescaped dot, so it skips `creds.xdll` but not `creds.dll`; the rename mirrors that.) The
  file is then scanned like any other text file, subject to the magic-byte skip below.
- gitleaks recognises archives by name only. A file ending in `.jar .war .docx .xlsx .pptx .odt .ods .odp` is scanned
  with the suffix `.zip` instead, so that it is opened as an archive (for `.docx` and `.xlsx` the `.zip` rule wins),
  and a file ending in `.tgz` with the suffix `.tar.gz`. These two rules apply to the file name only, not to
  directories. Archives that gitleaks recognises by name, such as `.zip` and `.tar.gz`, keep their name; archives
  under any other name (for example `.7z` renamed to `.dat`, or without an extension) are not opened.
- Archives are opened one level deep (`--max-archive-depth 1`): a secret in a file inside a zip, an office document
  or a gzipped tar is found, an archive inside an archive is not opened. The CI job `secrets` stops after 30 minutes,
  which bounds what a huge archive or an archive bomb costs.
- A changed file whose renamed copy would overwrite another changed file (for example `creds.bin` and
  `creds.bin.scan` in one pull request) fails the scan with `cannot write a changed file`.
- The directory and lock-file entries of the default configuration (`node_modules`, `vendor/`, `package-lock.json`,
  `go.sum` and the like) stay skipped.
- gitleaks skips every file whose magic bytes map to an `application/*` type, whatever its name and in every scan mode:
  real PDFs, fonts, executables and compressed data are never scanned. Images are scanned; the repository's own icons
  and fonts give no findings.
- Findings, `.gitleaksignore` fingerprints and path allowlists name the renamed path, with the suffix on every renamed
  component, and a file inside an archive after a `!`, for example `creds.bin.scan:github-pat:1`,
  `assets.png.scan/creds.bin.scan:github-pat:1` or
  `creds.docx.zip!word/document.xml:generic-api-key:1`.
- The history scan `make scan-secrets` (git mode) renames nothing and opens no archives: binary content,
  binary-extension files and archives are covered by `make scan-secrets-diff` only.

The two extension lists live in the `Makefile` (`GITLEAKS_RENAME_EXT`, `GITLEAKS_ZIP_EXT`) and are re-checked against
gitleaks' default configuration whenever the gitleaks image is bumped.

## What the scan relies on

A pull request runs its own `.github/workflows/ci.yml`, `Makefile` (including `deploy/compose/versions.env`, which the
Makefile reads as make syntax and which pins the gitleaks image) and scripts. It can therefore change how it is
scanned, or skip the scan, and no setting inside the repository prevents that. The scan's integrity rests on code
review of `.github/`, the `Makefile`, `deploy/compose/versions.env` and `deploy/compose/scripts/`.

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
