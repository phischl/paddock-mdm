# 0027 — Secret scan: `AND` allowlists with `paths` must be rule-targeted
Status: Accepted (2026-10-12)

## Context
`make scan-secrets-diff` runs gitleaks in directory mode (`gitleaks dir`) over the files a pull request changes and
the blobs it adds (ADR 0025, ADR 0026); `make scan-secrets` runs it in git mode over the history. The repository's
`.gitleaks.toml` uses allowlists with `condition = "AND"` that bind a path to the exact shape of the allowed value
(a hex digest in `vendored.json`, a UUID in the Authentik fixtures, and so on). PDK-078's reviews found that
directory mode skips a file whose path such an allowlist matches without looking at the allowlist's regexes, while
git mode reports the finding; PDK-085 was opened to decide how the diff scan covers those files.

Measured on 2026-10-12 with the pinned image `zricethezav/gitleaks:v8.30.1` (source of the tag read alongside):

- **Root cause.** `sources/common.go` `shouldSkipPath` is a path-only pre-filter that directory mode
  (`sources/files.go`) applies to every directory and file before reading it: it iterates the global allowlists
  (`cfg.Allowlists`) and skips on `a.PathAllowed(path)` alone, ignoring `condition`, `regexes` and `commits`. The
  detector (`detect/detect.go` `checkCommitOrPathAllowed`, `checkFindingAllowed`) evaluates `AND` correctly, but the
  file never reaches it. Git mode has no such pre-filter (`sources/git.go` filters allowed commits only), which is why
  the two scans disagree. Upstream knows: pull request gitleaks/gitleaks#2227 ("don't skip files on path match when
  allowlist condition is AND", opened 2026-08-01) fixes exactly this line and is unmerged; no released version
  contains it.
- **Rule-targeted allowlists are not global.** `config/config.go` adds an allowlist with `targetRules` to the named
  rules (`rule.Allowlists`) and not to `cfg.Allowlists`, so the pre-filter never sees it, and the detector evaluates
  it per rule with full `AND` semantics. gitleaks validates every target rule ID after `extend`, so an unknown ID
  fails loudly.
- **Probe, bare `gitleaks dir`.** Allowlist `condition = "AND"`, `paths = ['''^gen/''']`,
  `regexes = ['''^[0-9a-f]{64}$''']`, `regexTarget = "secret"`; a fake `ghp_` token in `gen/creds.env` and in
  `elsewhere/creds.env`. Without `targetRules`: directory mode reports only `elsewhere/creds.env` and logs
  `skipping file: global allowlist path=gen/creds.env`; git mode reports both. With
  `targetRules = ["generic-api-key"]` added: directory mode reports both. An `OR` allowlist with the same `paths`
  skips `gen/` too, which is correct: in `OR` the path alone allows the finding in every mode.
- **The repository's configuration is not affected.** Every `AND` allowlist in `.gitleaks.toml` carries
  `targetRules = ["generic-api-key"]`. With that file as the merge-base configuration and PDK-078's generated child,
  `make scan-secrets-diff` over a pull request that adds a `ghp_` token and an `api_key` value to
  `server/web/src/assets/vendored.json` and a `ghp_` token to `test/system/autoinstall.go` fails with three findings
  per layer, and a pull request that adds only a 64-hex digest and the `id_ed25519.pub` file name passes. The premise
  of PDK-085 that the files behind the repository's `AND` allowlists are never scanned does not hold; it holds for the
  review probe of PDK-078 and for the `multi-line-basic` case of `test/scan-secrets_test.sh`, both `AND` allowlists
  without `targetRules`, which is why the suite keeps its accepted cases away from the diff scan today.

So the gap is: a global `AND` allowlist with `paths` (no `targetRules`) is accepted by the generated configuration
(ADR 0026, amendment 2026-10-12) and silently turns into a path-only skip in the diff scan. That is a construct that
acts differently than it reads, the class the amendment refuses.

## Options
- **Refuse `condition = "AND"` with `paths` unless `targetRules` is set** (chosen). + A few lines in the existing
  whitelist of `deploy/compose/scripts/gitleaks-child-config.py`; the construct that fails open cannot reach gitleaks;
  the repository's configuration already complies; rule-targeted `AND` allowlists are evaluated with full `AND`
  semantics in both modes, measured. − An author who wants an `AND` allowlist across all rules has to list the rules;
  for a repository that allowlists specific false positives that is the precise form anyway.
- **Scan the files behind `AND` allowlists a second time with a configuration whose `AND` allowlists drop their
  `paths`.** + Keeps global `AND` allowlists usable. − The recipe would have to select those files with gitleaks'
  regex semantics (another Go helper or a gitleaks dry run), generate and canary a second configuration, run every
  layer twice, and keep fingerprints and the `^(b/)?` anchors consistent across both passes; a large addition to a
  recipe whose last four reviews showed how hard it is to get right, for a construct the repository does not use.
- **Convert the `AND` allowlists to `.gitleaksignore` fingerprints.** − Fingerprints are commit-bound in git mode and
  line-bound in directory mode; the repository moved these very entries from fingerprints to content-bound allowlists
  on 2026-10-11 because history rewrites and branch scans broke them. Also unnecessary: the allowlists work.
- **Document the gap and wait for upstream.** − Leaves a construct in the whitelist that fails open without an
  error; upstream's fix has been open since 2026-08-01 with no release date. Documentation alone is not a control.
- **Carry upstream's patch in a self-built image.** − A new build pipeline and image for a one-line fix; the digest
  pin and the sha256-pinned default configuration would have to be re-derived; rejected as disproportionate.

## Decision
1. The generated configuration refuses an allowlist that has `condition = "AND"` and a `paths` key unless it also
   has a non-empty `targetRules` list. The refusal happens in `deploy/compose/scripts/gitleaks-child-config.py`
   before gitleaks runs, in both `make scan-secrets` and `make scan-secrets-diff`, with a message naming the
   allowlist and this ADR. An empty `targetRules = []` counts as absent, because gitleaks treats it as global.
2. Nothing else changes: no second scan pass, no fingerprint conversion, no change to the Makefile recipes, no change
   to the canary (it guards the structure of the generated configuration; this rule guards one construct and is
   covered by the regression test, which the image bump procedure runs).
3. `test/scan-secrets_test.sh` proves the rule in both scans: a global `AND` allowlist with `paths` (with regexes,
   with commits, with `paths` only, with `targetRules = []`) is refused before gitleaks runs; a rule-targeted `AND`
   allowlist reports a token under its path in both scans, allows a value that matches its regexes, and reports a
   value of the targeted rule that does not. The accepted cases of the suite run through both scans again.
4. `docs/operations/secret-scan.md` names the rule among the constructs the scan refuses and states the reason (the
   directory scan's path-only pre-filter, upstream gitleaks/gitleaks#2227).

## Consequences
+ A token in a file behind an `AND` allowlist whose regexes it does not match fails `make scan-secrets-diff` for every
  configuration the scan accepts; the repository's `.gitleaks.toml` passes unchanged.
+ The rule is cheap to keep after upstream merges #2227: a rule-targeted allowlist is the precise form of a
  false-positive allowlist, so the restriction costs nothing and may stay. Re-evaluate at the image bump that first
  contains the fix; relaxing the rule then is optional.
− The whitelist carries one more rule that mirrors a gitleaks internal; the regression test pins it, so a future
  version that treats rule-targeted allowlists as global would fail the suite, not the scan.
Follow-up: the implementation ticket PDK-085, after PDK-078 is merged (the whitelist and the test suite it changes
come from PDK-078) and before PDK-072 (which edits the same test suite).
