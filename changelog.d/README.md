# Changelog fragments

Every change with an effect that users, operators or integrators can see adds its `CHANGELOG.md` entry here as a
fragment file instead of editing `CHANGELOG.md`. Parallel pull requests then never conflict on the `[Unreleased]`
section. The release manager assembles the fragments into the release section with `make changelog` (see
`docs/operations/agent-releases.md`, *Server release*).

- **Name:** `<ticket-id>.<section>.md`, for example `PDK-518.changed.md`. A change without a ticket id uses a short
  lower-case slug instead, for example `deps-go-patch.security.md` for a Dependabot bump.
- **Section:** one of `added`, `changed`, `deprecated`, `removed`, `fixed`, `security` (lower case). A change with
  entries in two sections adds two files.
- **Content:** the Keep a Changelog bullet(s) in English, exactly as they will appear in `CHANGELOG.md`: each entry
  starts with `- `, continuation lines are indented by two spaces, no headings.

`make changelog-check` (part of `make lint`) validates the fragments; `make changelog-preview` prints the section the
next release would get.
