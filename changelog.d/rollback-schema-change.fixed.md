- `./paddock rollback` no longer refuses every rollback after a release that changed the schema: the upgrade now
  records the schema versions of the pre-upgrade backup before its first `up`, and the rollback restores that point
  with them instead of the schema the new release's backups report; a rollback point without them is refused with a
  pointer to `./paddock restore`.
