- Alerts that read a gauge only one role sets no longer fire permanently or stay silent through the default value of
  the other roles. Every role served the metrics of the worker and the audit writer at their default (for example
  `paddock_openbao_reachable` at 0), so `PaddockOpenBaoUnreachable`, `PaddockAuditVerifyStale` and
  `PaddockAuditIndexPurgeStale` fired with one instance per role. The worker and the audit writer now register their
  metrics only in their own role, and the alerts select the owning role (`role="paddock-worker"`,
  `role="paddock-audit-writer"`), as do `PaddockAutoUnsealWithdrawn`, `PaddockAutoUnsealerDown` and
  `PaddockOpenBaoHealthMissing`. Metric names and meanings are unchanged.
