# Compliance pack

Everything an auditor needs about Paddock in one place (plan M6b decision 5).

| Document | Answers |
| --- | --- |
| [iso27001-mapping.md](iso27001-mapping.md) | Which ISO/IEC 27001:2022 Annex A controls Paddock supports, the evidence (audit codes, WORM store, hash chain, `audit verify`) and the operator's duties |
| [residual-risks.md](residual-risks.md) | The risks Paddock leaves to the operator, with mitigations and what to record in the ISMS |
| [audit-codes.md](audit-codes.md) | Every audit event code with its meaning, parameters and outcomes (generated from the code) |
| [privacy.md](privacy.md) | What Paddock collects from devices and administrators, what it stores, and what it never collects |
| [third-party.md](third-party.md) | Licenses of linked dependencies, bundled services, published images, device software and build tools |
| [glossary-de.md](glossary-de.md) | The German terms of the portal |

Operational evidence lives in the runbooks: audit bucket and verification (`docs/operations/audit-bucket.md`),
production checks (`docs/operations/install.md`, `make prod-check`), backups and the restore drill
(`docs/operations/restore.md`), monitoring (`docs/operations/monitoring.md`), revocation acceptance
(`docs/operations/revocation-acceptance.md`) and capacity (`docs/operations/capacity.md`).
