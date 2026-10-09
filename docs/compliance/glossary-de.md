# German glossary of the portal

The German catalog `server/web/src/locales/de.json` (plan M6b decision 2) uses exactly these terms. A new message
uses the term from this table; a new term is added here in the same change. Audit events are stored with their
English codes and parameters and only displayed in German (`audit.<code>`).

Conventions: formal address (*Sie*); German quotation marks („…“); numbers, dates and plurals through ICU and
`Intl` (`1.234`, `50 %`); product and protocol names stay English (Bundle, Check-in, Rollout, Keyslot, Header,
Unit, Slug, Token, sudo, LUKS, TPM, CVE, CVSS). Values that the API returns as identifiers (for example the
schedule weekdays `Mon … Sun`) stay as the API expects them.

| English | German | Note |
| --- | --- | --- |
| Agent release | Agent-Release | |
| API token | API-Token | neuter: *das* API-Token |
| Approve (device, Destroy) | Freigeben | Freigabe |
| Attention (page) | Handlungsbedarf | One row is a *Befund* (open condition). |
| Audit log | Audit-Protokoll | |
| Auditor | Auditor | |
| Boot PIN | Boot-PIN | |
| Break-glass account | Notfallkonto | |
| Bundle | Bundle | Signed configuration of a device. |
| Change set | Änderungssatz | declarative configuration (paddockctl) |
| Check-in | Check-in | |
| Configuration (navigation group) | Konfiguration | |
| Dead man's switch | Totmannschalter | Its period is the *Frist*. |
| Destroy (revocation) | Vernichtung; Gerät vernichten | Irreversible: erases every keyslot and the escrow. |
| Device | Gerät | |
| Device group | Gerätegruppe | |
| Device lock (Lock revocation) | Sperre; Gerät sperren | *Gerätesperre* where it must be told apart from a user lock. |
| Disk encryption | Festplattenverschlüsselung | |
| Enroll, enrollment | Registrieren, Registrierung | |
| Enrollment token | Registrierungstoken | |
| Escrow; escrowed | Treuhand-Ablage; in der Treuhand-Ablage hinterlegt (kurz: hinterlegt) | Recovery keys, LUKS headers, local administrator passwords. |
| Finding (vulnerability) | Fund | a CVE matched on a device |
| Hold (package) | Zurückhalten; zurückgehaltenes Paket | Not *Sperre*, which is reserved for locks. |
| Install now | Sofort installieren; Sofortinstallation | |
| Inventory (navigation group) | Inventar | |
| Issue (revocation) | Ausstellen | The revocation issuer is the *Widerrufsaussteller*. |
| Local administrator | Lokaler Administrator | |
| Managed file / unit | Verwaltete Datei / Unit | |
| Navigation | Navigation | Navigation drawer; *einklappen* / *ausklappen* for the rail. |
| Organization | Organisation | |
| Organization administrator | Organisationsadministrator | |
| Overview (navigation group) | Übersicht | |
| Permission profile | Berechtigungsprofil | Classes: Keine, Eingeschränkt, Voll. |
| Platform (navigation group) | Plattform | |
| Platform administrator | Plattformadministrator | |
| Presumed lost | Vermutlich verloren | |
| Quarantine | Quarantäne | |
| Recovery key | Wiederherstellungsschlüssel | |
| Reject | Ablehnen | |
| Restore (backup) | Wiederherstellung | restore drill: *Wiederherstellungsprobe* |
| Retire | Außer Betrieb nehmen | |
| Reveal (password, key) | Anzeigen | Every reveal is audited. |
| Revocation (Lock, Destroy, self-lock) | Widerruf | Page *Widerrufe*. |
| Rollout, wave | Rollout, Welle | |
| Root-equivalent | root-gleichwertig | |
| Rotate (password) | Rotieren; Rotation | |
| Security (navigation group) | Sicherheit | |
| Self-lock (dead man's switch) | Selbstsperre | |
| Severity | Schweregrad | Kritisch, Hoch, Mittel, Niedrig, Unbekannt. |
| Sign in / sign out | Anmelden / Abmelden | |
| Silent device (staleness) | Gerät ohne Kontakt | |
| Start (page) | Start | |
| Step-up | Identitätsbestätigung | |
| Suspend / resume logins | Anmeldungen aussetzen / wieder zulassen | |
| Synced (user), upstream directory | Synchronisiert, Quellverzeichnis | |
| Tamper (event) | Manipulation | |
| User lock | Sperre; Benutzer sperren / entsperren | *Benutzersperre* where it must be told apart from a device lock. |
| User menu | Benutzermenü | |
| Volume (LUKS) | Volume | kept in English, as in cryptsetup |
| Vulnerability | Schwachstelle | |
