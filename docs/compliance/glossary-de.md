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
| Attention pill (app bar) | „{n} brauchen Aufmerksamkeit“ | Plural through ICU (*1 braucht Aufmerksamkeit*). |
| Audit log | Audit-Protokoll | |
| Auditor | Auditor | |
| Boot PIN | Boot-PIN | |
| Break-glass account | Notfallkonto | |
| Bundle | Bundle | Signed configuration of a device. |
| Change set | Änderungssatz | declarative configuration (paddockctl) |
| Check-in | Check-in | |
| Command palette | Befehlspalette | |
| Configuration (navigation group) | Konfiguration | |
| Danger zone | Gefahrenbereich | Lock, Destroy and Retire on the device page. |
| Dead man's switch | Totmannschalter | Its period is the *Frist*. |
| Denied path | Gesperrter Pfad | Managed files on it are refused and not shipped. |
| Density | Dichte (Kompakt / Komfortabel) | |
| Destroy (revocation) | Vernichtung; Gerät vernichten | Irreversible: erases every keyslot and the escrow. |
| Device | Gerät | |
| Device group | Gerätegruppe | |
| Device lock (Lock revocation) | Sperre; Gerät sperren | *Gerätesperre* where it must be told apart from a user lock. |
| Disk encryption | Festplattenverschlüsselung | |
| Encrypted / Not encrypted / Partial | Verschlüsselt / Nicht verschlüsselt / Teilweise | Disk encryption chips. |
| Enroll, enrollment | Registrieren, Registrierung | |
| Enrollment token | Registrierungstoken | |
| Escrow; escrowed | Treuhand-Ablage; in der Treuhand-Ablage hinterlegt (kurz: hinterlegt) | Recovery keys, LUKS headers, local administrator passwords. |
| Finding (vulnerability) | Fund | a CVE matched on a device |
| Hold (package) | Zurückhalten; zurückgehaltenes Paket | Not *Sperre*, which is reserved for locks. |
| Install now | Sofort installieren; Sofortinstallation | |
| Inventory (navigation group) | Inventar | |
| Issue (revocation) | Ausstellen | The revocation issuer is the *Widerrufsaussteller*. |
| Keyboard shortcut | Tastenkürzel | |
| Local administrator | Lokaler Administrator | |
| Managed file / unit | Verwaltete Datei / Unit | |
| Navigation | Navigation | Navigation drawer; *einblenden* / *ausblenden* to show or hide it. |
| Never contacted | Nie verbunden | |
| Not reported | Nicht gemeldet | |
| Online | Online | |
| Organization | Organisation | |
| Operator root (managed files) | Operator-Wurzel | Directory below which operators manage files without a step-up. |
| Organization administrator | Organisationsadministrator | |
| Overview (navigation group) | Übersicht | |
| Overview (page) | Übersicht | The start page of administrators and operators. |
| Permission profile | Berechtigungsprofil | Classes: Keine, Eingeschränkt, Voll. |
| Platform (navigation group) | Plattform | |
| Platform administrator | Plattformadministrator | |
| Presumed lost | Vermutlich verloren | |
| Quarantine | Quarantäne | |
| Reboot required | Neustart erforderlich | |
| Recovery key | Wiederherstellungsschlüssel | |
| Reject | Ablehnen | |
| Restore (backup) | Wiederherstellung | restore drill: *Wiederherstellungsprobe* |
| Retire | Außer Betrieb nehmen | |
| Reveal (password, key) | Anzeigen | Every reveal is audited. |
| Revocation (Lock, Destroy, self-lock) | Widerruf | Page *Widerrufe*. |
| Rollout, wave | Rollout, Welle | |
| Root grant | Root-Berechtigung | A permission profile that is effectively Full. |
| Root-equivalent | root-gleichwertig | |
| Rotate (password) | Rotieren; Rotation | |
| Security (navigation group) | Sicherheit | |
| Security review | Sicherheitsprüfung | Review of root grants and files on sensitive or denied paths. |
| Security updates overdue | Sicherheitsupdates überfällig | |
| Sensitive path | Sensibler Pfad | Managed files on it need an organization administrator with a step-up. |
| Session (portal) | Sitzung | |
| Self-lock (dead man's switch) | Selbstsperre | |
| Severity | Schweregrad | Kritisch, Hoch, Mittel, Niedrig, Unbekannt. |
| Sign in / sign out | Anmelden / Abmelden | |
| Silent (contact chip) | Ohne Kontakt | |
| Silent device (staleness) | Gerät ohne Kontakt | |
| Start (page) | Start | |
| Step-up | Identitätsbestätigung | |
| Suspend / resume logins | Anmeldungen aussetzen / wieder zulassen | |
| Synced (user), upstream directory | Synchronisiert, Quellverzeichnis | |
| Tamper (event) | Manipulation | |
| Theme | Erscheinungsbild (System / Hell / Dunkel) | |
| User lock | Sperre; Benutzer sperren / entsperren | *Benutzersperre* where it must be told apart from a device lock. |
| User menu | Benutzermenü | |
| Volume (LUKS) | Volume | kept in English, as in cryptsetup |
| Vulnerability | Schwachstelle | |
