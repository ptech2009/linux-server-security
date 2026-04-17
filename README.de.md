# Linux Server Security Script

**Version 3.0.7** · Interaktives Bash-Skript zur systematischen Absicherung von Debian/Ubuntu-Servern.

Automatisiert zahlreiche manuelle Konfigurationsschritte mit einem **Audit-First-Ansatz**: Das Skript prüft den aktuellen Zustand gegen Best Practices und fragt nur nach, wenn Probleme gefunden werden.

## 🔐 Funktionen

### SSH-Härtung & Schlüsselverwaltung
- Prüft und optimiert `sshd_config`-Einstellungen (`PasswordAuthentication`, `PermitRootLogin`, `AllowUsers`, `X11Forwarding`, etc.)
- Ed25519-Schlüsselpaar-Generierung mit automatischer `authorized_keys`-Einrichtung
- Konfigurationsvalidierung via `sshd -t` vor jedem Neustart — gibt reale Fehlerausgaben bei Fehlschlag aus
- Drop-in-Konfiguration via `/etc/ssh/sshd_config.d/` (modern, nicht-destruktiv)
- Erkennt Keyboard-Interactive/2FA `AuthenticationMethods` und deaktiviert keine erforderlichen Methoden
- `PermitRootLogin` wird in verwalteten Drop-ins auf `prohibit-password` normalisiert
- **SSH-Krypto-Richtlinienmodus** (`off` | `modern` | `fips-compatible` | `strict`) mit Validierung und Rollback bei Fehlschlag

### Google 2FA (Zwei-Faktor-Authentifizierung)
- Installiert und konfiguriert `libpam-google-authenticator`
- Interaktive Einrichtung mit QR-Code und Notfall-Scratch-Codes
- Automatische PAM- und SSHD-Konfiguration

### Fail2ban (Audit-Modus)
- **Automatisches Audit** bei Installation: prüft jail.local, [sshd]-Jail-Status, ignoreip-Whitelist, Dienststatus
- Erstellt minimale `jail.local` (keine Kopie der riesigen `jail.conf`)
- Konfigurationsvalidierung via `fail2ban-client -t` vor Neustart, mit Wiederherstellung bei Fehlschlag
- Automatisches Whitelisting lokaler Subnetze zur Vermeidung von Aussperrungen

### SSHGuard (Audit-Modus)
- **Automatisches Audit** bei Installation: prüft Whitelist-Vollständigkeit, Dienststatus
- IPv4/IPv6-Erkennung lokaler Subnetze und Whitelisting

### UFW Firewall (Audit-Modus)
- **Automatisches Audit** bei Installation: prüft aktiven Zustand, SSH-Port-Regel, nicht abgedeckte lauschende Ports
- Erkennt Host-Ports via `ss` und Container-Ports via Docker/Podman
- SSH-Vorfreischaltung vor UFW-Aktivierung zur Vermeidung von Aussperrungen
- Interaktive Port-für-Port-Überprüfung für nicht abgedeckte Dienste

### Sysctl-Kernel-Härtung (Audit-Modus)
- **Automatisches Audit** von 21 Kernel-/Netzwerkparametern gegen Best Practices
- Abdeckung: `rp_filter`, `accept_redirects`, `send_redirects`, `accept_source_route`, `log_martians`, `icmp_echo_ignore_broadcasts`, `tcp_syncookies`, `randomize_va_space`, `sysrq`, `protected_hardlinks/symlinks`
- Schreibt nach `/etc/sysctl.d/99-security-script.conf` (keine Änderung an `/etc/sysctl.conf`)

### Sudoers TTY-Ticket-Isolation (Audit-Modus)
- **Automatisches Audit**, ob `tty_tickets` aktiv ist
- Stellt sicher, dass sudo-Anmeldedaten pro Terminal gelten, nicht sitzungsübergreifend
- Validierung mit `visudo` vor der Anwendung

### Journald-Protokollbegrenzung (Audit-Modus)
- **Automatisches Audit** von `SystemMaxUse` gegen konfigurierten Zielwert (Standard: 1G)
- Fragt nur nach, wenn der Wert von der Empfehlung abweicht

### Login-Umask-Härtung
- **Systemweite Baseline-Härtung** via `/etc/login.defs`, `/etc/profile.d/` und systemd Drop-ins für System- und Benutzerdienste
- Konfiguriert `umask 027` auf allen drei Ebenen für vollständige Abdeckung
- Assessment validiert systemweite Umask-Abdeckung einschließlich systemd Drop-in-Präsenz
- Rollback stellt alle Umask Drop-ins inklusive systemd-Ziele vollständig wieder her

### SUID/SGID-Inventarisierung & Auditierung
- Erstellt beim ersten Lauf eine Baseline aller SUID/SGID-Binaries
- Tägliche Audit-only-Berichterstattung via Cron — keine automatischen Entfernungen
- Schreibt Inventar nach `/var/lib/security-script/suid_sgid_baseline.txt`
- Berichtet Unterschiede unter `/var/log/security-script-suid-sgid-report.log`

### ClamAV-Antivirensoftware
- Installiert `clamav` und `clamav-daemon` falls nicht vorhanden
- Führt initiales `freshclam`-Datenbankupdate durch
- Konfiguriert automatische Virendefinitions-Updates

### Unattended Upgrades
- Konfiguriert `unattended-upgrades` für automatische Sicherheits-Patches
- Richtet `Allowed-Origins`, Neustart-Zeitplan und E-Mail-Benachrichtigungen ein
- Validiert und korrigiert die periodische `20auto-upgrades`-Konfiguration

### PAM-Härtung
- Verwendet `pam-auth-update` (nativer Debian/Ubuntu-Mechanismus) — **kein rohes `sed` auf live PAM-Dateien**
- `pam_faillock` via `/etc/security/faillock.conf` (moderner, sicherer Ansatz)
- Passwortqualitätsdurchsetzung via `/etc/security/pwquality.conf`
- **Sudo-Smoke-Test nach jeder PAM-Änderung** — automatischer Rollback bei Fehlschlag

### auditd (Audit-Framework)
- Installiert und konfiguriert `auditd` für detaillierte Systemereignisaufzeichnung
- **Erweiterter STIG-Stil-Regelsatz** mit Abdeckung für Sitzungsdateien, Zeitänderungen, Berechtigungsänderungen, Hostnameänderungen, Shell-/Profil-Härtungsdateien, rsyslog, modprobe und GRUB
- Schreibt Regeln nach `/etc/audit/rules.d/99-security-script.rules`
- Gibt relevante Log-Speicherorte und Befehle nach der Einrichtung aus

### AIDE (Datei-Integritätsüberwachung)
- Erstellt eine Integritäts-Baseline wichtiger Systemdateien
- Lokale Ausschlüsse für volatile Container-/Log-Pfade zur Rauschreduzierung auf Live-Hosts
- Automatische tägliche Prüfung via Cron (`/etc/cron.daily/aide-check`)
- Robuste DB-Erkennung mit `nice`/`ionice`-Unterstützung und nicht-interaktiver Init mit Timeout
- Bevorzugt autogenerierte Konfiguration; Cron kann Fallback-Konfiguration ohne `update-aide.conf` aktualisieren

### AppArmor-Durchsetzung
- Schaltet alle geladenen AppArmor-Profile von Complain- in Enforce-Modus
- Erkennt korrekt teilweise entladene/Teardown-Zustände — keine falschen GRÜNEN Befunde
- Standardmäßig übersprungen auf Docker/Podman-Hosts, außer explizit erzwungen
- Auditiert und meldet Profile, die nicht sauber durchgesetzt werden können

### Dateisystem-Härtung
- Wendet sichere Mount-Optionen (`noexec`, `nosuid`, `nodev`) auf temporäre Dateisysteme an
- Reduziert das Risiko der Ausführung von Schadcode aus häufig genutzten Staging-Pfaden

### Kernel-Modul-Blacklisting
- Sperrt ungenutzte oder gefährliche Kernel-Module
- Schreibt nach `/etc/modprobe.d/security-script-blacklist.conf`

### Core-Dump-Beschränkungen
- Deaktiviert Core Dumps via `/etc/security/limits.d/` und `sysctl`
- Verhindert unkontrolliertes Schreiben sensibler Prozessdaten auf die Festplatte

### Login-Banner
- Konfiguriert SSH-Pre-Login-Banner (`/etc/issue.net`) mit rechtlichem/organisatorischem Hinweis
- Leert `/etc/motd` zur Vermeidung von Informationslecks

### MSMTP-E-Mail-Benachrichtigungen
- Interaktiver SMTP-Einrichtungsassistent (benutzer- oder systemweit)
- Unterstützt Host, Port, TLS, Anmeldedaten und Absenderkonfiguration
- Optionaler Test-E-Mail-Versand
- Sicherheitshinweis zur GPG/Secret-Tool-Passwortspeicherung

### Compliance-Katalog & Berichterstattung *(neu in v3.0.6)*
- **Stabile Check-IDs** und ein zentrales Schweregrad-Modell für jeden Härtungs-Check
- **Skript-verwalteter Compliance-Katalog** mit CIS/BSI/STIG-Zuordnungsfeldern
- Maschinenlesbarer Compliance-Bericht unter `/var/log/security-script/compliance_report.tsv`
- **On-Demand-Berichtsgenerierung** aus Log-Menü Option 11 — funktioniert auch ohne vorherigen Härtungslauf *(verbessert in v3.0.7)*
- **Optionaler E-Mail-Versand** des Compliance-Berichts via bestehender MSMTP-Konfiguration *(neu in v3.0.7)*
- **Exception-System** mit check-spezifischen Modi: `disable`, `warn`, `assessment-only`
- Governance-Dateien-Menü zum Anzeigen und Bearbeiten von Katalog und Exception-Definitionen

### Rollback-Aktionsbericht *(neu in v3.0.6)*
- Detaillierter Bericht nach jedem Rollback-Lauf
- Listet wiederhergestellte Elemente, Fehler, manuelle Prüfpunkte und erwartete ROTE Befunde auf
- Geschrieben nach `/var/log/security-script/rollback_report.log`

### Backup & Wiederherstellung
- Vor-Änderungs-Backups für jede geänderte Konfigurationsdatei
- `list_backups`: Zeigt alle Backups mit Zeitstempeln
- `restore_backup_interactive`: Nummeriertes Menü zur selektiven Wiederherstellung
- Interaktives Backup-Management am Skriptende

### Vollständiger Rollback
- Stellt alle gesicherten Konfigurationsdateien aus einem maschinenlesbaren **Transaktionslog** wieder her
- Entfernt vom Skript installierte Pakete
- Entsperrt Root-Account, falls vom Skript gesperrt
- Entfernt alle vom Skript hinzugefügten Dateien
- Stellt entfernte Cron-Jobs wieder her
- Läuft nicht-interaktiv und vollautomatisch
- Erstellt einen Rollback-Aktionsbericht mit wiederhergestellten Elementen und manuellen Prüfpunkten

### Selektive Entfernung
- Interaktives Erkennungs- und Auswahlmenü für installierte Komponenten
- `--remove ziel1,ziel2` CLI-Flag für geskriptete Nutzung

### Log-Viewer
- Eingebautes interaktives Log-Menü nach der Härtung zugänglich
- Zeigt nach jedem Lauf eine Zusammenfassung aller relevanten Log-Speicherorte
- Menüeinträge (0–11):

| # | Eintrag |
|---|---------|
| 1 | Sicherheits-Log-Zusammenfassung (alle relevanten Pfade auf einen Blick) |
| 2 | AIDE-Init-Log |
| 3 | AIDE-Prüf-Log |
| 4 | Neuester täglicher AIDE-Bericht |
| 5 | Fail2ban-Journal |
| 6 | Fail2ban-Status |
| 7 | auditd-Journal |
| 8 | auditd-Rohlog |
| 9 | Skript-Änderungslog |
| 10 | Transaktionslog |
| 11 | Compliance-Katalog, On-Demand-Bericht & E-Mail-Versand |

### Dry-Run-Modus
- Vorschau aller Änderungen ohne Systemmodifikation
- Aktivierung via: `sudo ./Linux-Server-Security-Script_v3_0_7.sh --dry-run`

---

## 🔄 Audit-Muster

Bereiche mit vorhandenen Installationen **überspringen die „X konfigurieren?"-Frage** und starten direkt mit dem Audit. Das Skript prüft jeden Aspekt und meldet:

```
INFO: 5a. Fail2ban — Audit & Konfiguration
SUCCESS: Fail2ban ist installiert.
INFO: Fail2ban-Konfiguration wird geprüft...
SUCCESS: jail.local vorhanden.
SUCCESS: Jail [sshd] ist aktiviert.
SUCCESS: Lokale Subnetze durch ignoreip abgedeckt.
SUCCESS: Fail2ban-Dienst ist aktiv.
SUCCESS: Fail2ban-Dienst ist aktiviert.
SUCCESS: Fail2ban-Audit: Alle Prüfungen bestanden.
```

Bei gefundenen Problemen lautet das Muster: **[Problem]** → **Empfehlung** → **Beheben?**

```
WARNING: [Problem] Jail [sshd] ist nicht aktiviert.
INFO:   Empfehlung: [sshd]-Jail aktivieren, um SSH gegen Brute-Force zu schützen.
  Beheben: [sshd]-Jail aktivieren? [J/n]:
```

Dies gilt für: Fail2ban, SSHGuard, UFW, Journald, Sysctl, Sudoers, AppArmor, AIDE, auditd, Dateisystem, PAM, Login-Banner, Login-Umask und SSH-Krypto-Richtlinie.

---

## 🚀 Installation & Verwendung

```bash
git clone https://github.com/ptech2009/linux-server-security.git
cd linux-server-security
chmod +x Linux-Server-Security-Script_v3_0_7.sh
sudo ./Linux-Server-Security-Script_v3_0_7.sh
```

### Startmenü

Beim Start wird einer von sieben Modi gewählt (verfügbar auf **Deutsch und Englisch**):

| # | Modus | Beschreibung |
|---|-------|--------------|
| 1 | Nur Assessment | Audit ohne Änderungen, Exit-Code 2 bei ROTEN Befunden |
| 2 | Empfohlene Härtung | Wendet Best-Practice-Standardeinstellungen automatisch an, inkl. Baseline-Fixes für echte ROTE Befunde |
| 3 | Schritt für Schritt | Prüft alle Bereiche einzeln durch |
| 4 | Vollautomatisch | Liest `security_config.env` |
| 5 | Vollständiger Rollback | Stellt Vor-Skript-Zustand ohne weitere Rückfragen wieder her |
| 6 | Selektive Entfernung | Erkennungs- und interaktives Auswahlmenü |
| 7 | Expertenmodus | Profilauswahl und Sonderfälle |

### CLI-Flags

```bash
# Vorschau ohne Änderungen
sudo ./Linux-Server-Security-Script_v3_0_7.sh --dry-run

# Nur Assessment (Exit-Code 2 bei verbleibenden ROTEN Befunden)
sudo ./Linux-Server-Security-Script_v3_0_7.sh --assess

# Vollständiger Rollback
sudo ./Linux-Server-Security-Script_v3_0_7.sh --rollback

# Selektive Entfernung
sudo ./Linux-Server-Security-Script_v3_0_7.sh --remove fail2ban,clamav

# Verifizierung nach Härtung (Exit-Code 2 bei verbleibenden ROTEN Befunden)
sudo ./Linux-Server-Security-Script_v3_0_7.sh --verify
```

### Voraussetzungen
- Debian/Ubuntu (getestet auf Ubuntu 24.04 LTS, Linux Mint 22)
- Bash 4+
- Root-Rechte

---

## ✨ Feature-Matrix

| Funktion | linux-server-security | captainzero93/linux-hardening | dev-sec/linux-baseline | openstack-ansible-security |
|:---------|:---------------------|:-----------------------------|:-----------------------|:---------------------------|
| Interaktive Benutzerführung | ✅ Ja | 🔶 Teilweise | ❌ Nein | ❌ Nein |
| Idempotent (sicher bei Mehrfachausführung) | ✅ Ja | 🔶 Teilweise | ✅ Ja | ✅ Ja |
| Audit-First-Muster | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| SSH-Härtung | ✅ Ja | ✅ Ja | ✅ Ja | ✅ Ja |
| SSH-Krypto-Richtlinie (inkl. Strict-Modus) | ✅ Ja | ❌ Nein | ❌ Nein | 🔶 Teilweise |
| Google 2FA-Integration | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| Sysctl-Härtung | ✅ Ja (`/etc/sysctl.d/`) | 🔶 Minimal | 🔶 Teilweise | ✅ Ja |
| Sudoers TTY-Tickets | ✅ Ja | ❌ Nein | ❌ Nein | 🔶 Teilweise |
| UFW-Firewall-Verwaltung | ✅ Ja | 🔶 Teilweise (iptables) | 🔶 Teilweise | ✅ Ja |
| Container-Port-Erkennung | ✅ Ja (Docker + Podman) | ❌ Nein | ❌ Nein | ❌ Nein |
| Unattended Upgrades | ✅ Ja | 🔶 Teilweise | ❌ Nein | ✅ Ja |
| Fail2ban + SSHGuard | ✅ Ja | ✅ Ja | ❌ Nein | ✅ Ja |
| ClamAV-Integration | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| PAM-Härtung (sicher, nativ) | ✅ Ja | ❌ Nein | 🔶 Teilweise | 🔶 Teilweise |
| auditd / Audit-Regeln (STIG-erweitert) | ✅ Ja | ❌ Nein | ✅ Ja | ✅ Ja |
| AIDE-Datei-Integrität | ✅ Ja | ❌ Nein | ✅ Ja | ❌ Nein |
| AppArmor-Durchsetzung | ✅ Ja | ❌ Nein | ❌ Nein | 🔶 Teilweise |
| Dateisystem-Härtung | ✅ Ja | ❌ Nein | 🔶 Teilweise | 🔶 Teilweise |
| Kernel-Modul-Blacklist | ✅ Ja | ❌ Nein | 🔶 Teilweise | 🔶 Teilweise |
| Core-Dump-Beschränkungen | ✅ Ja | ❌ Nein | ✅ Ja | 🔶 Teilweise |
| Login-Umask-Härtung (systemweit) | ✅ Ja | ❌ Nein | 🔶 Teilweise | 🔶 Teilweise |
| SUID/SGID-Inventarisierung & Audit | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| Login-Banner | ✅ Ja | ❌ Nein | ✅ Ja | ✅ Ja |
| Compliance-Katalog (CIS/BSI/STIG) | ✅ Ja | ❌ Nein | 🔶 Teilweise | 🔶 Teilweise |
| Exception-System (check-spezifische Modi) | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| Rollback-Aktionsbericht | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| Konfigurations-Backups & Wiederherstellung | ✅ Ja | ❌ Nein | ❌ Nein | 🔶 Teilweise |
| Vollständiger Rollback + Transaktionslog | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| Selektive Entfernung | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| Startmenü-Sprachauswahl (DE/EN) | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| Sudo-Smoke-Test + Auto-Rollback | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| Dry-Run-Modus | ✅ Ja | 🔶 Minimal | ❌ Nein | 🔶 Teilweise |
| Kein eval()-Einsatz | ✅ Ja | ❌ Verwendet eval | N/A (InSpec) | N/A (Ansible) |

---

## 🔒 Sicherheits- & Qualitätsverbesserungen in v3.0.7

- **Compliance-Bericht auf Abruf** — Log-Menü Option 11 generiert jetzt einen aktuellen Compliance-Bericht direkt aus dem Live-Systemzustand, auch ohne vorherigen Härtungs- oder Verify-Lauf
- **E-Mail-Versand für Compliance-Berichte** — der Compliance-Bericht kann jetzt direkt aus dem Log-Menü via bestehender MSMTP-Konfiguration versendet werden
- **Prompt- & UX-Fixes** — alle interaktiven Prompts im Compliance-Bericht- und MSMTP-Workflow erscheinen jetzt sofort ohne zusätzliche Enter-Eingabe; Prompts schreiben bei Bedarf direkt nach `/dev/tty`
- **MSMTP-Konfigurationsbehandlung korrigiert** — die `/etc/msmtprc`-Kopierbestätigung bleibt sichtbar, wenn die systemweite Konfiguration fehlt; der Laufzeit-Konfigurationspfad wird nach einer interaktiven Bestätigung nicht mehr überschrieben
- **PDF-Bericht-Workflow gehärtet** — die Verifizierung passwortgeschützter PDFs gelingt jetzt zuverlässig mit dem eingegebenen Passwort; `qpdf`-Kompatibilität für ältere Releases verbessert; `qpdf` kann bei Bedarf direkt aus dem Workflow heraus installiert werden
- **Übernommen aus v3.0.6**: Stabile Check-IDs, Compliance-Katalog, Exception-System, Rollback-Aktionsbericht, Governance-Dateien-Menü und alle vorherigen Härtungsfunktionen

---

## 📋 Changelog

### v3.0.7
- **NEU:** Log-Menü Option 11 generiert on-demand einen aktuellen Compliance-Bericht aus dem Live-Systemzustand
- **NEU:** Optionaler E-Mail-Versand des Compliance-Berichts via bestehender MSMTP-Konfiguration
- **VERBESSERT:** Compliance-Bericht-Workflow funktioniert auch ohne vorherigen Härtungs-/Verify-Lauf
- **BEHOBEN:** Verifizierung passwortgeschützter PDFs gelingt jetzt zuverlässig mit dem eingegebenen Passwort
- **BEHOBEN:** Compliance-Bericht-Mail-Workflow kompatibel mit älteren `qpdf`-Releases; `qpdf` kann bei Bedarf installiert werden
- **BEHOBEN:** Raw-TSV-Prompt wird sofort angezeigt ohne zusätzliche Enter-Eingabe
- **BEHOBEN:** `/etc/msmtprc`-Kopierbestätigung bleibt sichtbar, wenn die systemweite msmtp-Konfiguration fehlt
- **BEHOBEN:** msmtp-Konfigurationspfad wird nach interaktiver Bestätigung nicht mehr überschrieben

### v3.0.6
- **NEU:** Stabile Check-IDs und zentrales Schweregrad-Modell für alle Härtungs-Checks
- **NEU:** Skript-verwalteter Compliance-Katalog mit CIS/BSI/STIG-Zuordnungsfeldern und maschinenlesbarem TSV-Bericht
- **NEU:** Exception-System mit check-spezifischen Modi: `disable`, `warn`, `assessment-only`
- **NEU:** Governance-Dateien-Menü-Helfer (Log-Menü Option 11) zum Anzeigen/Bearbeiten von Katalog und Exception-Definitionen
- **NEU:** Rollback-Aktionsbericht mit wiederhergestellten Elementen, Fehlern, manuellen Prüfpunkten und erwarteten ROTEN Befunden

### v3.0.5
- **NEU:** `strict`-SSH-Krypto-Richtlinienmodus mit explizitem Ciphers/MACs/KEX-Pinning
- **VERBESSERT:** Umask-Härtung auf vollständige systemweite Baseline erweitert (login.defs + Shell-Hook + systemd Drop-ins)
- **VERBESSERT:** Assessment validiert systemweite Umask-Abdeckung und behandelt fehlendes SSH-Strict-Pinning als Befund
- **VERBESSERT:** Rollback stellt SSH-Strict-Krypto-Richtlinie und alle systemd Umask Drop-ins vollständig wieder her

### v3.0.4
- **VERBESSERT:** Empfohlener Modus bietet aktiv Baseline-Fixes für ROTE Befunde an (auditd, AIDE, Login-Umask, SUID/SGID-Baseline, SSH-Krypto-Richtlinie)
- **NEU:** SSH-Krypto-Richtlinienmodus (`off` | `modern` | `fips-compatible`) mit Konfigurationsvalidierung und Rollback
- **NEU:** Login-Umask-Härtung via `/etc/login.defs` und `/etc/profile.d/`
- **NEU:** SUID/SGID-Inventarisierungs-Baseline + tägliche Audit-only-Cron-Berichterstattung
- **VERBESSERT:** auditd-Regelsatz mit STIG-Stil-Abdeckung erweitert
- **BEHOBEN:** Mehrere SSH-Konfigurations-, Assessment-Logik- und Idempotenz-Verbesserungen

---

## 📢 Hinweise

- Deckt eine **CIS/BSI-orientierte Baseline** für Debian/Ubuntu ohne schweren Compliance-Overhead ab
- Ideal für **Root-Server**, **VPS**, **Home Labs** und **Private Clouds**
- Leichtgewichtig, modular und vollständig interaktiv
- Backups werden automatisch erstellt, aber eigene Backups vor kritischen Änderungen werden empfohlen

## 📄 Lizenz

MIT-Lizenz — siehe [LICENSE](LICENSE) für Details.

## 🤝 Beiträge & Feedback

Vorschläge, Fehlerberichte und Pull Requests sind willkommen. Jeder Beitrag hilft, das Skript zu verbessern!
