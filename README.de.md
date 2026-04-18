# Linux Server Security Script

[![Version](https://img.shields.io/badge/version-3.0.8-blue.svg)](https://github.com/ptech2009/linux-server-security)
[![Lizenz: MIT](https://img.shields.io/badge/Lizenz-MIT-yellow.svg)](LICENSE)
[![Plattform](https://img.shields.io/badge/plattform-Debian%20%7C%20Ubuntu-orange.svg)]()

Ein umfassendes Bash-Script zur Überprüfung und Absicherung von Debian/Ubuntu-Servern. CIS/BSI/STIG-orientierte Baseline mit Compliance-Reporting, Ausnahmeverwaltung und vollständigem Rollback-Support.

---

## Funktionen

- **Automatisierte Härtung** für SSH, PAM, sysctl, auditd, AIDE, AppArmor und mehr
- **Compliance-Katalog** mit stabilen Check-IDs (SSH-001…, SYS-001…) und CIS/BSI/STIG-Mapping
- **Schweregrad-Modell** — critical / high / medium / low pro Check
- **Ausnahmesystem** — pro Check konfigurierbare Modi: `disable`, `warn`, `assessment-only`
- **Governance-Datei-Menü** — Katalog und Ausnahmen direkt im Script einsehen und bearbeiten
- **Compliance-Report** — auf Abruf oder nach jedem Lauf generiert, mit optionalem PDF- und Mail-Versand via msmtp
- **Assessment-Matrix** — Live-Systemzustand wird gegen alle Check-IDs ausgewertet, inkl. SSH-Key-Prüfung
- **Vollständiger Rollback** — alle Änderungen rückgängig machen, inkl. SSH-Crypto-Policy, Umask-Drop-ins und auditd-Regeln
- **Container-bewusst** — service-aware Logik verhindert Probleme mit Nextcloud, Docker, AdGuard Home, Caddy
- **Idempotent** — sicher mehrfach ausführbar; plant nur Sektionen, die im aktuellen Lauf ausgeführt wurden

---

## Modi

| Modus | Beschreibung |
|-------|--------------|
| `recommended` | Interaktive Baseline-Härtung mit geführten Prompts |
| `automatic` | Nicht-interaktive Vollhärtung, geeignet für CI/Automation |
| `assessment` | Nur-Audit — keine Änderungen, Befunde werden gemeldet |
| `rollback` | Alle script-verwalteten Änderungen rückgängig machen |
| `selective` | Einzelne Härtungs-Sektionen auswählen |

---

## Schnellstart

```bash
# Herunterladen
wget https://raw.githubusercontent.com/ptech2009/linux-server-security/main/linux-server-security_script_v3_0_8.sh

# Ausführbar machen
chmod +x linux-server-security_script_v3_0_8.sh

# Assessment ausführen (keine Änderungen)
sudo bash linux-server-security_script_v3_0_8.sh --mode assessment

# Empfohlene Härtung ausführen
sudo bash linux-server-security_script_v3_0_8.sh --mode recommended
```

---

## Compliance-Abdeckung

| Framework | Abdeckung |
|-----------|-----------|
| CIS Benchmark (Debian/Ubuntu) | Baseline-Controls |
| BSI IT-Grundschutz | Relevante Härtungsmaßnahmen |
| STIG (DISA) | Erweiterte auditd-Regeln, SSH-Policy |

Jeder Check im Compliance-Katalog hat eine stabile ID, einen Schweregrad und Framework-Mapping-Felder. Ausnahmen können pro Check-ID mit Begründung und Ablaufdatum definiert werden.

---

## Check-ID Referenz (SSH)

| ID | Titel | Schweregrad |
|----|-------|-------------|
| SSH-001 | SSH-Dienst aktiv | high |
| SSH-009 | SSH Passwort-Authentifizierungsstatus | high |
| SSH-010 | SSH schlüsselbasierte Authentifizierung verfügbar | medium |
| … | … | … |

---

## Changelog

### v3.0.8
- **FIXED:** Assessment-Matrix wertet SSH-010 jetzt korrekt in der Compliance-Matrix aus
- **IMPROVED:** Neuer Assessment-Helper prüft `~/.ssh` des aktuellen Administratorbenutzers auf Ed25519-Public-Keys und `authorized_keys`-Einträge
- **IMPROVED:** SSH-010-Fehlermeldungen nennen explizit, wenn `PasswordAuthentication=no` gesetzt ist und kein Ed25519-Key-Eintrag gefunden wurde
- **IMPROVED:** SSH-009/SSH-010-Titel neutralisiert, um widersprüchliche RED-Befunde zu vermeiden; SSH-009-Schweregrad auf `high` angehoben

### v3.0.7
- **NEU:** Log-Menü Option 11 generiert auf Abruf einen frischen Compliance-Report aus dem Live-Systemzustand
- **NEU:** Optionaler Mail-Versand des Compliance-Reports über bestehende msmtp-Konfiguration
- **IMPROVED:** Compliance-Report-Workflow funktioniert auch ohne vorherigen Härtungs-/Verify-Lauf
- **FIXED:** Geschütztes PDF wird mit eingegebenem Passwort zuverlässig verifiziert
- **FIXED:** Mail-Workflow für Compliance-Report kompatibel mit älteren qpdf-Versionen; qpdf kann bei Bedarf installiert werden
- **FIXED:** Raw-TSV-Prompt erscheint sofort — kein zusätzliches Enter mehr nötig
- **FIXED:** Interaktive `/etc/msmtprc`-Kopierbestätigung bleibt sichtbar, wenn system-weite msmtp-Config fehlt
- **FIXED:** msmtp-Config-Lookup beschädigt den Laufzeit-Config-Pfad nach interaktiver Kopierbestätigung nicht mehr

### v3.0.6
- **NEU:** Stabile Check-IDs, Schweregrad-Modell und zentralisierte Check-Metadaten
- **NEU:** Script-verwalteter Compliance-Katalog mit CIS/BSI/STIG-Mapping-Feldern
- **NEU:** Ausnahmesystem mit pro-Check-Modi: `disable`, `warn`, `assessment-only`
- **NEU:** Governance-Datei-Menü — Katalog und Ausnahmen direkt im Script einsehen und bearbeiten
- **NEU:** Rollback-Aktionsbericht mit rückgängig gemachten Elementen, Fehlern, manuellen Review-Punkten und erwarteten RED-Befunden

### v3.0.5
- **NEU:** Strikter SSH-Crypto-Policy-Modus (`strict`) für explizites Ciphers/MACs/KEX-Pinning
- **NEU:** System-weite UMASK-Härtung über `login.defs`, Shell-Hook und systemd-Drop-ins
- **IMPROVED:** Assessment behandelt fehlendes SSH-Crypto-Pinning als Befund
- **IMPROVED:** Rollback und selektives Entfernen kehren SSH-Crypto-Policy und Umask-Drop-ins vollständig um

### v3.0.4
- **NEU:** System-weite Standard-Umask-Härtung (`/etc/login.defs` + `/etc/profile.d`)
- **NEU:** SSH-Crypto-Policy-Modus (`off` | `modern` | `fips-compatible`) mit Validierung und Rollback
- **NEU:** SUID/SGID-Inventar-Baseline mit täglichem Audit-Only-Cron-Reporting
- **IMPROVED:** Recommended-Modus bietet aktiv Baseline-Fixes für echte RED-Befunde an
- **IMPROVED:** auditd-Regelwerk um STIG-artige Abdeckung erweitert (Session, Zeit, Berechtigungen, Hostname, modprobe, GRUB)
- **IMPROVED:** Alle Ergänzungen sind service-aware — keine Probleme mit Nextcloud, AdGuard Home, Caddy, Docker, Podman

---

## Voraussetzungen

- Debian 11+ oder Ubuntu 20.04+
- Bash 4.x+
- Root- / sudo-Zugriff
- Optional: `msmtp` für Mail-Versand, `qpdf` für PDF-Report-Schutz, `aide`, `auditd`, `apparmor`

---

## Lizenz

MIT — Kostenlos nutzbar, veränderbar und weitergebebar. Keine Garantie. Nutzung auf eigene Gefahr.

---

## Autor

**Paul Schumacher** — [github.com/ptech2009](https://github.com/ptech2009)
