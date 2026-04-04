# Linux Server Security Script

**Version 3.0** · Interaktives Bash-Skript zur systematischen Absicherung von Debian/Ubuntu-Servern.

Automatisiert zahlreiche manuelle Konfigurationsaufgaben mit einem **Audit-First-Ansatz**: Das Skript prüft den aktuellen Zustand gegen Best Practices und fragt nur bei gefundenen Problemen nach.

## 🔐 Funktionen und Features

### ✅ SSH-Härtung & -Konfiguration
- **Überprüfung und Optimierung der SSH-Konfiguration**  
  Einstellungen wie `PasswordAuthentication`, `PermitRootLogin`, `AllowUsers` und weitere sicherheitsrelevante Parameter werden kontrolliert und angepasst.
- **Automatisierte Erstellung von SSH-Schlüsselpaaren**  
  Generierung von Ed25519-Schlüsseln mit der Option, den öffentlichen Schlüssel automatisch in `authorized_keys` einzufügen.
- **Config-Validierung**  
  `sshd -t`-Prüfung vor jedem Neustart verhindert fehlerhafte Konfigurationen.
- **Drop-in-Konfiguration** via `/etc/ssh/sshd_config.d/` (modern, nicht-destruktiv).

### ✅ Google 2FA (Zwei-Faktor-Authentifizierung)
- Installation und Konfiguration von Google Authenticator (`libpam-google-authenticator`).
- Interaktives Setup: QR-Code und Backup-Codes werden direkt im Terminal angezeigt.
- Automatische Anpassung der PAM- und SSHD-Konfiguration für sicheren 2FA-Login.

### ✅ Fail2ban (Audit-Modus)
- **Automatischer Audit** bei installiertem Paket: prüft jail.local, [sshd]-Jail-Status, ignoreip-Whitelist, Service-Zustand.
- **Minimale jail.local** statt Kopie der großen `jail.conf` mit potenziell inkompatiblen Defaults.
- **Config-Validierung** via `fail2ban-client -t` vor Restart, mit Restore-Angebot bei Fehler.
- **Automatisches Whitelisting** lokaler Subnetze zur Vermeidung von Selbst-Aussperrung.

### ✅ SSHGuard (Audit-Modus)
- **Automatischer Audit** bei installiertem Paket: prüft Whitelist-Vollständigkeit, Service-Zustand.
- IPv4/IPv6-Erkennung lokaler Subnetze und automatisches Whitelisting.

### ✅ UFW (Uncomplicated Firewall) (Audit-Modus)
- **Automatischer Audit** bei installiertem Paket: prüft Aktivstatus, SSH-Port-Regel, nicht abgedeckte Listening-Ports.
- **Port- und Container-Erkennung** via `ss` (Host-Ports) und Docker/Podman (Container-Ports).
- **SSH-Pre-Allow** vor UFW-Aktivierung gegen Aussperrung.
- **Interaktive Port-für-Port-Überprüfung** nicht abgedeckter Dienste.

### ✅ Sysctl Kernel-Härtung (Audit-Modus)
- **Automatischer Audit** von 21 Kernel-/Netzwerk-Parametern gegen Best Practices.
- Umfasst: `rp_filter`, `accept_redirects`, `send_redirects`, `accept_source_route`, `log_martians`, `icmp_echo_ignore_broadcasts`, `tcp_syncookies`, `randomize_va_space`, `sysrq`, `protected_hardlinks/symlinks`.
- Schreibt nach `/etc/sysctl.d/99-security-script.conf` (keine Änderung an `/etc/sysctl.conf`).

### ✅ Sudoers TTY-Ticket-Isolation (Audit-Modus)
- **Automatischer Audit** ob `tty_tickets` aktiv ist.
- Stellt sicher, dass sudo-Credentials pro Terminal gelten, nicht sitzungsübergreifend.
- Validierung mit `visudo -c` vor Anwendung.

### ✅ Journald Log-Limits (Audit-Modus)
- **Automatischer Audit** von `SystemMaxUse` gegen konfigurierten Zielwert (Standard: 1G).
- Fragt nur nach, wenn der Wert von der Empfehlung abweicht.

### ✅ ClamAV Antivirus-Integration
- **Paketinstallation** von `clamav` und `clamav-daemon`, falls noch nicht vorhanden.
- **Initiales Datenbank-Update** der Virensignaturen via `freshclam`.
- **Dienstkonfiguration** des `clamav-freshclam`-Dienstes für automatische Signatur-Updates.

### ✅ Unattended Upgrades
- **Automatische Sicherheitsupdates** über Unattended Upgrades.
- Einrichtung von `Allowed-Origins`, Reboot-Zeitplan und E-Mail-Benachrichtigungen.
- Validierung und Korrektur der periodischen `20auto-upgrades`-Konfiguration.

### ✅ PAM-Härtung *(komplett neu geschrieben in v3.0)*
- Verwendet `pam-auth-update` (Debian/Ubuntu-nativer Mechanismus) — **kein rohes `sed` auf Live-PAM-Dateien**.
- `pam_faillock` via `/etc/security/faillock.conf` (moderner, sicherer Ansatz).
- Passwortqualität via `/etc/security/pwquality.conf`.
- **Sudo-Smoke-Test nach jeder PAM-Änderung** — automatischer Rollback bei Fehler.

### ✅ auditd (Audit-Framework)
- Installation und Konfiguration von `auditd` für detaillierte Systemereignis-Aufzeichnung.
- CIS/BSI-orientierte Regeln in `/etc/audit/rules.d/99-security-script.rules`.
- Gibt nach dem Setup relevante Log-Pfade und Befehle zur Auswertung aus.

### ✅ AIDE (Datei-Integritätsüberwachung)
- Erstellt eine Integritäts-Baseline wichtiger Systemdateien.
- Lokale Ausschlüsse für volatile Container-/Log-Pfade zur Rauschreduzierung auf Live-Hosts.
- Automatische tägliche Prüfung via Cron (`/etc/cron.daily/aide-check`).
- Robuste DB-Erkennung mit `nice`/`ionice`-Unterstützung, nicht-interaktiver Init mit Timeout.

### ✅ AppArmor-Durchsetzung
- Schaltet alle geladenen AppArmor-Profile von Complain- auf Enforce-Modus.
- Prüft und meldet Profile, die nicht sauber enforced werden können.

### ✅ Dateisystem-Härtung
- Setzt sichere Mount-Optionen (`noexec`, `nosuid`, `nodev`) für temporäre Dateisysteme.
- Reduziert das Risiko, dass Schadcode aus typischen Ablageorten direkt ausgeführt wird.

### ✅ Kernel-Modul-Blacklisting
- Blacklistet ungenutzte oder gefährliche Kernel-Module.
- Schreibt nach `/etc/modprobe.d/security-script-blacklist.conf`.

### ✅ Core-Dump-Beschränkung
- Deaktiviert Core Dumps via `/etc/security/limits.d/` und `sysctl`.
- Verhindert, dass sensible Prozessdaten unkontrolliert auf die Platte geschrieben werden.

### ✅ Login-Banner
- Konfiguriert SSH Pre-Login-Banner (`/etc/issue.net`) mit rechtlichem/organisatorischem Hinweis.
- Bereinigt `/etc/motd` zur Vermeidung von Informationsabfluss.

### ✅ MSMTP Konfiguration
- **Interaktiver Setup-Assistent** – sowohl benutzerbezogen als auch systemweit.
- Abfrage von Host, Port, TLS-Modus, Benutzername/Passwort und Absenderadresse.
- Optionaler Test-E-Mail-Versand.
- Sicherheitshinweis für GPG/secret-tool Passwortspeicherung.

### ✅ Backup und Wiederherstellung
- **Automatisierte Backups** vor jeder Änderung (Suffix `.security_script_backup`).
- **`list_backups`**: Zeigt alle Backups mit Zeitstempeln an.
- **`restore_backup_interactive`**: Nummeriertes Menü zur selektiven Wiederherstellung.
- **Interaktive Backup-Verwaltung** am Skriptende.

### ✅ Vollständiger Rollback *(neu in v3.0)*
- Stellt alle gesicherten Konfigurationsdateien aus dem maschinenlesbaren **Transaktions-Log** wieder her.
- Entfernt vom Skript installierte Pakete.
- Entsperrt den Root-Account, falls vom Skript gesperrt.
- Entfernt alle vom Skript angelegten Dateien und stellt entfernte Cron-Jobs wieder her.
- Läuft nicht-interaktiv und vollautomatisch.

### ✅ Selektives Entfernen *(verbessert in v3.0)*
- Interaktives Erkennungs- und Auswahlmenü für installierte Komponenten.
- `--remove target1,target2`-Flag für geskripteten Einsatz.

### ✅ Dry-Run Modus
- **Vorschau-Modus**: Simuliert die Ausführung, ohne Änderungen am System vorzunehmen.
- Aktivierung:
  ```bash
  sudo ./Linux-Server-Security-Script_v3_0.sh --dry-run
  ```

---

## 🔄 Audit-Pattern

Sections mit bestehender Installation **überspringen die „Konfigurieren?"-Frage** und starten direkt den Audit. Das Skript prüft jeden Aspekt und meldet:

```
INFO: 5a. Fail2ban — Audit & Configuration
SUCCESS: Fail2ban is installed.
INFO: Auditing Fail2ban configuration...
SUCCESS: jail.local exists.
SUCCESS: Jail [sshd] is enabled.
SUCCESS: Local subnets covered by ignoreip.
SUCCESS: Fail2ban service is active.
SUCCESS: Fail2ban service is enabled.
SUCCESS: Fail2ban audit: All checks passed.
```

Bei gefundenen Problemen folgt das Muster: **[Issue]** → **Recommendation** → **Fix?**

```
WARNING: [Issue] Jail [sshd] is not enabled.
INFO:   Recommendation: Enable [sshd] jail to protect SSH against brute-force.
  Fix: Enable [sshd] jail? [Y/n]:
```

Gilt für: Fail2ban, SSHGuard, UFW, Journald, Sysctl, Sudoers, AppArmor, AIDE, auditd, Dateisystem, PAM und Login-Banner.

---

## 🚀 Installation und Anwendung

```bash
git clone https://github.com/ptech2009/linux-server-security.git
cd linux-server-security
chmod +x Linux-Server-Security-Script_v3_0.sh
sudo ./Linux-Server-Security-Script_v3_0.sh
```

### Startmenü *(neu in v3.0)*

Beim Start wird ein Modus gewählt (verfügbar auf **Deutsch und Englisch**):

| # | Modus | Beschreibung |
|---|-------|--------------|
| 1 | Nur Prüfung | Audit ohne Änderungen, Exit-Code 2 bei RED-Findings |
| 2 | Empfohlene Härtung | Wendet Best-Practice-Defaults automatisch an |
| 3 | Schritt für Schritt | Prüft alle Bereiche einzeln |
| 4 | Vollautomatisch | Liest `security_config.env` |
| 5 | Vollständiger Rollback | Stellt Vorher-Zustand ohne Rückfragen wieder her |
| 6 | Selektives Entfernen | Erkennung + interaktives Auswahlmenü |
| 7 | Expertenmodus | Profilauswahl und Sonderfälle |

### CLI-Flags

```bash
# Vorschau ohne Änderungen
sudo ./Linux-Server-Security-Script_v3_0.sh --dry-run

# Nur Prüfung (Exit-Code 2 bei verbleibenden RED-Findings)
sudo ./Linux-Server-Security-Script_v3_0.sh --assess

# Vollständiger Rollback
sudo ./Linux-Server-Security-Script_v3_0.sh --rollback

# Selektives Entfernen
sudo ./Linux-Server-Security-Script_v3_0.sh --remove fail2ban,clamav

# Verifikation nach Härtung (Exit-Code 2 bei RED-Findings)
sudo ./Linux-Server-Security-Script_v3_0.sh --verify
```

### Voraussetzungen
- Debian/Ubuntu (getestet mit Ubuntu 24.04 LTS, Linux Mint 22)
- Bash 4+
- Root-Rechte

---

## ✨ Feature-Matrix: Vergleich mit anderen Hardening-Skripten

| Funktion | linux-server-security | captainzero93/linux-hardening | dev-sec/linux-baseline | openstack-ansible-security |
|:---------|:---------------------|:-----------------------------|:-----------------------|:---------------------------|
| Interaktive Benutzerführung | ✅ Ja | 🔶 Teilweise | ❌ Nein | ❌ Nein |
| Idempotenz (sicher bei Wiederholung) | ✅ Ja | 🔶 Teilweise | ✅ Ja | ✅ Ja |
| Audit-First-Ansatz | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| SSH-Härtung | ✅ Ja | ✅ Ja | ✅ Ja | ✅ Ja |
| Google 2FA-Integration | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| Sysctl-Härtung | ✅ Ja (`/etc/sysctl.d/`) | 🔶 Minimal | 🔶 Teilweise | ✅ Ja |
| Sudoers TTY-Tickets | ✅ Ja | ❌ Nein | ❌ Nein | 🔶 Teilweise |
| UFW Firewall-Management | ✅ Ja | 🔶 Teilweise (iptables) | 🔶 Teilweise | ✅ Ja |
| Container-Port-Erkennung | ✅ Ja (Docker + Podman) | ❌ Nein | ❌ Nein | ❌ Nein |
| Automatische Updates | ✅ Ja | 🔶 Teilweise | ❌ Nein | ✅ Ja |
| Fail2ban + SSHGuard | ✅ Ja | ✅ Ja | ❌ Nein | ✅ Ja |
| ClamAV-Integration | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| PAM-Härtung (sicher, nativ) | ✅ Ja | ❌ Nein | 🔶 Teilweise | 🔶 Teilweise |
| auditd / Audit-Regeln | ✅ Ja | ❌ Nein | ✅ Ja | ✅ Ja |
| AIDE Datei-Integrität | ✅ Ja | ❌ Nein | ✅ Ja | ❌ Nein |
| AppArmor-Durchsetzung | ✅ Ja | ❌ Nein | ❌ Nein | 🔶 Teilweise |
| Dateisystem-Härtung | ✅ Ja | ❌ Nein | 🔶 Teilweise | 🔶 Teilweise |
| Kernel-Modul-Blacklisting | ✅ Ja | ❌ Nein | 🔶 Teilweise | 🔶 Teilweise |
| Core-Dump-Beschränkung | ✅ Ja | ❌ Nein | ✅ Ja | 🔶 Teilweise |
| Login-Banner | ✅ Ja | ❌ Nein | ✅ Ja | ✅ Ja |
| Config-Backups & Restore | ✅ Ja | ❌ Nein | ❌ Nein | 🔶 Teilweise |
| Vollständiger Rollback + Transaktions-Log | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| Selektives Entfernen | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| Sprachauswahl beim Start (DE/EN) | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| Sudo-Smoke-Test + Auto-Rollback | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| Dry-Run Modus | ✅ Ja | 🔶 Minimal | ❌ Nein | 🔶 Teilweise |
| Kein eval()-Einsatz | ✅ Ja | ❌ Nutzt eval | N/A (InSpec) | N/A (Ansible) |

**Legende**: ✅ Vollständig · 🔶 Eingeschränkt · ❌ Nicht verfügbar

---

## 🔒 Sicherheits- und Qualitätsverbesserungen in v3.0

- **PAM-Härtung komplett neu geschrieben** — verwendet `pam-auth-update` (Debian/Ubuntu-nativ), kein rohes `sed` auf Live-PAM-Dateien; `pam_faillock` via `/etc/security/faillock.conf`
- **Sudo-Smoke-Test** nach jeder PAM-Änderung — automatischer Rollback, falls `sudo` nicht mehr funktioniert
- **Vollständiger Rollback-Modus** (`--rollback`) — maschinenlesbares Transaktions-Log ermöglicht vollständige Systemwiederherstellung
- **AppArmor-Enforce-Sektion** — schaltet alle geladenen Profile in den Enforce-Modus
- **Startmenü 1–7** mit Sprachauswahl (Deutsch/Englisch) beim Start
- **Sicherer Config-Parser** — kein `source`/`eval` zum Einlesen von Konfigurationsdateien
- **`--verify`-Flag** — Exit-Code 2 bei verbleibenden RED-Findings nach Härtung (CI/CD-kompatibel)
- **AIDE-Verbesserungen** — nicht-interaktiver Init mit Timeout, robuste DB-Erkennung, `nice`/`ionice`-Unterstützung, volatile Ausschlüsse für Live-Hosts
- **Tmpfile-Cleanup auf EXIT-Trap** — keine temporären Dateien bei Abbruch
- **Login-Banner-Rollback** entfernt nun zuverlässig verbleibende Banner-Dateien
- **`set -uo pipefail`** — strikte Fehlerbehandlung ohne `set -e` (das bei grep zu falschen Abbrüchen führte)
- **Kein `eval()`-Einsatz** — alle Befehle über sichere Array-basierte `run_cmd()`-Funktion
- **Config-Validierung vor Neustarts** — `sshd -t`, `fail2ban-client -t`, `visudo -c` verhindern fehlerhafte Konfigurationen

---

## 📢 Hinweise

- Abdeckt eine **CIS/BSI-orientierte Baseline** für Debian/Ubuntu ohne übermäßigen Compliance-Aufwand.
- Ideal geeignet für **Root-Server**, **VPS**, **Home Labs** und **private Clouds**.
- **Leichtgewichtig**, **modular** und **voll interaktiv**.
- Backups werden automatisch erstellt, dennoch empfiehlt sich ein separates Backup vor kritischen Änderungen.

## 📄 Lizenz

Dieses Projekt steht unter der MIT License — Details in der [LICENSE](LICENSE)-Datei.

## 🤝 Beiträge und Feedback

Beiträge in Form von Issues, Pull Requests oder direktem Feedback helfen, das Skript weiter zu verbessern und an verschiedene Einsatzszenarien anzupassen. Jede Unterstützung ist willkommen!
