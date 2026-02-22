# Linux Server Security Script

**Version 2.0.6** · Interaktives Bash-Skript zur systematischen Absicherung von Debian/Ubuntu-Servern.

Automatisiert zahlreiche manuelle Konfigurationsaufgaben mit einem **Audit-First-Ansatz**: Das Skript prüft den aktuellen Zustand gegen Best Practices und fragt nur bei gefundenen Problemen nach.

## 🔐 Funktionen und Features

Das Skript bietet eine Vielzahl von Automatisierungshilfen und Sicherheitsmaßnahmen:

### ✅ SSH-Härtung & -Konfiguration
- **Überprüfung und Optimierung der SSH-Konfiguration**  
  Einstellungen wie `PasswordAuthentication`, `PermitRootLogin`, `AllowUsers` und weitere sicherheitsrelevante Parameter werden kontrolliert und angepasst.
- **Automatisierte Erstellung von SSH-Schlüsselpaaren**  
  Generierung von Ed25519-Schlüsseln mit der Option, den öffentlichen Schlüssel automatisch in `authorized_keys` einzufügen.
- **Config-Validierung**  
  `sshd -t` Prüfung vor jedem Neustart verhindert fehlerhafte Konfigurationen.

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
- **Daemon-Verwaltung** mit Prüfung der Definitionsdateien (`main.cvd`, `daily.cvd` oder `.cld`).

### ✅ Unattended Upgrades
- **Automatische Sicherheitsupdates** über Unattended Upgrades.
- Einrichtung von `Allowed-Origins`, Reboot-Zeitplan und E-Mail-Benachrichtigungen.
- Validierung und Korrektur der periodischen `20auto-upgrades` Konfiguration.

### ✅ MSMTP Konfiguration
- **Interaktiver Setup-Assistent** – sowohl benutzerbezogen (Home-Verzeichnis) als auch systemweit.
- Abfrage von Host, Port, TLS-Modus, Benutzername/Passwort und Absenderadresse.
- Optionaler Test-E-Mail-Versand.
- Sicherheitshinweis für GPG/secret-tool Passwortspeicherung.

### ✅ Backup und Wiederherstellung
- **Automatisierte Backups** vor jeder Änderung (Suffix `.security_script_backup`).
- **`list_backups`**: Zeigt alle Backups mit Zeitstempeln an.
- **`restore_backup_interactive`**: Nummeriertes Menü zur selektiven Wiederherstellung.
- **Interaktive Backup-Verwaltung** am Skriptende.

### ✅ Interaktive Benutzerführung & Logging
- Kontrollierte Ausführung kritischer Schritte via `ask_yes_no`.
- Umfassendes Logging in `/var/log/security_script_changes.log`.

### ✅ Dry-Run Modus
- **Vorschau-Modus**: Simuliert die Ausführung des Skripts, ohne Änderungen am System vorzunehmen.
- Ideal für sichere Überprüfungen, Testumgebungen, CI/CD-Pipelines oder Validierungsläufe.
- Aktivierung:
  ```bash
  sudo ./Linux-server-security_script.sh --dry-run
  ```

---

## 🔄 Audit-Pattern

Die größte UX-Änderung in v2.0: Sections mit bestehender Installation **überspringen die "Konfigurieren?"-Frage** und starten direkt den Audit. Das Skript prüft jeden Aspekt und meldet:

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

Bei gefundenen Problemen folgt das Muster: **[Issue]** → **Recommendation** → **Fix:**

```
WARNING: [Issue] Jail [sshd] is not enabled.
INFO:   Recommendation: Enable [sshd] jail to protect SSH against brute-force.
  Fix: Enable [sshd] jail? [Y/n]:
```

Gilt für: Fail2ban, SSHGuard, UFW, Journald, Sysctl und Sudoers.

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
| Config-Backups & Restore | ✅ Ja | ❌ Nein | ❌ Nein | 🔶 Teilweise |
| Dry-Run Modus | ✅ Ja | 🔶 Minimal | ❌ Nein | 🔶 Teilweise |
| Kein eval()-Einsatz | ✅ Ja | ❌ Nutzt eval | N/A (InSpec) | N/A (Ansible) |

**Legende**: ✅ Vollständig · 🔶 Eingeschränkt · ❌ Nicht verfügbar

---

## 🔒 Sicherheitsverbesserungen in v2.0

- **Kein `eval()`-Einsatz** — alle Befehle über sichere Array-basierte `run_cmd()`-Funktion
- **Config-Validierung vor Neustarts** — `sshd -t`, `fail2ban-client -t`, `visudo -c` verhindern fehlerhafte Konfigurationen
- **Minimale jail.local** — saubere Konfiguration statt Kopie der großen `jail.conf`
- **`set -uo pipefail`** — strikte Fehlerbehandlung ohne `set -e` (das bei grep zu falschen Abbrüchen führte)

---

## 🚀 Installation und Anwendung

```bash
git clone https://github.com/ptech2009/linux-server-security.git
cd linux-server-security
chmod +x Linux-server-security_script.sh
sudo ./Linux-server-security_script.sh
```

### Dry-Run (Vorschau ohne Änderungen)
```bash
sudo ./Linux-server-security_script.sh --dry-run
```

### Voraussetzungen
- Debian/Ubuntu (getestet mit Ubuntu 24.04 LTS, Linux Mint 22)
- Bash 4+
- Root-Rechte

---

### 📢 Hinweise
- Fokus auf **praktische Serversicherheit** für Debian/Ubuntu ohne übermäßigen Compliance-Aufwand.
- Ideal geeignet für **Root-Server**, **VPS**, **Home Labs** und **private Clouds**.
- **Leichtgewichtig**, **modular** und **voll interaktiv**.
- Backups werden automatisch erstellt, dennoch empfiehlt sich ein separates Backup vor kritischen Änderungen.

## 📄 Lizenz

Dieses Projekt steht unter der MIT License — Details in der [LICENSE](LICENSE)-Datei.

## 🤝 Beiträge und Feedback

Beiträge in Form von Issues, Pull Requests oder direktem Feedback helfen, das Skript weiter zu verbessern und an verschiedene Einsatzszenarien anzupassen. Jede Unterstützung ist willkommen!
