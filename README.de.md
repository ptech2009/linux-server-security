# Linux Server Security Script

Dieses interaktive Bash-Skript unterstützt Administratoren dabei, Debian/Ubuntu-Server systematisch abzusichern. Es automatisiert zahlreiche manuelle Konfigurationsaufgaben, wodurch der Aufwand und das Fehlerpotenzial deutlich reduziert werden.

## Funktionen und Features

Das Skript bietet eine Vielzahl von Automatisierungshilfen und Sicherheitsmaßnahmen:

### SSH-Härtung & -Konfiguration
- **Überprüfung und Optimierung der SSH-Konfiguration**  
  Einstellungen wie `PasswordAuthentication`, `PermitRootLogin`, `AllowUsers` und weitere sicherheitsrelevante Parameter werden kontrolliert und angepasst.
- **Automatisierte Erstellung von SSH-Schlüsselpaaren**  
  Generierung von Ed25519-Schlüsseln mit der Option, den öffentlichen Schlüssel automatisch in `authorized_keys` einzufügen.

✅ Google 2FA (Zwei-Faktor-Authentifizierung) Integration
- Installation und Konfiguration von Google Authenticator (libpam-google-authenticator).
- Interaktives Setup: QR-Code und Backup-Codes werden direkt im Terminal angezeigt.
- Automatische Anpassung der PAM- und SSHD-Konfiguration für einen sicheren 2FA-Login.


### Fail2ban Einrichtung und Konfiguration
- **Automatisierte Konfigurationsüberprüfung**  
  Anpassung der Fail2ban-Konfigurationsdateien zur effektiven Verhinderung von Brute-Force-Angriffen (insbesondere bei SSH).
- **Interaktive Konfiguration**  
  Unterstützung bei der Erstellung oder Anpassung der lokalen `jail`-Konfiguration über interaktive Abfragen.

### UFW (Uncomplicated Firewall) Management
- **Analyse der bestehenden Regeln**  
  Erkennung von bereits erlaubten Ports und Analyse der aktuellen Firewall-Konfiguration.
- **Interaktive Freischaltung von Ports**  
  Identifikation und Freigabe aktiver Host- und Container-Ports, um die UFW-Regeln anzupassen.
- **Automatische Integration von Empfehlungen**  
  Zusammenführung von bestehenden Regelkonfigurationen mit Sicherheitsempfehlungen.

### ClamAV Antivirus-Integration
- **Paketinstallation**  
  Installation von `clamav` und `clamav-daemon`, falls noch nicht vorhanden.  
- **Initiales Datenbank-Update**  
  Manuelles oder leises Update der Virensignaturen via `freshclam`.  
- **Dienstkonfiguration**  
  Einrichtung des `clamav-freshclam`-Dienstes für automatische Signatur-Updates.  
- **Daemon-Verwaltung**  
  Prüfung der Dateien (`main.cvd`, `daily.cvd` oder `.cld`) und optionaler Start/Aktivierung des `clamav-daemon`-Dienstes.

### Unattended Upgrades
- **Automatische Sicherheitsupdates**  
  Konfiguration der automatischen Installation sicherheitsrelevanter Updates über Unattended Upgrades.
- **E-Mail-Benachrichtigungen**  
  Einrichtung von Benachrichtigungen bei Upgrade-Fehlern über MSMTP.

### MSMTP Konfiguration
- **Interaktive Einrichtung**  
  Konfiguration von MSMTP zur Versendung von E-Mail-Benachrichtigungen – sowohl benutzerbezogen (Home-Verzeichnis) als auch systemweit.
- **Abfrage von SMTP-Parametern**  
  Interaktive Eingabe von Host, Port, TLS-Modus, Benutzername/Passwort und Absenderadresse.

### Backup und Wiederherstellung
- **Automatisierte Backups**  
  Vor jeder Änderung werden Konfigurationsdateien gesichert (suffix `.security_script_backup`).
- **Wiederherstellungsfunktionen**  
  Einfache Rückführung aus den erstellten Backups oder Protokollen.

### Paket- und Dienstmanagement
- **Automatische Paketprüfung und Installation**  
  Installation nötiger Pakete (z. B. `fail2ban`, `ufw`, `msmtp`, `mailutils`, `lsb-release` etc.).
- **Verwaltung von Systemdiensten**  
  Start, Neustart, Aktivierung bzw. Deaktivierung und Statusprüfung von Diensten.

### Port- und Container-Detection
- **Erkennung aktiver Ports**  
  Analyse der Host- und Container-Ports per `ss`.
- **Integration in Firewall-Regeln**  
  Nutzung der erkannten Ports zur Anpassung der UFW-Regeln.

### Interaktive Benutzerführung & Logging
- **Bestätigungsabfragen**  
  Kontrollierte Ausführung kritischer Schritte via `ask_yes_no`.
- **Umfassendes Logging**  
  Alle Änderungen werden in `/var/log/security_script_changes.log` detailliert protokolliert.

✅ **Dry-Run Modus (NEU)**
- **Vorschau-Modus**: Simuliert die Ausführung des Skripts, ohne Änderungen am System vorzunehmen.
- Ideal für sichere Überprüfungen, Testumgebungen, CI/CD-Pipelines oder Validierungsläufe.
- Aktivierung über eine einfache Kommandozeilenoption:  
  ```bash
   sudo ./Linux-server-security_script.sh --dry-run
  ```

## ✨ Feature-Matrix: Vergleich mit anderen Hardening-Skripten

| Funktion | linux-server-security (dieses Projekt) | captainzero93/linux-hardening | dev-sec/linux-baseline | openstack-ansible-security |
|:---------|:---------------------------------------|:------------------------------|:-----------------------|:---------------------------|
| Interaktive Benutzerführung | ✅ Ja | 🔶 Teilweise | ❌ Nein | ❌ Nein |
| Idempotenz (sicher bei wiederholten Ausführungen) | ✅ Ja | 🔶 Teilweise | ✅ Ja | ✅ Ja |
| Automatisches SSH-Hardening (Server- und Client-Einstellungen) | ✅ Ja | ✅ Ja | ✅ Ja | ✅ Ja |
| Optionale Google 2FA-Integration | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| sysctl.conf Sicherheitsoptimierungen | ✅ Ja (eigene `/etc/sysctl.d/` Datei) | 🔶 Minimal | 🔶 Teilweise geprüft | ✅ Vollständig (über Ansible) |
| Firewall-Konfiguration (UFW) | ✅ Ja | 🔶 Teilweise (nur iptables) | 🔶 Teilweise | ✅ Ja |
| Automatische Updates (unattended-upgrades) | ✅ Ja | 🔶 Teilweise | ❌ Nein | ✅ Ja |
| Fail2Ban oder SSHGuard Integration | ✅ Ja (optional) | ✅ Ja | ❌ Nein | ✅ Ja |
| ClamAV Antivirus-Integration (optional) | ✅ Ja | ❌ Nein | ❌ Nein | ❌ Nein |
| Optimiert für Debian und Ubuntu | ✅ Ja | 🔶 Teilweise | ✅ Ja | ✅ Ja |
| Automatische Backups vor Änderungen | ✅ Ja | ❌ Nein | ❌ Nein | 🔶 Teilweise |
| Dry-Run Modus (Ausführung simulieren) | ✅ Ja (vollständig unterstützt) | 🔶 Minimal (über Ansible --check) | ❌ Nein | 🔶 Teilweise (Ansible --check) |
| Auditd/Compliance-Fokus | ❌ Bewusst ausgeschlossen | 🔶 Teilweise | ✅ Ja | ✅ Ja |

✅ **Legende**:
- ✅ Ja: Vollständig unterstützt
- 🔶 Teilweise: Eingeschränkt oder unvollständig unterstützt
- ❌ Nein: Nicht verfügbar

---

### 📢 Hinweise
- Dieses Skript fokussiert sich bewusst auf **praktische Serversicherheit** für **Debian- und Ubuntu-Server**, ohne übermäßigen Compliance-Aufwand.
- Ideal geeignet für **Root-Server**, **VPS**, **Home Labs** und **private Clouds**.
- **Leichtgewichtig**, **modular** und **voll interaktiv**.

---

## Installation und Anwendung

```bash
git clone https://github.com/ptech2009/linux-server-security.git
cd linux-server-security
chmod +x Linux-server-security_script.sh
sudo ./sudo ./Linux-server-security_script.sh
``` 

Hinweise


  Das Skript wurde eingehend getestet, doch weitere Optimierungen sind geplant. Feedback ist sehr willkommen!

   Backup:
    Das Skript erstellt Sicherungen automatisch, dennoch empfiehlt sich ein separates Backup vor kritischen Änderungen.

   Interaktivität:
    Das Skript läuft interaktiv und fordert Bestätigungen bei kritischen Aktionen an.

Lizenz

Dieses Projekt steht unter der MIT License. Details findest Du in der LICENSE-Datei.
Beiträge und Feedback

Beiträge in Form von Issues, Pull Requests oder direktem Feedback helfen, das Skript weiter zu verbessern und an verschiedene Einsatzszenarien anzupassen. Jede Unterstützung ist willkommen!
