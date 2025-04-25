# Linux Server Security Script

Dieses interaktive Bash-Skript unterstützt Administratoren dabei, Debian/Ubuntu-Server systematisch abzusichern. Es automatisiert zahlreiche manuelle Konfigurationsaufgaben, wodurch der Aufwand und das Fehlerpotenzial deutlich reduziert werden.

## Funktionen und Features

Das Skript bietet eine Vielzahl von Automatisierungshilfen und Sicherheitsmaßnahmen:

### SSH-Härtung & -Konfiguration
- **Überprüfung und Optimierung der SSH-Konfiguration**  
  Einstellungen wie `PasswordAuthentication`, `PermitRootLogin`, `AllowUsers` und weitere sicherheitsrelevante Parameter werden kontrolliert und angepasst.
- **Automatisierte Erstellung von SSH-Schlüsselpaaren**  
  Generierung von Ed25519-Schlüsseln mit der Option, den öffentlichen Schlüssel automatisch in `authorized_keys` einzufügen.

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

## Installation und Anwendung

1. Repository klonen:
```bash
git clone https://github.com/DeinBenutzername/linux-server-security.git
```

In das Projektverzeichnis wechseln und das Skript ausführbar machen:

    cd linux-server-security
    chmod +x security_script.sh

Skript mit Administratorrechten starten:

    sudo ./security_script.sh

Hinweise

   Beta-Status:
    Dieses Skript befindet sich im Beta-Stadium. Es wurde eingehend getestet, doch Optimierungen sind geplant. Feedback ist sehr willkommen!

   Backup:
    Das Skript erstellt Sicherungen automatisch, dennoch empfiehlt sich ein separates Backup vor kritischen Änderungen.

   Interaktivität:
    Das Skript läuft interaktiv und fordert Bestätigungen bei kritischen Aktionen an.

Lizenz

Dieses Projekt steht unter der MIT License. Details findest Du in der LICENSE-Datei.
Beiträge und Feedback

Beiträge in Form von Issues, Pull Requests oder direktem Feedback helfen, das Skript weiter zu verbessern und an verschiedene Einsatzszenarien anzupassen. Jede Unterstützung ist willkommen!
