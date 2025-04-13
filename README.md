# Linux Server Security Script

Dieses interaktive Bash-Skript unterstützt Administratoren dabei, Debian/Ubuntu-Server systematisch abzusichern. Es automatisiert zahlreiche manuelle Konfigurationsaufgaben, wodurch der Aufwand und das Fehlerpotenzial deutlich reduziert werden.

## Funktionen und Features

Das Skript bietet eine Vielzahl von Automatisierungshilfen und Sicherheitsmaßnahmen:

### SSH-Härtung & -Konfiguration

**Überprüfung und Optimierung der SSH-Konfiguration**  
Einstellungen wie `PasswordAuthentication`, `PermitRootLogin`, `AllowUsers` und weitere sicherheitsrelevante Parameter werden kontrolliert und angepasst.

**Automatisierte Erstellung von SSH-Schlüsselpaaren**  
Generierung von Ed25519-Schlüsseln mit der Option, den öffentlichen Schlüssel automatisch in `authorized_keys` einzufügen.

### Fail2ban Einrichtung und Konfiguration

**Automatisierte Konfigurationsüberprüfung**  
Anpassung der Fail2ban-Konfigurationsdateien zur effektiven Verhinderung von Brute-Force-Angriffen (insbesondere bei SSH).

**Interaktive Konfiguration**  
Unterstützung bei der Erstellung oder Anpassung der lokalen `jail`-Konfiguration über interaktive Abfragen.

### UFW (Uncomplicated Firewall) Management

**Analyse der bestehenden Regeln**  
Erkennung von bereits erlaubten Ports und Analyse der aktuellen Firewall-Konfiguration.

**Interaktive Freischaltung von Ports**  
Identifikation und Freigabe aktiver Host- und Container-Ports, um die UFW-Regeln anzupassen.

**Automatische Integration von Empfehlungen**  
Zusammenführung von bestehenden Regelkonfigurationen mit Sicherheitsempfehlungen.

### Unattended Upgrades

**Automatische Sicherheitsupdates**  
Konfiguration der automatischen Installation sicherheitsrelevanter Updates mithilfe von Unattended Upgrades.

**E-Mail-Benachrichtigungen**  
Einrichtung von Benachrichtigungen bei Upgrade-Fehlern über die Konfiguration von Mail-Parametern via MSMTP.

### MSMTP Konfiguration

**Interaktive Einrichtung**  
Konfiguration von MSMTP zur Versendung von E-Mail-Benachrichtigungen – sowohl benutzerbezogen (über das Home-Verzeichnis) als auch systemweit.

**Abfrage von SMTP-Parametern**  
Interaktive Eingabe und Konfiguration von SMTP-Details wie Host, Port, TLS-Modus und Authentifizierungsinformationen.

### Backup und Wiederherstellung

**Automatisierte Backups**  
Vor jeder Änderung werden Konfigurationsdateien gesichert, sodass ein Rollback bei Problemen jederzeit möglich ist.

**Wiederherstellungsfunktionen**  
Einfache Rückführung der Konfigurationen aus den erstellten Backups.

### Paket- und Dienstmanagement

**Automatische Paketprüfung und Installation**  
Überprüfung und Installation notwendiger Pakete (z. B. `fail2ban`, `ufw`, `msmtp`, `mailutils`, `lsb-release` etc.).

**Verwaltung von Systemdiensten**  
Steuerung von Systemdiensten (Start, Neustart, Aktivierung und Statusprüfung).

### Port- und Container-Detection

**Erkennung aktiver Ports**  
Analyse der aktiven Host-Ports und Container-Ports mittels des `ss`-Kommandos.

**Integration in Firewall-Regeln**  
Nutzung der erkannten Ports zur Anpassung der UFW-Regeln, um ungewollte Verbindungen zu unterbinden.

### Interaktive Benutzerführung & Logging

**Interaktive Bestätigungsabfragen**  
Nutzung von Funktionen wie `ask_yes_no` für kontrollierte und sichere Änderungen.

**Umfassendes Logging**  
Detaillierte Dokumentation aller Änderungen, um den Konfigurationsprozess nachvollziehbar zu gestalten und Fehler leichter identifizieren zu können.

## Installation und Anwendung

1. Repository klonen:
   ```bash
   git clone https://github.com/DeinBenutzername/linux-server-security.git
   ```

2. In das Projektverzeichnis wechseln und das Skript ausführbar machen:
   ```bash
   cd linux-server-security
   chmod +x security_script.sh
   ```

3. Das Skript mit Administratorrechten starten:
   ```bash
   sudo ./security_script.sh
   ```

## Hinweise

- **Beta-Status:**  
  Dieses Skript befindet sich derzeit im Beta-Stadium. Es wurde bereits eingehend getestet, jedoch gibt es weiterhin Optimierungspotenzial. Feedback und Verbesserungsvorschläge sind daher sehr willkommen.

- **Backup:**  
  Vor dem Anwenden von Änderungen empfiehlt es sich, ein separates Backup der Konfigurationsdateien zu erstellen – das Skript erstellt automatisch Sicherungen, übernimmt aber nicht alle möglichen Szenarien.

- **Interaktivität:**  
  Das Skript arbeitet interaktiv und fordert bei kritischen Entscheidungen Bestätigungen an, um eine kontrollierte Umsetzung der Änderungen zu gewährleisten.

## Lizenz

Dieses Projekt steht unter der [MIT License](LICENSE) – Details findest Du in der LICENSE-Datei.

## Beiträge und Feedback

Beiträge in Form von Issues, Pull Requests oder direktem Feedback helfen, das Skript weiter zu verbessern und an unterschiedliche Einsatzszenarien anzupassen. Jede Unterstützung ist willkommen!
