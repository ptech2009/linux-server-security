Linux Server Security Script

Dieses interaktive Bash-Skript unterstützt Administratoren dabei, Debian/Ubuntu-Server systematisch abzusichern. Es automatisiert zahlreiche manuelle Konfigurationsaufgaben, wodurch der Aufwand und das Fehlerpotenzial deutlich reduziert werden.
Funktionen und Features

Das Skript bietet eine Vielzahl von Automatisierungshilfen und Sicherheitsmaßnahmen:

  SSH-Härtung & -Konfiguration:

  Überprüfung und Optimierung von SSH-Konfigurationseinstellungen wie PasswordAuthentication, PermitRootLogin, AllowUsers und weiteren sicherheitsrelevanten Parametern.

  Automatisierte Erstellung von SSH-Schlüsselpaaren (Ed25519) inklusive der Möglichkeit, den Public Key in authorized_keys einzufügen.

  Fail2ban Einrichtung und Konfiguration:

  Automatisierte Überprüfung und Anpassung der Fail2ban-Konfigurationsdateien, um Brute-Force-Angriffe, insbesondere auf SSH, effektiv zu verhindern.

  Interaktive Abfragen zur Erstellung oder Anpassung der lokalen jail-Konfiguration.

  UFW (Uncomplicated Firewall) Management:

  Analyse der aktuellen Firewall-Regeln und Erkennung von bereits erlaubten Ports.

  Interaktive Freischaltung von aktiven Host- und Container-Ports zur Anpassung der Firewall-Regeln.

  Automatische Integration von Empfehlungen und bestehenden Regelkonfigurationen.

  Unattended Upgrades:

  Konfiguration automatischer Sicherheitsupdates mit Hilfe der Unattended Upgrades.

  Einrichtung von E-Mail-Benachrichtigungen bei Upgrade-Fehlern, inklusive Konfiguration von Mail-Parametern via MSMTP.

  MSMTP Konfiguration:

  Interaktive Einrichtung von MSMTP zur Versendung von E-Mail-Benachrichtigungen, entweder benutzerbezogen (über das Home-Verzeichnis) oder systemweit.

  Abfrage und Konfiguration von SMTP-Parametern wie Host, Port, TLS-Modus, Authentifizierung, etc.

  Backup und Wiederherstellung:

  Automatisiertes Backup von Konfigurationsdateien vor Änderungen, sodass ein Rollback bei Problemen jederzeit möglich ist.

  Funktionen zur Wiederherstellung von Dateien aus den erstellten Backups.

  Paket- und Dienstmanagement:

  Prüfung und automatische Installation notwendiger Pakete (z. B. fail2ban, ufw, msmtp, mailutils, lsb-release etc.).

  Verwaltung von Systemdiensten inklusive Start, Neustart, Aktivierung und Validierung des Dienststatus.

  Port- und Container-Detection:

  Erkennung von aktiven Host-Ports sowie Container-Ports mittels des ss-Kommandos.

  Integration dieser Informationen in die Firewall-Konfiguration, um ungewollte Verbindungen zu verhindern.

  Interaktive Benutzerführung & Logging:

  Mehrere interaktive Bestätigungsabfragen (mittels ask_yes_no), die eine kontrollierte Durchführung sicherheitskritischer Änderungen unterstützen.

  Umfassendes Logging aller Änderungen, um den Konfigurationsprozess nachvollziehbar zu gestalten und Fehler leichter identifizieren zu können.

Installation und Anwendung

Repository klonen:

git clone https://github.com/DeinBenutzername/linux-server-security.git

In das Projektverzeichnis wechseln und das Skript ausführbar machen:

cd linux-server-security
chmod +x security_script.sh

Das Skript mit Administratorrechten starten:

sudo ./security_script.sh

Hinweise

Beta-Status:
Dieses Skript befindet sich derzeit im Beta-Stadium. Es wurde bereits eingehend getestet, jedoch gibt es weiterhin Potenzial für Optimierungen. Feedback und Verbesserungsvorschläge sind daher sehr willkommen.

Backup:
Vor dem Anwenden von Änderungen empfiehlt es sich, ein separates Backup der Konfigurationsdateien zu erstellen – das Skript übernimmt dazu bereits automatisch Sicherungen.

Interaktivität:
Das Skript arbeitet interaktiv und fragt bei kritischen Entscheidungen nach. Dies unterstützt eine kontrollierte Umsetzung der Sicherheitseinstellungen.

Lizenz

Dieses Projekt steht unter der MIT License – Details findest Du in der LICENSE.

Beiträge in Form von Issues, Pull Requests oder direkte Rückmeldungen helfen, das Skript weiter zu verbessern und an unterschiedliche Einsatzszenarien anzupassen. Jede Unterstützung ist willkommen!

