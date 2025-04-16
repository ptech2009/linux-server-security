# 🛠️ Update-Log – Linux Server Security Script

Dieses Dokument enthält alle wesentlichen Verbesserungen, neuen Features und Bugfixes des Projekts **`linux-server-security`**. Ideal für alle, die den Fortschritt verfolgen oder gezielt upgraden möchten.

---

## 📦 Version 1.5 – (April 2025)

### ✨ Neue Features
- Refaktorierung mit modularer Struktur (bessere Wartbarkeit)
- `SCRIPT_DEBUG=true` für erweitertes Logging
- Farbcodiertes Logging: `info`, `warn`, `error`, `success`, `debug`
- Automatische Erkennung des SSH-Dienstes (`ssh` oder `sshd`)
- Verbesserte SSH-Key-Erkennung (Ed25519)
- Validierung für E-Mail, Ports, Bool-Werte
- Apt-Update wird nur **einmal pro Lauf** ausgeführt
- Interaktives `msmtp`-Setup für Benutzer- oder Systemebene
- `mailutils` optional mit Test-E-Mail (Timeout-geschützt)
- Neue Funktionen zur Prüfung der `unattended-upgrades` Konfiguration (`is_pattern_active`, `is_uu_param_true`)

### 🔒 Sicherheit & Zuverlässigkeit
- Verbesserte Backup- und Restore-Logik für Konfigdateien
- Sicheres Passphrase-Handling mit Bestätigung
- Erweiterte `sshd_config`-Härtung (u. a. `AllowUsers`, `PermitRootLogin`, `PasswordAuthentication`)
- Alle Änderungen werden in `/var/log/security_script_changes.log` geloggt

### 🧠 Verbesserte Struktur & Logik
- Einsatz assoziativer Arrays (z. B. für `ufw` Ports)
- Ausgabe effektiver SSH-Einstellungen via `sshd -T -C`
- Logging beim Erstellen oder Modifizieren von Konfigurationsdateien

---

## 📌 Geplante Features
- Interaktive `ufw`-Portkonfiguration (inkl. Wiederherstellung)

📁 [Zurück zum Hauptprojekt](https://github.com/ptech2009/linux-server-security)
