# 🛠️ Changelog – Linux Server Security Script

This document lists all significant updates, new features and fixes for the `linux-server-security` project.  
Dieses Dokument enthält alle wesentlichen Neuerungen, Features und Bugfixes des Projekts.

---

## 📦 Version 1.5.1 – April 2025

---

## ✨ English:

#Bugfix:
- The UFW port logic has been adapted so that only numerical port values are now extracted and compared.

### New Features
- Refactored into modular structure (improved maintainability)
- `SCRIPT_DEBUG=true` for extended logging
- Color-coded output: info, warn, error, success, debug
- Automatic detection of SSH service (`ssh` or `sshd`)
- Improved SSH key recognition (Ed25519)
- Input validation for email, ports and boolean values
- Single `apt update` per run (no duplication)
- Interactive `msmtp` setup (user- or system-wide)
- `mailutils` now optional with test email (with timeout)
- Functions to inspect `unattended-upgrades` (e.g. `is_pattern_active`, `is_uu_param_true`)

### Security & Reliability
- Enhanced config backup/restore logic
- Secure passphrase handling (with confirmation)
- Improved `sshd_config` hardening: `AllowUsers`, `PermitRootLogin`, `PasswordAuthentication`
- All changes logged to `/var/log/security_script_changes.log`

### Logic & Structure
- Use of associative arrays (e.g. for UFW ports)
- SSH audit output via `sshd -T -C`
- Logging when creating or modifying configuration files

### Upcoming Features
- Interactive UFW port configuration (with rollback functionality)

---

## 🇩🇪 Deutsch:

#Bugfix:
- Die UFW-Portlogik wurde angepasst, sodass jetzt ausschließlich numerische Portwerte extrahiert und verglichen werden.

### Neue Features
- Refaktorierung mit modularer Struktur (bessere Wartbarkeit)
- `SCRIPT_DEBUG=true` für erweitertes Logging
- Farbcodiertes Logging: info, warn, error, success, debug
- Automatische Erkennung des SSH-Dienstes (`ssh` oder `sshd`)
- Verbesserte SSH-Key-Erkennung (Ed25519)
- Validierung für E-Mail, Ports und Boolesche Werte
- Apt-Update wird nur einmal pro Lauf ausgeführt
- Interaktives `msmtp`-Setup (benutzer- oder systemweit)
- `mailutils` optional mit Test-E-Mail (timeout-geschützt)
- Neue Funktionen zur Prüfung von `unattended-upgrades` (`is_pattern_active`, `is_uu_param_true`)

### Sicherheit & Zuverlässigkeit
- Verbesserte Backup- und Restore-Logik für Konfigdateien
- Sicheres Passphrase-Handling mit Bestätigung
- Erweiterte `sshd_config`-Härtung: `AllowUsers`, `PermitRootLogin`, `PasswordAuthentication`
- Alle Änderungen werden in `/var/log/security_script_changes.log` geloggt

### Struktur & Logik
- Einsatz assoziativer Arrays (z. B. für UFW-Ports)
- Ausgabe effektiver SSH-Einstellungen via `sshd -T -C`
- Logging beim Erstellen oder Modifizieren von Konfigurationsdateien

### Geplante Features
- Interaktive UFW-Portkonfiguration (inkl. Wiederherstellungsfunktion)

---
