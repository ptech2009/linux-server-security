# 🛠️ Changelog – Linux Server Security Script

Dieses Dokument enthält alle wesentlichen Neuerungen, Features und Bugfixes des Projekts.

---

## 📦 Version 1.7.1 – April 2025

### ✨ English
#### Bugfixes
- Fixed a critical logic error in the **unattended-upgrades** configuration function:
  - Corrected handling of parameter and origin matching.
  - Ensured reliable activation of security and update repositories.

#### New Features
- Modular refactoring for better structure and maintainability.
- `SCRIPT_DEBUG=true` enables detailed debug logging.
- Color-coded output: `info`, `warn`, `error`, `success`, `debug`.
- Automatic detection of SSH service (`ssh` or `sshd`).
- Improved SSH key detection (Ed25519 support).
- Input validation for email addresses, port numbers and boolean inputs.
- Only one `apt update` per run to avoid redundancy.
- Interactive `msmtp` setup (user-wide or system-wide).
- `mailutils` now optional; test email is timeout-protected.
- New functions for inspecting unattended-upgrades:
  - `is_pattern_active`, `is_uu_param_true`.
- **ClamAV Antivirus Integration**:
  - Installs `clamav` and `clamav-daemon`.
  - Supports manual or quiet-mode `freshclam` update.
  - Configures `clamav-freshclam` service for auto updates.
  - Verifies signature files and optionally starts/enables `clamav-daemon`.

#### Security & Reliability
- Improved config file backup and restore logic.
- Secure passphrase input with confirmation.
- Enhanced `sshd_config` hardening:
  - `AllowUsers`, `PermitRootLogin`, `PasswordAuthentication`.
- All changes are logged to `/var/log/security_script_changes.log`.

#### Logic & Structure
- Uses associative arrays for port handling (e.g., UFW).
- SSH audit via `sshd -T -C`.
- Logs file creation/modification steps.

---

### 🇩🇪 Deutsch
#### Bugfixes
- Kritischer Logikfehler in der **unattended-upgrades**-Funktion behoben:
  - Korrekte Behandlung von Parametern und Ursprungsmustern.
  - Zuverlässige Aktivierung von Security- und Update-Repositories sichergestellt.

#### Neue Features
- Refaktorisierung in modulare Struktur (bessere Wartbarkeit).
- `SCRIPT_DEBUG=true` für erweitertes Logging.
- Farbcodierte Ausgabe: `info`, `warn`, `error`, `success`, `debug`.
- Automatische Erkennung des SSH-Dienstes (`ssh` oder `sshd`).
- Verbesserte SSH-Schlüsselerkennung (Ed25519).
- Validierung für E-Mail-Adressen, Ports und Boolesche Werte.
- Nur ein `apt update` pro Lauf (keine Duplikate mehr).
- Interaktives `msmtp`-Setup (benutzer- oder systemweit).
- `mailutils` ist optional, Testmail mit Timeout-Schutz.
- Neue Funktionen zur Analyse von unattended-upgrades:
  - `is_pattern_active`, `is_uu_param_true`.
- **ClamAV-Antivirus-Integration**:
  - Installation von `clamav` und `clamav-daemon`.
  - Initiales Update via `freshclam` (leise oder manuell).
  - Konfiguration des `clamav-freshclam`-Dienstes.
  - Prüfung der Signaturdateien, optionales Starten/Aktivieren von `clamav-daemon`.

#### Sicherheit & Zuverlässigkeit
- Verbesserte Backup-/Restore-Logik für Konfigdateien.
- Sichere Passphrase-Eingabe mit Bestätigung.
- Verbesserte `sshd_config`-Härtung:
  - `AllowUsers`, `PermitRootLogin`, `PasswordAuthentication`.
- Alle Änderungen werden in `/var/log/security_script_changes.log` protokolliert.

#### Struktur & Logik
- Nutzung von assoziativen Arrays (z. B. für UFW-Ports).
- SSH-Analyse via `sshd -T -C`.
- Logging beim Erstellen/Ändern von Konfigurationsdateien.
