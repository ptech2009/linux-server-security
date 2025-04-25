# Linux Server Security Script

This interactive Bash script helps administrators systematically harden Debian/Ubuntu servers. It automates numerous manual configuration steps, significantly reducing effort and error potential.

## 🔐 Features and Capabilities

The script offers a wide range of automation tools and security mechanisms:

### ✅ SSH Hardening & Configuration
- Verifies and optimizes `sshd_config` settings.
- Ensures secure parameters like `PasswordAuthentication`, `PermitRootLogin`, `AllowUsers`, and others are configured.
- **Optional SSH key generation:** Creates an Ed25519 keypair and adds the public key to `authorized_keys`.

### ✅ Fail2ban Setup & Configuration
- **Automatic config validation:** Scans and adjusts Fail2ban files to prevent brute-force attacks (especially on SSH).
- **Interactive jail customization:** Guided prompts help set up or modify the local `jail.conf` or `jail.local` interactively.

### ✅ UFW (Uncomplicated Firewall) Management
- **Rule analysis:** Detects existing firewall rules and open ports.
- **Interactive port allow-listing:** Identifies active host and container ports for selective UFW configuration.
- **Security recommendations integration:** Merges safe default rules with the current config.

### ✅ ClamAV Antivirus Integration
- Installs `clamav` and `clamav-daemon` packages if missing.
- Runs an initial `freshclam` database update (with optional manual or quiet mode).
- Configures the `clamav-freshclam` service for automatic virus definition updates.
- Verifies signature files (`main.cvd`, `daily.cvd` or `.cld`) and optionally starts/enables the `clamav-daemon` service.

### ✅ Unattended Upgrades
- **Automated security updates:** Configures `unattended-upgrades` to install important security patches automatically.
- **Failure alerts via email:** Notifies administrators via MSMTP in case of update issues.

### ✅ MSMTP Configuration
- **Interactive setup wizard:** Guides you through configuring MSMTP – either user-based (home dir) or system-wide.
- **Prompted SMTP setup:** Inputs for host, port, TLS mode, credentials, and sender address are fully supported.

### ✅ Backup & Restore
- **Pre-change backups:** Automatically backs up each config file before any modification is made.
- **Easy rollback:** Restores previous versions via a built-in restore function.

### ✅ Package and Service Management
- Checks for and installs required packages (e.g. `fail2ban`, `ufw`, `msmtp`, `mailutils`, `lsb-release`, etc.).
- Controls system services: start, restart, enable, disable, and status checking.

### ✅ Port and Container Detection
- Uses `ss` to identify open host and container ports.
- Integrates detected ports into firewall logic to minimize attack surfaces.

### ✅ Interactive UX & Logging
- Uses confirmation prompts like `ask_yes_no` to avoid unintended changes.
- Logs every modification in detail (`/var/log/security_script_changes.log`) to ensure full traceability.

## 🚀 Installation & Usage

```bash
git clone https://github.com/YourUsername/linux-server-security.git
cd linux-server-security
chmod +x security_script.sh
sudo ./security_script.sh
``` 
⚠️ Notes

  Beta status:
    This script is currently in beta. It has been tested extensively, but further optimization is ongoing. Feedback is highly appreciated!

  Backups:
    While the script automatically backs up modified configs, it's still a good idea to keep separate backups before applying any critical changes.

  Interactive behavior:
    This script runs in interactive mode and requires confirmations for critical actions to ensure safe execution.

📄 License

This project is licensed under the MIT License – see the LICENSE file for details.
🤝 Contributions & Feedback

Suggestions, bug reports, or pull requests are always welcome and appreciated. Every bit of input helps improve the script and adapt it to new use cases!
