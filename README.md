# Linux Server Security Script

This interactive Bash script helps administrators systematically harden Debian/Ubuntu servers. It automates numerous manual configuration steps, significantly reducing effort and error potential.

## 🔐 Features and Capabilities

The script offers a wide range of automation tools and security mechanisms:

### ✅ SSH Hardening & Configuration
- Verifies and optimizes `sshd_config` settings.
- Ensures secure parameters like `PasswordAuthentication`, `PermitRootLogin`, `AllowUsers`, and others are configured.
- **Optional SSH key generation:** Creates an Ed25519 keypair and adds the public key to `authorized_keys`.

✅ Google 2FA (Two-Factor Authentication) Integration
- Installs and configures Google Authenticator (libpam-google-authenticator).
- Provides interactive setup: QR code and backup codes displayed directly in terminal.
- Automatically adjusts PAM and SSHD configuration for secure 2FA login.

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

✅ **Dry-Run Mode (NEW)**
- **Preview Mode**: Simulate the script execution without making any changes to the system.
- Perfect for safe reviews, testing environments, CI/CD pipelines, or validation runs.
- Activated via simple command-line option:  
  ```bash
  sudo ./Linux-server-security_script.sh --dry-run
  ```
## ✨ Feature Matrix: Comparison to Other Hardening Scripts

| Feature | linux-server-security (this project) | captainzero93/linux-hardening | dev-sec/linux-baseline | openstack-ansible-security |
|:--------|:-------------------------------------|:-----------------------------|:-----------------------|:---------------------------|
| Interactive user guidance | ✅ Yes | 🔶 Partially | ❌ No | ❌ No |
| Idempotent (safe for repeated runs) | ✅ Yes | 🔶 Partially | ✅ Yes | ✅ Yes |
| Automatic SSH hardening (server + client settings) | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Optional integrated Google 2FA protection | ✅ Yes | ❌ No | ❌ No | ❌ No |
| sysctl.conf security optimizations | ✅ Yes (own `/etc/sysctl.d/` file) | 🔶 Minimal | 🔶 Partially checks | ✅ Full (via Ansible) |
| Firewall configuration (UFW) | ✅ Yes | 🔶 Partially (iptables only) | 🔶 Partially | ✅ Yes |
| Automatic updates (unattended-upgrades) | ✅ Yes | 🔶 Partially | ❌ No | ✅ Yes |
| Fail2Ban or SSHGuard integration | ✅ Yes (optional) | ✅ Yes | ❌ No | ✅ Yes |
| ClamAV antivirus integration (optional) | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Optimized for Debian and Ubuntu | ✅ Yes | 🔶 Partially | ✅ Yes | ✅ Yes |
| Automatic backups for changes | ✅ Yes | ❌ No | ❌ No | 🔶 Partially |
| Dry-Run Mode (simulate execution) | ✅ Yes (fully supported) | 🔶 Minimal (via Ansible --check) | ❌ No | 🔶 Partial (Ansible --check) |
| Auditd/Compliance Focus | ❌ Intentionally excluded | 🔶 Partially | ✅ Yes | ✅ Yes |

✅ **Legend**:
- ✅ Yes: Full support
- 🔶 Partially: Limited or incomplete support
- ❌ No: Not available

---

### 📢 Notes
- This script deliberately **focuses on practical security** for **Debian and Ubuntu servers** without heavy compliance overhead.
- Perfect for **root servers**, **VPS**, **home labs**, and **private clouds** where **fast and reliable server security** is needed.
- Lightweight, modular, and fully interactive.

---



## 🚀 Installation & Usage

```bash
git clone https://github.com/ptech2009/linux-server-security.git
cd linux-server-security
chmod +x linux_server_security_script.sh
sudo ./linux_server_security_script.sh
``` 
⚠️ Notes

  This script has been tested extensively, but further optimization is ongoing. Feedback is highly appreciated!

  Backups:
    While the script automatically backs up modified configs, it's still a good idea to keep separate backups before applying any critical changes.

  Interactive behavior:
    This script runs in interactive mode and requires confirmations for critical actions to ensure safe execution.

📄 License

This project is licensed under the MIT License – see the LICENSE file for details.

🤝 Contributions & Feedback

Suggestions, bug reports, or pull requests are always welcome and appreciated. Every bit of input helps improve the script and adapt it to new use cases!
