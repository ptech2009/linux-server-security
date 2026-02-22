# Linux Server Security Script

**Version 2.0.6** · Interactive Bash script for systematic hardening of Debian/Ubuntu servers.

Automates numerous manual configuration steps with an **audit-first approach**: the script checks your current state against best practices and only prompts when issues are found.

## 🔐 Features

### SSH Hardening & Key Management
- Verifies and optimizes `sshd_config` settings (`PasswordAuthentication`, `PermitRootLogin`, `AllowUsers`, `X11Forwarding`, etc.)
- Ed25519 keypair generation with automatic `authorized_keys` setup
- Config validation via `sshd -t` before every restart

### Google 2FA (Two-Factor Authentication)
- Installs and configures `libpam-google-authenticator`
- Interactive setup with QR code and emergency scratch codes
- Automatic PAM and SSHD configuration

### Fail2ban (Audit Mode)
- **Auto-audits** when installed: checks jail.local, [sshd] jail status, ignoreip whitelist, service state
- Creates minimal `jail.local` (not a copy of the huge `jail.conf`)
- Config validation via `fail2ban-client -t` before restart, with restore on failure
- Automatic local subnet whitelisting to prevent self-lockout

### SSHGuard (Audit Mode)
- **Auto-audits** when installed: checks whitelist completeness, service state
- IPv4/IPv6 local subnet detection and whitelisting

### UFW Firewall (Audit Mode)
- **Auto-audits** when installed: checks active state, SSH port rule, uncovered listening ports
- Detects host ports via `ss` and container ports via Docker/Podman
- SSH pre-allow before UFW activation to prevent lockout
- Interactive port-by-port review for uncovered services

### Sysctl Kernel Hardening (Audit Mode)
- **Auto-audits** 21 kernel/network parameters against best practices
- Covers: `rp_filter`, `accept_redirects`, `send_redirects`, `accept_source_route`, `log_martians`, `icmp_echo_ignore_broadcasts`, `tcp_syncookies`, `randomize_va_space`, `sysrq`, `protected_hardlinks/symlinks`
- Writes to `/etc/sysctl.d/99-security-script.conf` (no modification of `/etc/sysctl.conf`)

### Sudoers TTY Ticket Isolation (Audit Mode)
- **Auto-audits** whether `tty_tickets` is active
- Ensures sudo credentials are per-terminal, not shared across sessions
- Validates with `visudo` before applying

### Journald Log Limits (Audit Mode)
- **Auto-audits** `SystemMaxUse` against configured target (default: 1G)
- Only prompts if the value differs from the recommendation

### ClamAV Antivirus
- Installs `clamav` and `clamav-daemon` if missing
- Runs initial `freshclam` database update
- Configures automatic virus definition updates

### Unattended Upgrades
- Configures `unattended-upgrades` for automatic security patches
- Sets up `Allowed-Origins`, reboot schedule, and email notifications
- Validates and fixes `20auto-upgrades` periodic configuration

### MSMTP Email Notifications
- Interactive SMTP setup wizard (user-based or system-wide)
- Supports host, port, TLS, credentials, and sender configuration
- Optional test email sending
- Security hint for GPG/secret-tool password storage

### Backup & Restore
- Pre-change backups for every modified config file
- `list_backups`: Shows all backups with timestamps
- `restore_backup_interactive`: Numbered menu for selective restoration
- Interactive backup management offered at script end

### Dry-Run Mode
- Preview all changes without modifying the system
- Activated via: `sudo ./Linux-server-security_script.sh --dry-run`

## 🔄 Audit Pattern

The biggest UX change in v2.0: sections with existing installations **skip the "Configure X?" question** and go straight into auditing. The script checks each aspect and reports:

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

When issues are found, the pattern is: **[Issue]** → **Recommendation** → **Fix:**

```
WARNING: [Issue] Jail [sshd] is not enabled.
INFO:   Recommendation: Enable [sshd] jail to protect SSH against brute-force.
  Fix: Enable [sshd] jail? [Y/n]:
```

This applies to: Fail2ban, SSHGuard, UFW, Journald, Sysctl, and Sudoers.

## ✨ Feature Matrix

| Feature | linux-server-security | captainzero93/linux-hardening | dev-sec/linux-baseline | openstack-ansible-security |
|:--------|:---------------------|:-----------------------------|:-----------------------|:---------------------------|
| Interactive user guidance | ✅ Yes | 🔶 Partially | ❌ No | ❌ No |
| Idempotent (safe for repeated runs) | ✅ Yes | 🔶 Partially | ✅ Yes | ✅ Yes |
| Audit-first pattern | ✅ Yes | ❌ No | ❌ No | ❌ No |
| SSH hardening | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Google 2FA integration | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Sysctl hardening | ✅ Yes (`/etc/sysctl.d/`) | 🔶 Minimal | 🔶 Partially | ✅ Yes |
| Sudoers TTY tickets | ✅ Yes | ❌ No | ❌ No | 🔶 Partially |
| UFW firewall management | ✅ Yes | 🔶 Partially (iptables) | 🔶 Partially | ✅ Yes |
| Container port detection | ✅ Yes (Docker + Podman) | ❌ No | ❌ No | ❌ No |
| Unattended upgrades | ✅ Yes | 🔶 Partially | ❌ No | ✅ Yes |
| Fail2ban + SSHGuard | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes |
| ClamAV integration | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Config backups & restore | ✅ Yes | ❌ No | ❌ No | 🔶 Partially |
| Dry-run mode | ✅ Yes | 🔶 Minimal | ❌ No | 🔶 Partial |
| No eval() usage | ✅ Yes | ❌ Uses eval | N/A (InSpec) | N/A (Ansible) |

## 🚀 Installation & Usage

```bash
git clone https://github.com/ptech2009/linux-server-security.git
cd linux-server-security
chmod +x Linux-server-security_script.sh
sudo ./Linux-server-security_script.sh
```

### Dry-Run (preview without changes)
```bash
sudo ./Linux-server-security_script.sh --dry-run
```

### Requirements
- Debian/Ubuntu (tested on Ubuntu 24.04 LTS, Linux Mint 22)
- Bash 4+
- Root privileges

## 🔒 Security Improvements in v2.0

- **No `eval()` usage** — all commands executed via safe array-based `run_cmd()` function
- **Config validation before restarts** — `sshd -t`, `fail2ban-client -t`, `visudo -c` prevent broken configs from being applied
- **Minimal jail.local** — creates a clean config instead of copying the large `jail.conf` with potentially incompatible defaults
- **`set -uo pipefail`** — strict error handling without `set -e` (which caused false exits on grep)

## 📢 Notes

- Focuses on **practical security** for Debian/Ubuntu without heavy compliance overhead
- Perfect for **root servers**, **VPS**, **home labs**, and **private clouds**
- Lightweight, modular, and fully interactive
- Backups are created automatically, but keeping separate backups before critical changes is recommended

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 🤝 Contributions & Feedback

Suggestions, bug reports, and pull requests are welcome. Every bit of input helps improve the script!
