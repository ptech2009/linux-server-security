# Linux Server Security Script

**Version 3.0** · Interactive Bash script for systematic hardening of Debian/Ubuntu servers.

Automates numerous manual configuration steps with an **audit-first approach**: the script checks your current state against best practices and only prompts when issues are found.

## 🔐 Features

### SSH Hardening & Key Management
- Verifies and optimizes `sshd_config` settings (`PasswordAuthentication`, `PermitRootLogin`, `AllowUsers`, `X11Forwarding`, etc.)
- Ed25519 keypair generation with automatic `authorized_keys` setup
- Config validation via `sshd -t` before every restart
- Drop-in config via `/etc/ssh/sshd_config.d/` (modern, non-destructive)

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

### PAM Hardening *(completely rewritten in v3.0)*
- Uses `pam-auth-update` (Debian/Ubuntu native mechanism) — **no raw `sed` on live PAM files**
- `pam_faillock` via `/etc/security/faillock.conf` (modern, safe approach)
- Password quality enforcement via `/etc/security/pwquality.conf`
- **Sudo smoke-test after every PAM change** — automatic rollback on failure

### auditd (Audit Framework)
- Installs and configures `auditd` for detailed system event recording
- Writes CIS/BSI-oriented rules to `/etc/audit/rules.d/99-security-script.rules`
- Prints relevant log locations and commands after setup

### AIDE (File Integrity Monitoring)
- Builds an integrity baseline of important system files
- Local excludes for volatile container/log paths to reduce noise on live hosts
- Automatic daily check via cron (`/etc/cron.daily/aide-check`)
- Robust DB discovery with `nice`/`ionice` support and non-interactive init with timeout

### AppArmor Enforcement
- Switches all loaded AppArmor profiles from complain to enforce mode
- Audits and reports profiles that cannot be enforced cleanly

### Filesystem Hardening
- Applies secure mount options (`noexec`, `nosuid`, `nodev`) to temporary filesystems
- Reduces the risk of malicious code execution from common staging locations

### Kernel Module Blacklisting
- Blacklists unused or dangerous kernel modules
- Writes to `/etc/modprobe.d/security-script-blacklist.conf`

### Core Dump Restrictions
- Disables core dumps via `/etc/security/limits.d/` and `sysctl`
- Prevents sensitive process memory from being written to disk uncontrolled

### Login Banners
- Configures SSH pre-login banner (`/etc/issue.net`) with legal/organizational notice
- Clears `/etc/motd` to avoid information leakage

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

### Full Rollback *(new in v3.0)*
- Restores all backed-up config files from a machine-readable **transaction log**
- Removes packages installed by this script
- Unlocks root account if locked by this script
- Removes all files added by this script
- Restores removed cron jobs
- Runs non-interactively and fully automatically

### Selective Removal *(improved in v3.0)*
- Interactive detection + selection menu for installed components
- `--remove target1,target2` CLI flag for scripted use

### Dry-Run Mode
- Preview all changes without modifying the system
- Activated via: `sudo ./Linux-Server-Security-Script_v3_0.sh --dry-run`

---

## 🔄 Audit Pattern

Sections with existing installations **skip the "Configure X?" question** and go straight into auditing. The script checks each aspect and reports:

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

When issues are found, the pattern is: **[Issue]** → **Recommendation** → **Fix?**

```
WARNING: [Issue] Jail [sshd] is not enabled.
INFO:   Recommendation: Enable [sshd] jail to protect SSH against brute-force.
  Fix: Enable [sshd] jail? [Y/n]:
```

This applies to: Fail2ban, SSHGuard, UFW, Journald, Sysctl, Sudoers, AppArmor, AIDE, auditd, Filesystem, PAM, and Login Banners.

---

## 🚀 Installation & Usage

```bash
git clone https://github.com/ptech2009/linux-server-security.git
cd linux-server-security
chmod +x Linux-Server-Security-Script_v3_0.sh
sudo ./Linux-Server-Security-Script_v3_0.sh
```

### Startup Menu (new in v3.0)

On launch, you choose one of seven modes (available in **German and English**):

| # | Mode | Description |
|---|------|-------------|
| 1 | Assessment only | Audit without changes, exit code 2 on RED findings |
| 2 | Recommended hardening | Applies best-practice defaults automatically |
| 3 | Step by step | Reviews all areas one by one |
| 4 | Fully automatic | Reads `security_config.env` |
| 5 | Full rollback | Restores pre-script state without further prompts |
| 6 | Selective removal | Detection + interactive selection menu |
| 7 | Expert mode | Profile selection and special cases |

### CLI Flags

```bash
# Preview without changes
sudo ./Linux-Server-Security-Script_v3_0.sh --dry-run

# Assessment only (exit code 2 if RED findings remain)
sudo ./Linux-Server-Security-Script_v3_0.sh --assess

# Full rollback
sudo ./Linux-Server-Security-Script_v3_0.sh --rollback

# Selective removal
sudo ./Linux-Server-Security-Script_v3_0.sh --remove fail2ban,clamav

# Verify after hardening (exit code 2 if RED findings remain)
sudo ./Linux-Server-Security-Script_v3_0.sh --verify
```

### Requirements
- Debian/Ubuntu (tested on Ubuntu 24.04 LTS, Linux Mint 22)
- Bash 4+
- Root privileges

---

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
| PAM hardening (safe, native) | ✅ Yes | ❌ No | 🔶 Partially | 🔶 Partially |
| auditd / audit rules | ✅ Yes | ❌ No | ✅ Yes | ✅ Yes |
| AIDE file integrity | ✅ Yes | ❌ No | ✅ Yes | ❌ No |
| AppArmor enforcement | ✅ Yes | ❌ No | ❌ No | 🔶 Partially |
| Filesystem hardening | ✅ Yes | ❌ No | 🔶 Partially | 🔶 Partially |
| Kernel module blacklist | ✅ Yes | ❌ No | 🔶 Partially | 🔶 Partially |
| Core dump restrictions | ✅ Yes | ❌ No | ✅ Yes | 🔶 Partially |
| Login banners | ✅ Yes | ❌ No | ✅ Yes | ✅ Yes |
| Config backups & restore | ✅ Yes | ❌ No | ❌ No | 🔶 Partially |
| Full rollback + transaction log | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Selective removal | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Startup language selection (DE/EN) | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Sudo smoke-test + auto-rollback | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Dry-run mode | ✅ Yes | 🔶 Minimal | ❌ No | 🔶 Partial |
| No eval() usage | ✅ Yes | ❌ Uses eval | N/A (InSpec) | N/A (Ansible) |

---

## 🔒 Security & Quality Improvements in v3.0

- **PAM hardening completely rewritten** — uses `pam-auth-update` (Debian/Ubuntu native), no raw `sed` on live PAM files; `pam_faillock` via `/etc/security/faillock.conf`
- **Sudo smoke-test** after every PAM change — automatic rollback if `sudo` breaks
- **Full rollback mode** (`--rollback`) — machine-readable transaction log enables complete system restore
- **AppArmor enforce section** — switches all loaded profiles to enforce mode
- **Startup menu 1–7** with language selection (Deutsch / English) at launch
- **Safe config file parser** — no `source`/`eval` for reading config files
- **`--verify` flag** — exits with code 2 if RED findings remain after hardening (CI/CD compatible)
- **AIDE improvements** — non-interactive init with timeout, robust DB discovery, `nice`/`ionice` support, volatile excludes for live hosts
- **All tmpfile cleanups on EXIT trap** — no leftover temporary files on abort
- **Login banner rollback** now removes lingering banner files reliably
- **`set -uo pipefail`** — strict error handling without `set -e` (which caused false exits on grep)
- **No `eval()` usage** — all commands executed via safe array-based `run_cmd()` function
- **Config validation before restarts** — `sshd -t`, `fail2ban-client -t`, `visudo -c` prevent broken configs from being applied

---

## 📢 Notes

- Covers a **CIS/BSI-oriented baseline** for Debian/Ubuntu without heavy compliance overhead
- Perfect for **root servers**, **VPS**, **home labs**, and **private clouds**
- Lightweight, modular, and fully interactive
- Backups are created automatically, but keeping separate backups before critical changes is recommended

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 🤝 Contributions & Feedback

Suggestions, bug reports, and pull requests are welcome. Every bit of input helps improve the script!
