# Linux Server Security Script

[![Version](https://img.shields.io/badge/version-3.0.8-blue.svg)](https://github.com/ptech2009/linux-server-security)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-orange.svg)]()

A comprehensive Bash script for auditing and hardening Debian/Ubuntu servers. CIS/BSI/STIG-oriented baseline with compliance reporting, exception management, and full rollback support.

---

## Features

- **Automated hardening** for SSH, PAM, sysctl, auditd, AIDE, AppArmor and more
- **Compliance catalog** with stable check IDs (SSH-001…, SYS-001…) and CIS/BSI/STIG mapping
- **Severity model** — critical / high / medium / low per check
- **Exception system** — per-check modes: `disable`, `warn`, `assessment-only`
- **Governance file menu** — view and edit catalog and exception definitions from the script
- **Compliance report** — generated on demand or after each run, with optional PDF and mail delivery via msmtp
- **Assessment matrix** — live system state evaluated against all check IDs including SSH key checks
- **Full rollback** — revert all changes including SSH crypto policy, umask drop-ins, and auditd rules
- **Container-aware** — service-aware logic avoids breaking Nextcloud, Docker, AdGuard Home, Caddy
- **Idempotent** — safe to re-run; only plans sections actually executed in the current run

---

## Modes

| Mode | Description |
|------|-------------|
| `recommended` | Interactive baseline hardening with guided prompts |
| `automatic` | Non-interactive full hardening, suitable for CI/automation |
| `assessment` | Audit-only — no changes made, findings reported |
| `rollback` | Revert all script-managed changes |
| `selective` | Choose individual hardening sections |

---

## Quick Start

```bash
# Download
wget https://raw.githubusercontent.com/ptech2009/linux-server-security/main/linux-server-security_script_v3_0_8.sh

# Make executable
chmod +x linux-server-security_script_v3_0_8.sh

# Run assessment (no changes)
sudo bash linux-server-security_script_v3_0_8.sh --mode assessment

# Run recommended hardening
sudo bash linux-server-security_script_v3_0_8.sh --mode recommended
```

---

## Compliance Coverage

| Framework | Coverage |
|-----------|----------|
| CIS Benchmark (Debian/Ubuntu) | Baseline controls |
| BSI IT-Grundschutz | Relevant hardening measures |
| STIG (DISA) | Extended auditd rules, SSH policy |

Each check in the compliance catalog carries a stable ID, severity level, and framework mapping fields. Exceptions can be defined per check ID with a justification and expiry date.

---

## Check ID Reference (SSH)

| ID | Title | Severity |
|----|-------|----------|
| SSH-001 | SSH service active | high |
| SSH-009 | SSH password authentication status | high |
| SSH-010 | SSH key-based authentication available | medium |
| … | … | … |

---

## Changelog

### v3.0.8
- **FIXED:** Assessment matrix now evaluates SSH-010 in the compliance matrix
- **IMPROVED:** New assessment helper checks the current administrative user's `~/.ssh` for Ed25519 public keys and `authorized_keys` entries
- **IMPROVED:** SSH-010 failure details now explicitly mention when `PasswordAuthentication=no` and no Ed25519 key reference exists
- **IMPROVED:** SSH-009/SSH-010 titles made neutral to avoid contradictory RED findings; SSH-009 severity raised to `high`

### v3.0.7
- **NEW:** Log menu option 11 generates a fresh compliance report from the live system state on demand
- **NEW:** Optional mail delivery for the compliance report via existing msmtp configuration
- **IMPROVED:** Compliance report workflow works even if no prior hardening/verify run created the report file
- **FIXED:** Protected PDF verification now succeeds reliably with the entered password
- **FIXED:** Compliance report mail workflow is compatible with older qpdf releases and can install qpdf on demand
- **FIXED:** Raw TSV prompt displayed immediately — no longer requires an extra Enter to continue
- **FIXED:** Interactive `/etc/msmtprc` copy confirmation remains visible when system-wide msmtp config is missing
- **FIXED:** msmtp config lookup no longer corrupts the runtime config path after an interactive copy confirmation

### v3.0.6
- **NEW:** Stable check IDs, severity model and centralized check metadata
- **NEW:** Script-managed compliance catalog with CIS/BSI/STIG mapping fields
- **NEW:** Exception system with per-check modes: `disable`, `warn`, `assessment-only`
- **NEW:** Governance files menu — view/edit catalog and exception definitions from within the script
- **NEW:** Rollback action report with reverted items, failures, manual review points and expected RED findings

### v3.0.5
- **NEW:** Strict SSH crypto policy mode (`strict`) for explicit Ciphers/MACs/KEX pinning
- **NEW:** System-wide UMASK hardening via `login.defs`, shell hook and systemd drop-ins
- **IMPROVED:** Assessment treats missing strict SSH crypto pinning as a finding
- **IMPROVED:** Rollback and selective remove fully revert SSH strict crypto policy and umask drop-ins

### v3.0.4
- **NEW:** System-wide default umask hardening (`/etc/login.defs` + `/etc/profile.d`)
- **NEW:** SSH crypto policy mode (`off` | `modern` | `fips-compatible`) with validation and rollback
- **NEW:** SUID/SGID inventory baseline with daily audit-only cron reporting
- **IMPROVED:** Recommended mode actively offers baseline fixes for real RED findings
- **IMPROVED:** auditd ruleset expanded with STIG-style coverage (session, time, permissions, hostname, modprobe, GRUB)
- **IMPROVED:** All additions are service-aware — avoids breaking Nextcloud, AdGuard Home, Caddy, Docker, Podman

---

## Requirements

- Debian 11+ or Ubuntu 20.04+
- Bash 4.x+
- Root / sudo access
- Optional: `msmtp` for mail delivery, `qpdf` for PDF report protection, `aide`, `auditd`, `apparmor`

---

## License

MIT — Free to use, modify and distribute. No warranty. Use at your own risk.

---

## Author

**Paul Schumacher** — [github.com/ptech2009](https://github.com/ptech2009)
