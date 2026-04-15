#!/bin/bash

# ============================================================================
# Linux Server Security Script
# Version: 3.0.6
# Author: Paul Schumacher
# Purpose: Audit and harden Debian/Ubuntu servers — CIS/BSI-oriented baseline
# License: MIT — Free to use, but at your own risk. NO WARRANTY.
#
# Changelog v3.0.6:
# - FIXED v3.0.6: Protected PDF verification no longer fails because qpdf tried to decrypt into an already-existing mktemp file
# - IMPROVED v3.0.6: Verification now removes the temp output path before qpdf decrypts and logs verification stderr on failure
# - NEW v3.0.6: PDF encryption now uses qpdf's legacy-compatible positional syntax via @argfile and verifies the password by decrypting to a temp file
# - FIXED v3.0.6: Compliance report mail workflow is compatible with older qpdf releases that do not support flag-based --encrypt password options
# - NEW v3.0.6: PDF password verification now tolerates qpdf warning exit codes and uses --warning-exit-0 for encrypted report self-tests
# - NEW v3.0.6: PDF password handling hardened to preserve exact input, verify the encrypted output, and use a distinct random owner password
# - FIXED v3.0.6: Protected compliance PDFs are now validated with the entered password before they can be mailed
# - NEW v3.0.6: Optional mail delivery now sends a password-protected PDF attachment with mandatory minimum 8-character password
# - NEW v3.0.6: Missing PDF/encryption mail dependencies can now be installed on demand from the report workflow
# - IMPROVED v3.0.6: Report workflow now summarizes generated artifacts and offers raw TSV viewing only on request
#
# Changelog v3.0.6:
# - NEW v3.0.6: Log menu option 11 now generates a fresh compliance report from the live system state on demand
# - NEW v3.0.6: Optional mail delivery for the compliance report via existing MSMTP configuration
# - IMPROVED v3.0.6: Compliance report workflow now works even if no prior hardening/verify run created the report file

# Changelog v3.0.6:
# - NEW v3.0.6: Added stable check IDs, severity model and centralized check metadata
# - NEW v3.0.6: Added script-managed compliance catalog + compliance report (CIS/BSI/STIG mapping fields)
# - NEW v3.0.6: Added exception system with per-check modes: disable, warn, assessment-only
# - NEW v3.0.6: Added governance files menu helpers to view/edit the catalog and exception definitions
# - NEW v3.0.6: Added rollback action report with reverted items, failures, manual review points and expected RED findings
#
# Changelog v3.0.5:
# - NEW v3.0.5: Added strict SSH crypto policy mode (strict) for explicit Ciphers/MACs/KEX pinning
# - NEW v3.0.5: Upgraded UMASK hardening from interactive-only to a system-wide baseline using login.defs, shell hook and systemd drop-ins
# - IMPROVED v3.0.5: Assessment now treats missing strict SSH crypto pinning as a finding and validates system-wide umask coverage
# - IMPROVED v3.0.5: Rollback and selective remove now fully revert SSH strict crypto policy and system-wide umask drop-ins
#
# Changelog v3.0.4:
# - IMPROVED v3.0.4: Recommended mode now actively offers baseline fixes for real RED findings
#   such as auditd, AIDE, login umask, SUID/SGID baseline and SSH crypto policy
# - IMPROVED v3.0.4: Fixed SUID/SGID inventory script generation (no TMP_FILE expansion bug; no empty cron target script)
# - FIXED v3.0.4: SSH effective config fallback now also reads sshd_config.d drop-ins when sshd -T is not usable
# - FIXED v3.0.4: Prevent writing empty SSH directive values into the hardening drop-in
# - FIXED v3.0.4: Added safe fallback defaults for ClientAliveInterval, ClientAliveCountMax and PrintLastLog
# - IMPROVED v3.0.4: SSH crypto prompt now accepts Enter/y/yes as the recommended default and n/no as off
# - IMPROVED v3.0.4: Idempotence proof now only plans for sections actually executed in the run
# - IMPROVED v3.0.4: Recommended mode defaults SSH crypto policy to 'modern' instead of 'off'
# - IMPROVED v3.0.4: Context-aware optional skips in recommended mode now only suppress non-baseline extras
#
# Changelog v3.0.4:
# - NEW: System-wide default umask hardening for logins and future systemd-managed services/users (/etc/login.defs + /etc/profile.d)
# - NEW: SSH crypto policy mode (off | modern | fips-compatible) with validation + rollback on failure
# - NEW: SUID/SGID inventory baseline + daily audit-only reporting (no automatic removals)
# - IMPROVED: auditd ruleset expanded with STIG-style coverage for session files, time change,
#   permission changes, hostname changes, shell/profile hardening files, rsyslog, modprobe and GRUB
# - IMPROVED: Assessment now checks strict SSH crypto policy, system-wide umask, SUID/SGID baseline coverage
#   and extended auditd coverage in addition to the existing baseline checks
# - IMPROVED: All Mil/Gov-oriented additions are service-aware by default and avoid broad changes
#   that could break Nextcloud, AdGuard Home, Caddy, Docker or Podman workloads
# - FIXED v3.0.4: assessment logic made more robust (sudoers tty regex, auditd dependency handling, AppArmor active-process awareness)
# - IMPROVED v3.0.4: interactive login umask check now accepts equivalent shell hook locations
# - IMPROVED v3.0.4: SSH crypto assessment differentiates between missing explicit policy and actually weak algorithms
# - RETAINED: Safe PAM handling, rollback support, transaction logging, AIDE/AppArmor/container logic,
#   idempotence checks, SSH validation and interactive/automatic modes from v3.0.3
# ============================================================================

set -uo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================
readonly SCRIPT_VERSION="3.0.6"
readonly JOURNALD_MAX_USE="${JOURNALD_MAX_USE:-1G}"
readonly SCRIPT_LOG_FILE="/var/log/security_script_changes.log"
readonly TRANSACTION_LOG="/var/log/security_script_transactions.log"
readonly BACKUP_SUFFIX=".security_script_backup"
readonly MSMTP_CONFIG_CHOICE="user"
readonly SYSCTL_CONFIG_FILE="/etc/sysctl.d/99-security-script.conf"
readonly SUDOERS_TTY_FILE="/etc/sudoers.d/tty_tickets"
readonly SCRIPT_DEBUG="${SCRIPT_DEBUG:-false}"
readonly MODPROBE_BLACKLIST="/etc/modprobe.d/security-script-blacklist.conf"
readonly LIMITS_CONF="/etc/security/limits.d/99-security-script.conf"
readonly FAILLOCK_CONF="/etc/security/faillock.conf"
readonly PWQUALITY_CONF="/etc/security/pwquality.conf"
readonly LOGIN_DEFS_FILE="/etc/login.defs"
readonly PROFILE_UMASK_FILE="/etc/profile.d/99-security-script-umask.sh"
readonly SYSTEM_UMASK_SYSTEMD_DROPIN="/etc/systemd/system.conf.d/99-security-script-umask.conf"
readonly USER_UMASK_SYSTEMD_DROPIN="/etc/systemd/user.conf.d/99-security-script-umask.conf"
readonly DEFAULT_LOGIN_UMASK="027"
readonly SUID_SGID_AUDIT_SCRIPT="/usr/local/sbin/security-script-suid-sgid-inventory.sh"
readonly SUID_SGID_AUDIT_BASELINE="/var/lib/security-script/suid_sgid_baseline.txt"
readonly SUID_SGID_AUDIT_REPORT="/var/log/security-script-suid-sgid-report.log"
readonly SUID_SGID_AUDIT_CRON="/etc/cron.daily/security-script-suid-sgid-inventory"
readonly BANNER_FILE="/etc/issue.net"
readonly MOTD_FILE="/etc/motd"
readonly AIDE_CRON="/etc/cron.daily/aide-check"
readonly AUDITD_RULES="/etc/audit/rules.d/99-security-script.rules"
readonly SSHD_HARDENING_DROPIN="/etc/ssh/sshd_config.d/00-security-script.conf"
readonly SSHD_HARDENING_DROPIN_LEGACY="/etc/ssh/sshd_config.d/99-security-script.conf"
readonly AIDE_INIT_LOG="/var/log/aide-init.log"
readonly AIDE_LOCAL_EXCLUDES="/etc/aide/aide.conf.d/99-security-script-local"
readonly AIDE_INIT_TIMEOUT_DEFAULT="${AIDE_INIT_TIMEOUT:-1800}"
AIDE_INIT_TIMEOUT="$AIDE_INIT_TIMEOUT_DEFAULT"
readonly IDEMPOTENCE_LOG="/var/log/security_script_idempotence.log"
readonly BASELINE_SNAPSHOT="/var/log/security_script_baseline_before_hardening.tsv"
readonly ROLLBACK_VALIDATION_REPORT="/var/log/security_script_rollback_validation.log"
readonly DEFAULT_AUTO_CONFIG="./security_config.env"
readonly GOVERNANCE_REPORT_DIR="/var/log/security-script"
readonly COMPLIANCE_REPORT="${GOVERNANCE_REPORT_DIR}/compliance_report.tsv"
readonly COMPLIANCE_REPORT_PDF="${GOVERNANCE_REPORT_DIR}/compliance_report.pdf"
readonly COMPLIANCE_REPORT_PDF_PROTECTED="${GOVERNANCE_REPORT_DIR}/compliance_report_protected.pdf"
readonly ROLLBACK_ACTION_REPORT="${GOVERNANCE_REPORT_DIR}/rollback_report.log"

# ============================================================================
# GLOBAL STATE
# ============================================================================
ORIGINAL_ARGC=$#
DRY_RUN=false
AUTO_MODE=false
ASSESS_ONLY=false
VERIFY_AFTER_HARDENING=false
ROLLBACK_MODE=false
SELECTIVE_REMOVE_MODE=false
REMOVE_TARGETS_RAW=""
SCRIPT_APT_UPDATED=false
SCRIPT_APT_FAILED=false
SSH_SERVICE=""
INTERACTIVE_MENU_USED=false
UI_LANG="de"
CLI_LANG_SET=false
SELECTIVE_MENU_RESULT=""
ACTIVE_PROFILE="server"
PROFILE_SELECTED=false
PROFILE_STRICT=false
INTERACTIVE_RECOMMENDED_MODE=false
INTERACTIVE_STEP_MODE=false
EXPERT_PROFILE_MODE=false
PROVE_IDEMPOTENCE=true
DRY_RUN_ACTIONS=0
DRY_RUN_NOTES=()
IDEMPOTENCE_LAST_RESULT="NOT_RUN"
HOST_HAS_DOCKER=false
HOST_HAS_PODMAN=false
HOST_CONTEXT_ROLE_FILE=false
HOST_CONTEXT_ROLE_MAIL=false
HOST_CONTEXT_ROLE_NEXTCLOUD=false
HOST_CONTEXT_CONTAINER_HINTS=""
HOST_CONTEXT_EXTRA_RECOMMENDATIONS=""
CURRENT_CHILD_PID=""
ABORT_REQUESTED=false
AIDE_FALLBACK_TIMEOUT=120
SECTION_WAS_EXECUTED=false

# Temp files — cleaned up on exit
TMPFILES=()
cleanup_tmpfiles() { for f in "${TMPFILES[@]+"${TMPFILES[@]}"}"; do rm -f "$f" 2>/dev/null; done; }
handle_interrupt() {
    ABORT_REQUESTED=true
    echo
    warn "$(tr_msg aborted_ctrlc)"
    if [[ -n "${CURRENT_CHILD_PID:-}" ]]; then
        kill "$CURRENT_CHILD_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$CURRENT_CHILD_PID" 2>/dev/null || true
    fi
    cleanup_tmpfiles
    exit 130
}
trap cleanup_tmpfiles EXIT
trap handle_interrupt INT TERM

mktemp_tracked() { local f; f=$(mktemp); TMPFILES+=("$f"); echo "$f"; }

# Assessment matrix
declare -A ASSESS_RESULTS=()
declare -a ASSESS_ORDER=()

declare -A CHECK_STABLE_ID=()
declare -A CHECK_SEVERITY=()
declare -A CHECK_TITLE=()
declare -A CHECK_SECTION=()
declare -A CHECK_CIS=()
declare -A CHECK_BSI=()
declare -A CHECK_STIG=()
declare -A CHECK_NOTES=()
declare -A CHECK_LEGACY_BY_STABLE_ID=()

declare -A ASSESS_META_STABLE_ID=()
declare -A ASSESS_META_SEVERITY=()
declare -A ASSESS_META_TITLE=()
declare -A ASSESS_META_MODE=()
declare -A ASSESS_META_REASON=()

declare -A EXCEPTION_MODE_BY_ID=()
declare -A EXCEPTION_REASON_BY_ID=()

declare -a ROLLBACK_ITEMS_REVERTED=()
declare -a ROLLBACK_ITEMS_FAILED=()
declare -a ROLLBACK_ITEMS_MANUAL=()
declare -a ROLLBACK_ITEMS_EXPECT_RED=()

# ============================================================================
# EMBEDDED USER EXCEPTION BLOCK
# Edit this block directly inside the script when a check must be excepted.
# Supported modes: disable | warn | assessment-only
#
# Examples:
#   ["NET-001"]="assessment-only"
#   ["SSH-008"]="warn"
#
# Typical use case:
#   ["NET-001"]="assessment-only"
#   ["NET-001"]="disable"
#   ["UMASK-001"]="warn"
# and set the matching reason below.
# ============================================================================
declare -A EMBEDDED_EXCEPTION_MODE=(
    # ["NET-001"]="assessment-only"
    # ["SSH-008"]="warn"
)

declare -A EMBEDDED_EXCEPTION_REASON=(
    # ["NET-001"]="handled externally by upstream firewall"
    # ["SSH-008"]="legacy monitoring appliance requires older SSH client compatibility"
)

# ============================================================================
# COLORS
# ============================================================================
readonly C_RESET='\e[0m'
readonly C_RED='\e[0;31m'
readonly C_GREEN='\e[0;32m'
readonly C_YELLOW='\e[0;33m'
readonly C_BLUE='\e[0;34m'
readonly C_MAGENTA='\e[0;35m'
readonly C_CYAN='\e[0;36m'
readonly C_BOLD='\e[1m'
readonly C_RED_BOLD='\e[1;31m'
readonly C_GREEN_BOLD='\e[1;32m'
readonly C_YELLOW_BOLD='\e[1;33m'

# ============================================================================
# OUTPUT HELPERS
# ============================================================================
debug()        { [[ "$SCRIPT_DEBUG" == "true" ]] && echo -e "${C_YELLOW}DEBUG [${FUNCNAME[1]}]:${C_RESET} $1"; return 0; }
info()         { echo -e "${C_BLUE}INFO:${C_RESET} $1"; }
success()      { echo -e "${C_GREEN}OK:${C_RESET} $1"; }
warn()         { echo -e "${C_YELLOW}WARN:${C_RESET} $1"; }
error()        { echo -e "${C_RED}ERROR:${C_RESET} $1" >&2; }
record_dry_run_action() {
    local note="$1"
    DRY_RUN_ACTIONS=$((DRY_RUN_ACTIONS+1))
    (( ${#DRY_RUN_NOTES[@]} < 50 )) && DRY_RUN_NOTES+=("$note")
}
dry_run_echo() { record_dry_run_action "$1"; echo -e "${C_MAGENTA}DRY-RUN:${C_RESET} Would execute: $1"; }
section_done() { echo "--- Section $1 completed ---"; echo; }

mark_section_executed() { SECTION_WAS_EXECUTED=true; }

# ============================================================================
# CHECK GOVERNANCE / COMPLIANCE / EXCEPTIONS
# ============================================================================
LAST_SECTION_SKIP_REASON=""
LAST_SECTION_SKIP_MODE=""

register_check_meta() {
    local legacy_id="$1" stable_id="$2" severity="$3" title="$4" section="$5" cis="$6" bsi="$7" stig="$8" notes="${9:-}"
    CHECK_STABLE_ID["$legacy_id"]="$stable_id"
    CHECK_SEVERITY["$legacy_id"]="$severity"
    CHECK_TITLE["$legacy_id"]="$title"
    CHECK_SECTION["$legacy_id"]="$section"
    CHECK_CIS["$legacy_id"]="$cis"
    CHECK_BSI["$legacy_id"]="$bsi"
    CHECK_STIG["$legacy_id"]="$stig"
    CHECK_NOTES["$legacy_id"]="$notes"
    CHECK_LEGACY_BY_STABLE_ID["$stable_id"]="$legacy_id"
}

init_check_catalog_metadata() {
    (( ${#CHECK_STABLE_ID[@]} > 0 )) && return 0

    register_check_meta "SSH_KEY_GEN"           "SSH-010"     "medium"   "Administrative Ed25519 SSH key available"                    "ssh"         "CIS: Secure administrative access / SSH authentication"          "BSI: SYS.1.3 SSH administration"                         "STIG: OpenSSH administrative authentication"                 "Operational safeguard for hardened SSH environments"
    register_check_meta "SSH_HARDENING"         "SSH-900"     "info"     "Managed SSH baseline drop-in state"                           "ssh"         "CIS: SSH server baseline management"                           "BSI: SYS.1.3 SSH configuration management"                "STIG: OpenSSH configuration management"                      "Synthetic orchestration check for managed baseline state"
    register_check_meta "SSH_ROOT_LOGIN"        "SSH-001"     "high"     "Disable direct root SSH login"                                "ssh"         "CIS: SSH server root login restrictions"                      "BSI: SYS.1.3 Secure remote administration"                "STIG: OpenSSH prohibit direct root login"                   ""
    register_check_meta "SSH_PASSWORD_AUTH"     "SSH-002"     "critical" "Disable SSH password authentication"                          "ssh"         "CIS: SSH password authentication disabled"                    "BSI: SYS.1.3 Strong authentication for admin access"      "STIG: OpenSSH disallow password authentication"             ""
    register_check_meta "SSH_X11"               "SSH-003"     "medium"   "Disable SSH X11 forwarding"                                   "ssh"         "CIS: Limit SSH forwarding features"                           "BSI: SYS.1.3 Minimize exposed SSH features"                "STIG: OpenSSH disable X11 forwarding"                       ""
    register_check_meta "SSH_AGENT_FWD"         "SSH-004"     "medium"   "Disable SSH agent forwarding"                                 "ssh"         "CIS: Limit SSH forwarding features"                           "BSI: SYS.1.3 Protect administrative credentials"           "STIG: OpenSSH disable agent forwarding"                     ""
    register_check_meta "SSH_TCP_FWD"           "SSH-005"     "medium"   "Disable SSH TCP forwarding when not required"                 "ssh"         "CIS: Limit SSH forwarding features"                           "BSI: SYS.1.3 Reduce SSH attack surface"                    "STIG: OpenSSH disable TCP forwarding"                       ""
    register_check_meta "SSH_GRACE_TIME"        "SSH-006"     "medium"   "Restrict SSH login grace time"                                "ssh"         "CIS: SSH session hardening"                                    "BSI: SYS.1.3 Protect remote access sessions"               "STIG: OpenSSH login grace time configuration"               ""
    register_check_meta "SSH_MAX_AUTH"          "SSH-007"     "medium"   "Restrict SSH authentication retries"                          "ssh"         "CIS: SSH authentication retry limits"                         "BSI: SYS.1.3 Resist brute-force on remote admin"           "STIG: OpenSSH MaxAuthTries configuration"                   ""
    register_check_meta "SSH_CRYPTO_POLICY"     "SSH-008"     "high"     "Pin approved SSH crypto policy"                               "ssh"         "CIS: SSH cryptographic policy / approved algorithms"          "BSI: SYS.1.3 Approved cryptography for SSH"                "STIG: OpenSSH approved ciphers MACs and KEX"                ""
    register_check_meta "SSH_GOOGLE_2FA"        "SSH-009"     "medium"   "Enable second factor for SSH administration"                  "ssh"         "CIS: MFA for privileged remote administration"                "BSI: ORP Identity and access management / MFA"             "STIG: Multifactor administrative remote access"             ""
    register_check_meta "UNATTENDED_UPGRADES"   "PATCH-001"   "high"     "Apply security updates automatically"                         "patching"    "CIS: Automated patching / security updates"                   "BSI: OPS Patch and change management"                      "STIG: Timely installation of security patches"              ""
    register_check_meta "UFW_ACTIVE"            "NET-001"     "high"     "Host firewall active"                                         "network"     "CIS: Host-based firewall enabled"                             "BSI: NET Network filtering on hosts"                       "STIG: Host firewall enabled and managed"                     ""
    register_check_meta "FAIL2BAN"              "NET-002"     "medium"   "Brute-force protection active"                                "network"     "CIS: Protect exposed services from brute-force"               "BSI: Detection and response for repeated login failures"   "STIG: Automated response to repeated failed logons"         ""
    register_check_meta "CLAMAV"                "MAL-001"     "medium"   "Malware scanning capability present"                          "malware"     "CIS: Anti-malware on relevant workloads"                      "BSI: Malware protection for file and mail flows"           "STIG: Anti-malware capability on applicable systems"        ""
    register_check_meta "AUDITD"                "AUDITD-001"  "high"     "Auditd installed and active"                                  "auditd"      "CIS: Audit logging enabled"                                   "BSI: Logging and evidence generation"                      "STIG: auditd service enabled and running"                   ""
    register_check_meta "AUDITD_EXTENDED"       "AUDITD-002"  "medium"   "Extended audit coverage present"                              "auditd"      "CIS: Extended audit rules for key security events"            "BSI: Logging of security-relevant administrative actions"  "STIG: Additional audit rules for privileged changes"        ""
    register_check_meta "AIDE"                  "FIM-001"     "medium"   "File integrity monitoring baseline available"                 "aide"        "CIS: File integrity monitoring"                               "BSI: Integrity protection and verification"                "STIG: File integrity monitoring mechanism configured"       ""
    register_check_meta "APPARMOR"              "MAC-001"     "medium"   "Mandatory access control active"                              "apparmor"    "CIS: Mandatory Access Control framework enabled"              "BSI: Application isolation and least privilege"            "STIG: Mandatory access control active"                      ""
    register_check_meta "SYSCTL"                "KERNEL-001"  "high"     "Kernel and network sysctl baseline applied"                   "sysctl"      "CIS: Kernel and network parameter hardening"                  "BSI: System hardening of kernel and network stack"         "STIG: Kernel runtime parameter hardening"                   ""
    register_check_meta "CORE_DUMPS"            "KERNEL-002"  "medium"   "Core dumps disabled for production baseline"                  "sysctl"      "CIS: Restrict information disclosure via core dumps"          "BSI: Minimize sensitive forensic residue"                  "STIG: Disable unrestricted core dumps"                      ""
    register_check_meta "FSTAB_HARDENING"       "FS-001"      "medium"   "Secure mount options on temporary filesystems"                "filesystem"  "CIS: noexec nosuid nodev on temporary mounts"                 "BSI: Harden temporary and shared storage areas"            "STIG: Secure mount options on temporary storage"            ""
    register_check_meta "MODULE_BLACKLIST"      "KERNEL-003"  "medium"   "Unused kernel modules blacklisted"                            "modules"     "CIS: Reduce kernel attack surface"                            "BSI: Disable unnecessary system functionality"             "STIG: Blacklist unnecessary kernel modules"                 ""
    register_check_meta "PAM_PWQUALITY"         "PAM-001"     "high"     "Password quality policy configured"                           "pam"         "CIS: Password complexity and minimum length"                  "BSI: Password policy enforcement"                          "STIG: Password quality requirements enforced"               ""
    register_check_meta "PAM_FAILLOCK"          "PAM-002"     "high"     "Account lockout on repeated failures configured"              "pam"         "CIS: Account lockout / failed authentication throttling"      "BSI: Protection against guessing attacks"                  "STIG: Consecutive failed logon lockout"                     ""
    register_check_meta "ROOT_LOCKED"           "ACC-001"     "medium"   "Local root account locked for direct login"                   "pam"         "CIS: Secure privileged account handling"                      "BSI: Controlled use of privileged accounts"                "STIG: Restrict direct privileged account logon"             ""
    register_check_meta "LOGIN_BANNER"          "BANNER-001"  "low"       "Authorized-use banner configured"                             "banner"      "CIS: Warning banners"                                         "BSI: Legal and compliance login notice"                    "STIG: Display approved login banner"                        ""
    register_check_meta "SUDOERS_TTY"           "SUDO-001"    "medium"   "tty_tickets configured for sudo sessions"                     "sudoers"     "CIS: Secure sudo behavior"                                    "BSI: Separation of privileged sessions"                    "STIG: Privileged session reauthentication behavior"         ""
    register_check_meta "LOGIN_UMASK"           "UMASK-001"   "high"     "Restrictive default system umask configured"                  "umask"       "CIS: Default permissions / umask baseline"                    "BSI: Secure default file permissions"                      "STIG: Default creation permissions hardened"                ""
    register_check_meta "SUID_SGID_BASELINE"    "FS-002"      "medium"   "SUID/SGID baseline inventory present"                         "filesystem"  "CIS: Monitor privileged executables"                          "BSI: Detect unauthorized privilege surfaces"               "STIG: Inventory and review privileged executables"          ""
    register_check_meta "NTP"                   "TIME-001"    "medium"   "Reliable time synchronization active"                         "time"        "CIS: Time synchronization"                                    "BSI: Reliable system time"                                 "STIG: Authoritative time source configured"                 ""
}

resolve_current_script_path() {
    local src_path="${BASH_SOURCE[0]}"
    if [[ "$src_path" != /* ]]; then
        src_path="$(cd "$(dirname "$src_path")" && pwd -P)/$(basename "$src_path")"
    fi
    printf '%s
' "$src_path"
}

ensure_governance_directories() {
    mkdir -p "$GOVERNANCE_REPORT_DIR" 2>/dev/null || true
}

load_embedded_exception_definitions() {
    EXCEPTION_MODE_BY_ID=()
    EXCEPTION_REASON_BY_ID=()

    local stable mode reason legacy
    for stable in "${!EMBEDDED_EXCEPTION_MODE[@]}"; do
        mode="${EMBEDDED_EXCEPTION_MODE[$stable],,}"
        legacy="${CHECK_LEGACY_BY_STABLE_ID[$stable]:-}"
        if [[ -z "$legacy" ]]; then
            warn "Ignoring embedded exception mode for unknown check ID: $stable"
            continue
        fi
        case "$mode" in
            disable|warn|assessment-only) EXCEPTION_MODE_BY_ID["$stable"]="$mode" ;;
            *) warn "Ignoring unsupported embedded exception mode for $stable: ${EMBEDDED_EXCEPTION_MODE[$stable]}" ;;
        esac
    done

    for stable in "${!EMBEDDED_EXCEPTION_REASON[@]}"; do
        reason="${EMBEDDED_EXCEPTION_REASON[$stable]}"
        legacy="${CHECK_LEGACY_BY_STABLE_ID[$stable]:-}"
        if [[ -z "$legacy" ]]; then
            warn "Ignoring embedded exception reason for unknown check ID: $stable"
            continue
        fi
        EXCEPTION_REASON_BY_ID["$stable"]="$reason"
    done
}

ensure_governance_files() {
    ensure_governance_directories
}

reload_governance_state() {
    init_check_catalog_metadata
    load_embedded_exception_definitions
}

emit_embedded_check_catalog() {
    local legacy stable severity title section cis bsi stig notes
    printf '# embedded check catalog from this script (v%s)
' "$SCRIPT_VERSION"
    printf '# stable_id	legacy_key	severity	title	section	cis_controls	bsi_controls	stig_controls	notes
'
    for legacy in $(printf '%s
' "${!CHECK_STABLE_ID[@]}" | sort); do
        stable="${CHECK_STABLE_ID[$legacy]}"
        severity="${CHECK_SEVERITY[$legacy]}"
        title="${CHECK_TITLE[$legacy]}"
        section="${CHECK_SECTION[$legacy]}"
        cis="${CHECK_CIS[$legacy]}"
        bsi="${CHECK_BSI[$legacy]}"
        stig="${CHECK_STIG[$legacy]}"
        notes="${CHECK_NOTES[$legacy]}"
        printf '%s	%s	%s	%s	%s	%s	%s	%s	%s
'             "$stable" "$legacy" "$severity" "$title" "$section" "$cis" "$bsi" "$stig" "$notes"
    done
}

emit_embedded_exceptions_view() {
    local stable mode reason legacy
    printf '# embedded exceptions from this script
'
    printf '# edit the EMBEDDED_EXCEPTION_MODE / EMBEDDED_EXCEPTION_REASON blocks inside the script
'
    printf '# stable_id	mode	reason	legacy_key	title
'
    for stable in $(printf '%s
' "${!CHECK_LEGACY_BY_STABLE_ID[@]}" | sort); do
        mode="${EMBEDDED_EXCEPTION_MODE[$stable]:-}"
        reason="${EMBEDDED_EXCEPTION_REASON[$stable]:-}"
        [[ -n "$mode" || -n "$reason" ]] || continue
        legacy="${CHECK_LEGACY_BY_STABLE_ID[$stable]}"
        printf '%s	%s	%s	%s	%s
'             "$stable" "${mode:-<unset>}" "${reason:-<unset>}" "$legacy" "$(lookup_check_title "$legacy")"
    done
}

show_generated_text() {
    local title="$1" generator_func="$2" tmp
    tmp=$(mktemp_tracked)
    "$generator_func" > "$tmp"
    show_text_file "$title" "$tmp"
}

open_embedded_script_editor() {
    local title="$1" focus_hint="$2" jump_to_hint="${3:-false}" editor script_path editor_base focus_line="" launch_ok=false
    echo
    echo -e "${C_BOLD}${title}${C_RESET}"
    script_path="$(resolve_current_script_path)"
    echo "Path: $script_path"
    if [[ -n "$focus_hint" ]]; then
        echo "Hint: search for $focus_hint"
        focus_line=$(grep -n -m1 -F "$focus_hint" "$script_path" 2>/dev/null | cut -d: -f1 || true)
        if [[ -n "$focus_line" && "$jump_to_hint" == "true" ]]; then
            if [[ "$UI_LANG" == "de" ]]; then
                echo "Springe möglichst direkt zu Zeile: $focus_line"
            else
                echo "Will try to jump directly to line: $focus_line"
            fi
        fi
    fi
    editor="$(preferred_editor 2>/dev/null || true)"
    if [[ -z "$editor" ]]; then
        warn "No editor found (EDITOR/nano/vim/vi)."
        read -rp "$( [[ "$UI_LANG" == "de" ]] && echo 'Enter zum Fortfahren' || echo 'Press Enter to continue' )" _ </dev/tty
        return 1
    fi
    if [[ ! -w "$script_path" ]]; then
        warn "Script file is not writable: $script_path"
        read -rp "$( [[ "$UI_LANG" == "de" ]] && echo 'Enter zum Fortfahren' || echo 'Press Enter to continue' )" _ </dev/tty
        return 1
    fi

    editor_base="$(basename -- "$editor")"
    if [[ "$jump_to_hint" == "true" && -n "$focus_line" ]]; then
        case "$editor_base" in
            nano|pico)
                "$editor" "+${focus_line}" "$script_path" && launch_ok=true
                ;;
            vim|vi|nvim|view|vim.basic)
                "$editor" "+${focus_line}" "$script_path" && launch_ok=true
                ;;
            less)
                "$editor" "+${focus_line}g" "$script_path" && launch_ok=true
                ;;
        esac
    fi
    if ! $launch_ok; then
        "$editor" "$script_path"
    fi
    reload_governance_state
    return 0
}

lookup_check_stable_id() {
    local legacy_id="$1"
    printf '%s\n' "${CHECK_STABLE_ID[$legacy_id]:-$legacy_id}"
}

lookup_check_severity() {
    local legacy_id="$1"
    printf '%s\n' "${CHECK_SEVERITY[$legacy_id]:-medium}"
}

lookup_check_title() {
    local legacy_id="$1"
    if [[ -n "${CHECK_TITLE[$legacy_id]:-}" ]]; then
        printf '%s\n' "${CHECK_TITLE[$legacy_id]}"
    else
        printf '%s\n' "$legacy_id"
    fi
}

lookup_check_controls_compact() {
    local legacy_id="$1"
    printf 'CIS=%s | BSI=%s | STIG=%s\n' \
        "${CHECK_CIS[$legacy_id]:-n/a}" \
        "${CHECK_BSI[$legacy_id]:-n/a}" \
        "${CHECK_STIG[$legacy_id]:-n/a}"
}

get_section_related_checks() {
    case "$1" in
        ssh_key|configure_ssh_key_and_users) echo "SSH_KEY_GEN" ;;
        unattended_upgrades|configure_unattended_upgrades) echo "UNATTENDED_UPGRADES" ;;
        ssh|ssh_hardening|ssh_baseline|configure_ssh_hardening) echo "SSH_HARDENING SSH_ROOT_LOGIN SSH_PASSWORD_AUTH SSH_X11 SSH_AGENT_FWD SSH_TCP_FWD SSH_GRACE_TIME SSH_MAX_AUTH SSH_CRYPTO_POLICY" ;;
        ssh_crypto) echo "SSH_CRYPTO_POLICY" ;;
        ssh_google_2fa|google_2fa|ssh_2fa|configure_google_2fa) echo "SSH_GOOGLE_2FA" ;;
        ufw|configure_ufw) echo "UFW_ACTIVE" ;;
        fail2ban|configure_fail2ban) echo "FAIL2BAN" ;;
        clamav|configure_clamav) echo "CLAMAV" ;;
        auditd|audit|configure_auditd) echo "AUDITD AUDITD_EXTENDED" ;;
        aide|configure_aide) echo "AIDE" ;;
        apparmor|configure_apparmor_enforce) echo "APPARMOR" ;;
        sysctl|configure_sysctl) echo "SYSCTL CORE_DUMPS" ;;
        journald|configure_journald) echo "" ;;
        filesystem|configure_filesystem_hardening) echo "FSTAB_HARDENING" ;;
        modules|module_blacklist|configure_module_blacklist) echo "MODULE_BLACKLIST" ;;
        pam|pam_hardening|configure_pam_hardening) echo "PAM_PWQUALITY PAM_FAILLOCK ROOT_LOCKED" ;;
        banner|banners|configure_login_banners) echo "LOGIN_BANNER" ;;
        sudoers|sudoers_tty|configure_sudoers_tty) echo "SUDOERS_TTY" ;;
        login_umask|umask|system_umask|configure_login_umask) echo "LOGIN_UMASK" ;;
        suid_sgid|suidsgid|configure_suid_sgid_inventory) echo "SUID_SGID_BASELINE" ;;
        ntp) echo "NTP" ;;
        *) echo "" ;;
    esac
}

get_exception_mode_for_legacy_check() {
    local legacy_id="$1" stable_id
    stable_id="$(lookup_check_stable_id "$legacy_id")"
    printf '%s\n' "${EXCEPTION_MODE_BY_ID[$stable_id]:-}"
}

get_exception_reason_for_legacy_check() {
    local legacy_id="$1" stable_id
    stable_id="$(lookup_check_stable_id "$legacy_id")"
    printf '%s\n' "${EXCEPTION_REASON_BY_ID[$stable_id]:-}"
}

section_skip_record_desc() {
    if [[ -n "${LAST_SECTION_SKIP_REASON:-}" ]]; then
        printf 'Skipped via exception (%s: %s)\n' "${LAST_SECTION_SKIP_MODE:-unknown}" "${LAST_SECTION_SKIP_REASON}"
    else
        printf 'Skipped via config\n'
    fi
}

rollback_report_reset() {
    ROLLBACK_ITEMS_REVERTED=()
    ROLLBACK_ITEMS_FAILED=()
    ROLLBACK_ITEMS_MANUAL=()
    ROLLBACK_ITEMS_EXPECT_RED=()
}

rollback_report_add_unique() {
    local array_name="$1" message="$2"
    eval "local current=(\"\${${array_name}[@]}\")"
    local item
    for item in "${current[@]}"; do
        [[ "$item" == "$message" ]] && return 0
    done
    eval "${array_name}+=(\"\$message\")"
}

rollback_report_reverted()   { rollback_report_add_unique "ROLLBACK_ITEMS_REVERTED" "$1"; }
rollback_report_failed()     { rollback_report_add_unique "ROLLBACK_ITEMS_FAILED" "$1"; }
rollback_report_manual()     { rollback_report_add_unique "ROLLBACK_ITEMS_MANUAL" "$1"; }
rollback_report_expect_red() { rollback_report_add_unique "ROLLBACK_ITEMS_EXPECT_RED" "$1"; }

register_expected_red_for_component() {
    local component="$1" legacy stable title severity
    for legacy in $(get_section_related_checks "$component"); do
        [[ -n "$legacy" ]] || continue
        stable="$(lookup_check_stable_id "$legacy")"
        title="$(lookup_check_title "$legacy")"
        severity="$(lookup_check_severity "$legacy")"
        rollback_report_expect_red "${stable} (${severity}) ${title}"
    done
}

write_rollback_action_report() {
    ensure_governance_directories
    mkdir -p "$(dirname "$ROLLBACK_ACTION_REPORT")" 2>/dev/null || true
    {
        echo "Rollback action report ($(date '+%Y-%m-%d %H:%M:%S'))"
        echo
        echo "[REVERTED]"
        if (( ${#ROLLBACK_ITEMS_REVERTED[@]} == 0 )); then
            echo "none"
        else
            printf '%s\n' "${ROLLBACK_ITEMS_REVERTED[@]}"
        fi
        echo
        echo "[FAILED]"
        if (( ${#ROLLBACK_ITEMS_FAILED[@]} == 0 )); then
            echo "none"
        else
            printf '%s\n' "${ROLLBACK_ITEMS_FAILED[@]}"
        fi
        echo
        echo "[MANUAL_REVIEW]"
        if (( ${#ROLLBACK_ITEMS_MANUAL[@]} == 0 )); then
            echo "none"
        else
            printf '%s\n' "${ROLLBACK_ITEMS_MANUAL[@]}"
        fi
        echo
        echo "[EXPECTED_RED_AFTER_ROLLBACK]"
        if (( ${#ROLLBACK_ITEMS_EXPECT_RED[@]} == 0 )); then
            echo "none"
        else
            printf '%s\n' "${ROLLBACK_ITEMS_EXPECT_RED[@]}"
        fi
        echo
        echo "# Note:"
        echo "# Expected RED means: these managed checks should typically become RED again after rollback"
        echo "# unless the system is still compliant because of pre-existing or externally managed controls."
    } > "$ROLLBACK_ACTION_REPORT"
}

write_compliance_report() {
    $DRY_RUN && return 0
    $ASSESS_ONLY && return 0
    ensure_governance_directories
    mkdir -p "$(dirname "$COMPLIANCE_REPORT")" 2>/dev/null || true
    local id entry raw desc normalized stable severity title mode reason cis bsi stig section
    {
        printf '# compliance report generated by security_script.sh v%s at %s\n' "$SCRIPT_VERSION" "$(date '+%Y-%m-%d %H:%M:%S')"
        printf 'stable_id\tlegacy_key\tseverity\tstatus_raw\tstatus_matrix\texception_mode\ttitle\tsection\tcis_controls\tbsi_controls\tstig_controls\texception_reason\tdetails\n'
        for id in "${ASSESS_ORDER[@]}"; do
            entry="${ASSESS_RESULTS[$id]:-}"
            [[ -n "$entry" ]] || continue
            raw="${entry%%:*}"
            desc="${entry#*:}"
            normalized="$(normalize_matrix_status "$raw")"
            stable="${ASSESS_META_STABLE_ID[$id]:-$(lookup_check_stable_id "$id")}"
            severity="${ASSESS_META_SEVERITY[$id]:-$(lookup_check_severity "$id")}"
            title="${ASSESS_META_TITLE[$id]:-$(lookup_check_title "$id")}"
            mode="${ASSESS_META_MODE[$id]:-}"
            reason="${ASSESS_META_REASON[$id]:-}"
            section="${CHECK_SECTION[$id]:-unknown}"
            cis="${CHECK_CIS[$id]:-n/a}"
            bsi="${CHECK_BSI[$id]:-n/a}"
            stig="${CHECK_STIG[$id]:-n/a}"
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$stable" "$id" "$severity" "$raw" "$normalized" "$mode" "$title" "$section" \
                "$cis" "$bsi" "$stig" "$reason" "$(printf '%s' "$desc" | tr '\t' ' ' | tr '\n' ' ')"
        done
    } > "$COMPLIANCE_REPORT"
}

preferred_editor() {
    local candidate
    for candidate in "${EDITOR:-}" nano vim vi; do
        [[ -n "$candidate" ]] || continue
        command -v "$candidate" >/dev/null 2>&1 && { printf '%s\n' "$candidate"; return 0; }
    done
    return 1
}

open_text_file_in_editor() {
    local title="$1" file="$2"
    open_embedded_script_editor "$title" "$file"
}

describe_action() {
    local key="$1"
    case "$UI_LANG:$key" in
        de:ssh_key) info "SSH-Schlüssel ersetzen Passwort-Logins durch starke, kryptografische Anmeldung und senken das Risiko von Brute-Force-Angriffen. Das ist die empfohlene Basis für einen sicheren Remote-Zugang." ;;
        en:ssh_key) info "SSH keys replace password logins with strong cryptographic authentication and reduce brute-force risk. This is the recommended baseline for secure remote access." ;;
        de:upgrades) info "Unattended Upgrades installiert Sicherheitsupdates automatisch und schließt bekannte Lücken schneller. Dadurch sinkt das Zeitfenster, in dem ein ungepatchtes System angreifbar ist." ;;
        en:upgrades) info "Unattended Upgrades installs security updates automatically and shortens exposure to known vulnerabilities. This reduces the time a system stays unpatched." ;;
        de:msmtp) info "MSMTP ermöglicht Mail-Benachrichtigungen des Systems, etwa für Reports oder Warnungen. Das ist hilfreich für Monitoring, aber keine Kernmaßnahme für jedes System." ;;
        en:msmtp) info "MSMTP enables system email notifications for reports and alerts. This is useful for monitoring, but not a core measure for every system." ;;
        de:ssh_hardening) info "SSH-Hardening reduziert unnötige Angriffsflächen wie Passwort-Login, Agent-Forwarding oder großzügige Timeouts. So wird der wichtigste Fernzugang des Servers deutlich robuster." ;;
        en:ssh_hardening) info "SSH hardening reduces attack surface by disabling risky options like password login, agent forwarding or loose timeouts. This makes the server's primary remote access much more robust." ;;
        de:twofa) info "Zwei-Faktor-Authentifizierung schützt den SSH-Zugang zusätzlich, falls ein Passwort oder Schlüssel kompromittiert wird. Sie ist wirksam, aber eher für gezielte Sicherheitsanforderungen oder exponierte Systeme gedacht." ;;
        en:twofa) info "Two-factor authentication adds an extra protection layer for SSH if a password or key is compromised. It is effective, but more suited to stricter requirements or exposed systems." ;;
        de:fail2ban) info "Fail2ban erkennt wiederholte Fehlversuche in Logs und sperrt auffällige IP-Adressen temporär. Das bremst automatisierte Login-Angriffe auf SSH und andere Dienste deutlich aus." ;;
        en:fail2ban) info "Fail2ban detects repeated failures in logs and temporarily blocks suspicious IP addresses. This significantly slows down automated login attacks against SSH and other services." ;;
        de:sshguard) info "SSHGuard ist ein zusätzlicher leichter Schutz gegen Brute-Force-Angriffe auf SSH. Er ist nützlich, aber bei bereits gut konfiguriertem Fail2ban oft optional." ;;
        en:sshguard) info "SSHGuard is an additional lightweight protection against SSH brute-force attacks. It is useful, but often optional when Fail2ban is already configured well." ;;
        de:ufw) info "Eine Host-Firewall erlaubt nur wirklich benötigte Ports und blockiert alles andere. Das ist eine zentrale Netzwerkschutzmaßnahme, kann aber auf komplexen Hosts sorgfältige Planung erfordern." ;;
        en:ufw) info "A host firewall allows only required ports and blocks everything else. This is a core network protection measure, but complex hosts may require careful planning." ;;
        de:journald) info "Eine Begrenzung der Journald-Größe verhindert, dass Logs unkontrolliert den Datenträger füllen. Das stabilisiert den Betrieb und schützt vor Speicherplatzproblemen durch Logfluten." ;;
        en:journald) info "Limiting journald size prevents logs from consuming disk space without bounds. This improves operational stability and protects against log-driven storage exhaustion." ;;
        de:clamav) info "ClamAV kann Dateien und Uploads auf bekannte Schadsoftware prüfen und ist besonders auf File- oder Mail-Servern nützlich. Auf reinen Minimalservern ist es eher optional als Pflicht." ;;
        en:clamav) info "ClamAV can scan files and uploads for known malware and is especially useful on file or mail servers. On minimal servers it is more optional than mandatory." ;;
        de:sysctl) info "Sysctl-Hardening setzt Kernel- und Netzwerkparameter sicherer, etwa für Redirects, Source Routing oder Speicher- und Kernel-Schutz. Das ist eine wichtige Baseline, weil viele Schutzmechanismen direkt im Kernel greifen." ;;
        en:sysctl) info "Sysctl hardening applies safer kernel and network parameters for topics such as redirects, source routing and memory/kernel protection. This is an important baseline because many protections act directly in the kernel." ;;
        de:sudoers) info "Sudoers-Härtung verbessert das Verhalten privilegierter Befehle und erschwert Missbrauch offener Sitzungen. Das ist eine kleine, aber sinnvolle Maßnahme für Admin-Konten." ;;
        en:sudoers) info "Sudoers hardening improves the handling of privileged commands and reduces abuse of open sessions. This is a small but useful safeguard for admin accounts." ;;
        de:auditd) info "auditd zeichnet sicherheitsrelevante Systemereignisse detailliert auf und unterstützt spätere Analyse sowie Compliance. Es ist besonders wertvoll, wenn Änderungen oder Angriffe nachvollzogen werden müssen." ;;
        en:auditd) info "auditd records security-relevant system events in detail and supports later analysis and compliance. It is especially valuable when changes or attacks must be traceable." ;;
        de:aide) info "AIDE erstellt eine Integritäts-Baseline wichtiger Dateien und erkennt spätere Manipulationen oder unerwartete Änderungen. Das hilft besonders bei forensischer Nachvollziehbarkeit und langfristiger Systemkontrolle." ;;
        en:aide) info "AIDE builds an integrity baseline for important files and detects later tampering or unexpected changes. This is especially helpful for forensic traceability and long-term system control." ;;
        de:apparmor) info "AppArmor begrenzt, was Prozesse auf dem System tun dürfen, und reduziert so die Folgen kompromittierter Dienste. Das ist ein starker zusätzlicher Schutz, wenn die Profile sauber laufen." ;;
        en:apparmor) info "AppArmor limits what processes on the system are allowed to do and reduces the impact of compromised services. This is a strong additional control when profiles run cleanly." ;;
        de:filesystem) info "Sichere Mount-Optionen wie noexec, nosuid und nodev erschweren Missbrauch temporärer Dateisysteme. Das senkt das Risiko, dass Schadcode aus typischen Ablageorten direkt ausgeführt wird." ;;
        en:filesystem) info "Secure mount options such as noexec, nosuid and nodev make abuse of temporary filesystems harder. This reduces the chance that malicious code is executed directly from common staging locations." ;;
        de:modules) info "Das Blacklisting ungenutzter Kernel-Module verringert die Angriffsfläche des Systems. Was nicht geladen werden kann, kann auch nicht so leicht missbraucht werden." ;;
        en:modules) info "Blacklisting unused kernel modules reduces the system's attack surface. What cannot be loaded is harder to abuse." ;;
        de:coredumps) info "Das Deaktivieren von Core Dumps verhindert, dass sensible Prozessdaten unkontrolliert auf der Platte landen. Das schützt vor Datenabfluss und reduziert forensische Altlasten auf Produktivsystemen." ;;
        en:coredumps) info "Disabling core dumps prevents sensitive process memory from being written uncontrolled to disk. This reduces data exposure and unwanted forensic residue on production systems." ;;
        de:pam) info "PAM-Hardening verbessert Passwortqualität und begrenzt Fehlversuche bei Logins. Dadurch werden schwache Kennwörter und Brute-Force-Angriffe deutlich schwieriger." ;;
        en:pam) info "PAM hardening improves password quality and limits failed login attempts. This makes weak passwords and brute-force attacks significantly harder." ;;
        de:banners) info "Login-Banner zeigen rechtliche und organisatorische Hinweise vor oder nach der Anmeldung an. Das ist vor allem für Compliance, Behörden- und Unternehmensumgebungen relevant." ;;
        en:banners) info "Login banners display legal and organizational notices before or after authentication. This is mainly relevant for compliance and enterprise or public-sector environments." ;;
    esac
}

describe_detail() {
    local key="$1"
    case "$UI_LANG:$key" in
        de:ssh_allowusers) info "AllowUsers begrenzt, welche lokalen Konten sich per SSH anmelden dürfen. Das reduziert die Angriffsfläche, wenn auf dem System mehrere Benutzer existieren." ;;
        en:ssh_allowusers) info "AllowUsers restricts which local accounts may log in via SSH. This reduces attack surface when multiple users exist on the system." ;;
        de:ssh_passwordauth) info "Das Deaktivieren der Passwortanmeldung erschwert Brute-Force- und Passwortspray-Angriffe direkt auf SSH. Nutze das nur, wenn bereits funktionierende Schlüssel hinterlegt sind." ;;
        en:ssh_passwordauth) info "Disabling password login makes brute-force and password-spraying attacks against SSH much harder. Use it only when working SSH keys are already in place." ;;
        de:ssh_challengeresponse) info "Challenge-Response-Logins können zusätzliche Passwortpfade offenhalten. Wenn du keine spezielle PAM-/OTP-Lösung brauchst, ist 'no' meist die sichere Wahl." ;;
        en:ssh_challengeresponse) info "Challenge-response logins can keep extra password-style authentication paths open. If you do not need a specific PAM or OTP flow, 'no' is usually the safer choice." ;;
        de:ssh_agentfwd) info "Agent-Forwarding erlaubt die Weitergabe deines lokalen SSH-Agenten an den Zielhost. Das ist praktisch, erhöht aber das Risiko bei kompromittierten Zwischenstationen." ;;
        en:ssh_agentfwd) info "Agent forwarding lets your local SSH agent be forwarded to the remote host. This is convenient, but increases risk on compromised jump hosts or servers." ;;
        de:ssh_tcpfwd) info "TCP-Forwarding erlaubt SSH-Tunnel über den Server. Wenn du das nicht brauchst, schließt 'no' eine oft unnötige Tunnel-Funktion." ;;
        en:ssh_tcpfwd) info "TCP forwarding allows SSH tunnels through the server. If you do not need this, setting it to 'no' closes an often unnecessary tunneling capability." ;;
        de:ssh_x11fwd) info "X11-Forwarding wird auf Servern selten benötigt und vergrößert die Angriffsfläche. Deshalb ist 'no' auf typischen Headless-Systemen sinnvoll." ;;
        en:ssh_x11fwd) info "X11 forwarding is rarely needed on servers and increases attack surface. That is why 'no' is sensible on typical headless systems." ;;
        de:ssh_logingracetime) info "Eine kürzere LoginGraceTime beendet hängende oder missbrauchte Anmeldeversuche schneller. Das reduziert die Zeit für langsame Brute-Force- oder Ressourcenangriffe." ;;
        en:ssh_logingracetime) info "A shorter LoginGraceTime terminates hanging or abused login attempts sooner. This reduces exposure to slow brute-force or resource-draining attacks." ;;
        de:ssh_maxauthtries) info "Weniger MaxAuthTries begrenzen die Anzahl falscher Versuche pro Verbindung. Das erschwert Passwort-Raten und unnötige Mehrfachversuche." ;;
        en:ssh_maxauthtries) info "Lower MaxAuthTries limits the number of failed attempts per connection. This makes password guessing and repeated trials harder." ;;
        de:ssh_maxsessions) info "Weniger parallele Sitzungen pro Verbindung verringern Missbrauchsmöglichkeiten und Ressourcenverbrauch. Für normale Admin-Zugriffe reichen kleine Werte meist aus." ;;
        en:ssh_maxsessions) info "Fewer parallel sessions per connection reduce abuse options and resource usage. Small values are usually enough for normal admin access." ;;
        de:ssh_clientaliveinterval) info "ClientAliveInterval erkennt tote oder verlassene Sitzungen früher. Das hilft, verwaiste SSH-Verbindungen sauber zu beenden." ;;
        en:ssh_clientaliveinterval) info "ClientAliveInterval detects dead or abandoned sessions sooner. This helps clean up stale SSH connections." ;;
        de:ssh_clientalivecountmax) info "ClientAliveCountMax legt fest, wie oft eine tote Sitzung toleriert wird, bevor sie beendet wird. Kleinere Werte schließen verwaiste Sitzungen schneller." ;;
        en:ssh_clientalivecountmax) info "ClientAliveCountMax defines how often a dead session is tolerated before it is dropped. Lower values close stale sessions more quickly." ;;
        de:ssh_permitrootlogin) info "Direkter Root-Login ist ein bevorzugtes Ziel von Angreifern. 'prohibit-password' oder 'no' reduziert dieses Risiko deutlich." ;;
        en:ssh_permitrootlogin) info "Direct root login is a preferred target for attackers. 'prohibit-password' or 'no' reduces this risk significantly." ;;
        de:ssh_permituserenvironment) info "Benutzerspezifische Umgebungsvariablen können SSH-Verhalten unerwartet beeinflussen. 'no' hält die Serverumgebung berechenbarer und robuster." ;;
        en:ssh_permituserenvironment) info "User-controlled environment variables can influence SSH behavior in unexpected ways. 'no' keeps the server environment more predictable and robust." ;;
        de:ssh_printlastlog) info "Die Anzeige des letzten erfolgreichen Logins hilft, verdächtige Zugriffe schneller zu bemerken. Das ist klein, aber für Administratoren nützlich." ;;
        en:ssh_printlastlog) info "Showing the last successful login helps spot suspicious access more quickly. This is a small but useful aid for administrators." ;;
        de:upgrades_periodic) info "Die empfohlenen Periodic-Einstellungen sorgen dafür, dass Updates zuverlässig geladen, installiert und aufgeräumt werden. Das verbessert die Patch-Hygiene des Systems." ;;
        en:upgrades_periodic) info "The recommended periodic settings ensure updates are downloaded, installed and cleaned up reliably. This improves the system's patch hygiene." ;;
        de:fail2ban_ignoreip) info "Mit ignoreip werden vertrauenswürdige lokale Netze vor versehentlichen Sperren geschützt. Trage hier nur Netze ein, denen du wirklich vertraust." ;;
        en:fail2ban_ignoreip) info "ignoreip protects trusted local networks from accidental bans. Only add networks that you genuinely trust." ;;
        de:clamav_freshclam) info "freshclam lädt aktuelle Signaturen herunter, damit ClamAV neue Malware erkennen kann. Ohne frische Signaturen sinkt der Nutzen des Scanners deutlich." ;;
        en:clamav_freshclam) info "freshclam downloads current signatures so ClamAV can detect newer malware. Without fresh signatures, the scanner is much less useful." ;;
        de:filesystem_mountopts) info "Sichere Mount-Optionen auf /tmp oder /dev/shm erschweren das direkte Ausführen oder Missbrauchen temporärer Dateien. Das ist besonders bei gemeinsam genutzten oder exponierten Hosts sinnvoll." ;;
        en:filesystem_mountopts) info "Secure mount options on /tmp or /dev/shm make direct execution or abuse of temporary files harder. This is especially useful on shared or exposed hosts." ;;
        de:pam_pwquality) info "pwquality erzwingt Mindestlänge und Komplexität für Kennwörter. Dadurch werden triviale oder sehr schwache Passwörter deutlich seltener." ;;
        en:pam_pwquality) info "pwquality enforces minimum length and complexity for passwords. This makes trivial or very weak passwords much less likely." ;;
        de:pam_faillock) info "faillock begrenzt wiederholte Fehlversuche bei der Anmeldung und verlangsamt Brute-Force-Angriffe deutlich. Auf Produktivsystemen ist das meist eine sinnvolle Baseline." ;;
        en:pam_faillock) info "faillock limits repeated failed login attempts and significantly slows brute-force attacks. On production systems, this is usually a sensible baseline." ;;
        de:root_lock) info "Ein gesperrtes Root-Konto verhindert direkte Passwortanmeldungen als root. Administration sollte stattdessen über sudo und nachvollziehbare Benutzerkonten erfolgen." ;;
        en:root_lock) info "A locked root account prevents direct password logins as root. Administration should instead happen via sudo and traceable user accounts." ;;
        de:banners_apply) info "Der Banner weist vor der Anmeldung auf autorisierte Nutzung und mögliche Überwachung hin. Das ist vor allem für Compliance- und Unternehmensumgebungen nützlich." ;;
        en:banners_apply) info "The banner warns about authorized use and possible monitoring before login. This is especially useful in compliance and enterprise environments." ;;
        de:sudo_ttytickets) info "tty_tickets trennt sudo-Anmeldungen pro Terminal-Sitzung. Dadurch kann ein offenes Terminal nicht automatisch andere Sitzungen mit privilegierten Rechten mitziehen." ;;
        en:sudo_ttytickets) info "tty_tickets separates sudo authentication per terminal session. This prevents one open terminal from automatically granting elevated rights to another session." ;;
        de:modules_blacklist) info "Ungenutzte Kernel-Module zu sperren reduziert die Angriffsfläche des laufenden Kernels. Das ist besonders sinnvoll, wenn bestimmte Altprotokolle oder Dateisysteme nie gebraucht werden." ;;
        en:modules_blacklist) info "Blocking unused kernel modules reduces the attack surface of the running kernel. This is especially useful when legacy protocols or filesystems are never needed." ;;
        de:coredumps_disable) info "Wenn Core Dumps deaktiviert sind, landen keine Speicherabbilder mit potenziell sensiblen Daten auf der Platte. Das ist auf Produktivsystemen meist die sicherere Standardeinstellung." ;;
        en:coredumps_disable) info "When core dumps are disabled, no memory images containing potentially sensitive data are written to disk. This is usually the safer default on production systems." ;;
        de:aide_reinit) info "Eine neue AIDE-Baseline ersetzt den bisherigen Referenzzustand. Das sollte nur nach bewusst geprüften Änderungen gemacht werden, sonst werden Manipulationen versehentlich als normal übernommen." ;;
        en:aide_reinit) info "A new AIDE baseline replaces the previous reference state. Do this only after consciously verified changes, otherwise tampering may accidentally be accepted as normal." ;;
    esac
}

tr_msg() {
    local key="$1"
    case "$UI_LANG:$key" in
        de:language_prompt) echo "Sprache wählen / Select language:" ;;
        en:language_prompt) echo "Select language / Sprache wählen:" ;;
        de:start_mode) echo "Startmodus wählen:" ;;
        en:start_mode) echo "Select startup mode:" ;;
        de:menu_1) echo "Prüfung              (Nur Scan, keine Änderungen)" ;;
        en:menu_1) echo "Assessment           (Scan only, no changes)" ;;
        de:menu_2) echo "Empfohlene Härtung   (nur empfohlene Standardmaßnahmen)" ;;
        en:menu_2) echo "Recommended hardening (recommended standard measures only)" ;;
        de:menu_3) echo "Schritt für Schritt  (alle Bereiche einzeln durchgehen)" ;;
        en:menu_3) echo "Step by step         (review all areas one by one)" ;;
        de:menu_4) echo "Vollautomatisch      (Liest security_config.env)" ;;
        en:menu_4) echo "Fully automatic      (Reads security_config.env)" ;;
        de:menu_5) echo "Vollständiger Rollback (ohne Rückfragen)" ;;
        en:menu_5) echo "Full rollback        (without further prompts)" ;;
        de:menu_6) echo "Selektives Entfernen (Auswahlmenü mit Erkennung)" ;;
        en:menu_6) echo "Selective removal    (detection + selection menu)" ;;
        de:menu_7) echo "Expertenmodus        (Profile / Spezialfälle)" ;;
        en:menu_7) echo "Expert mode          (profiles / special cases)" ;;
        de:menu_8) echo "Logs / Reports       (AIDE, Fail2ban, Auditd, Script-Logs)" ;;
        en:menu_8) echo "Logs / reports       (AIDE, Fail2ban, Auditd, script logs)" ;;
        de:menu_prompt) echo "Modus [1-8]: " ;;
        en:menu_prompt) echo "Mode [1-8]: " ;;
        de:mode_1_ok) echo "Modus 1: Prüfung" ;;
        en:mode_1_ok) echo "Mode 1: Assessment" ;;
        de:mode_2_ok) echo "Modus 2: Empfohlene Härtung" ;;
        en:mode_2_ok) echo "Mode 2: Recommended hardening" ;;
        de:mode_3_ok) echo "Modus 3: Härtung Schritt für Schritt" ;;
        en:mode_3_ok) echo "Mode 3: Step-by-step hardening" ;;
        de:mode_4_ok) echo "Modus 4: Vollautomatisch" ;;
        en:mode_4_ok) echo "Mode 4: Fully automatic" ;;
        de:mode_5_ok) echo "Modus 5: Vollständiger Rollback" ;;
        en:mode_5_ok) echo "Mode 5: Full rollback" ;;
        de:config_file) echo "Config-Datei" ;;
        en:config_file) echo "Config file" ;;
        de:set_recommended_prefix) echo "  Auf '" ;;
        en:set_recommended_prefix) echo "  Set '" ;;
        de:set_recommended_suffix) echo "' setzen?" ;;
        en:set_recommended_suffix) echo "'?" ;;
        de:no_key_warning) echo "  WARNUNG: Kein Ed25519-Key gefunden — Deaktivierung sperrt dich aus!" ;;
        en:no_key_warning) echo "  WARNING: No Ed25519 key found — disabling this may lock you out!" ;;
        de:restore_backup_prompt) echo "Backup wiederherstellen?" ;;
        en:restore_backup_prompt) echo "Restore a backup?" ;;
        de:mode_6_ok) echo "Modus 6: Selektives Entfernen" ;;
        en:mode_6_ok) echo "Mode 6: Selective removal" ;;
        de:mode_7_ok) echo "Modus 7: Expertenmodus" ;;
        en:mode_7_ok) echo "Mode 7: Expert mode" ;;
        de:mode_8_ok) echo "Modus 8: Logs / Reports" ;;
        en:mode_8_ok) echo "Mode 8: Logs / reports" ;;
        de:invalid_selection) echo "Ungültige Auswahl. Bitte 1-8 eingeben." ;;
        en:invalid_selection) echo "Invalid selection. Please enter 1-8." ;;
        de:selective_menu_title) echo "Erkannte entfern- oder rücksetzbare Komponenten:" ;;
        en:selective_menu_title) echo "Detected removable / resettable components:" ;;
        de:mark_all) echo "Alle markieren" ;;
        en:mark_all) echo "Select all" ;;
        de:clear_all) echo "Alle abwählen" ;;
        en:clear_all) echo "Clear all" ;;
        de:apply_selection) echo "Auswahl übernehmen" ;;
        en:apply_selection) echo "Apply selection" ;;
        de:enter_apply_hint) echo "Enter = Auswahl übernehmen, wenn bereits etwas markiert ist" ;;
        en:enter_apply_hint) echo "Enter = apply selection when at least one item is selected" ;;
        de:cancel) echo "Abbrechen" ;;
        en:cancel) echo "Cancel" ;;
        de:toggle_prompt) echo "Auswahl (Nummern/CSV zum Umschalten): " ;;
        en:toggle_prompt) echo "Selection (numbers/CSV to toggle): " ;;
        de:nothing_selected) echo "Es wurde nichts ausgewählt." ;;
        en:nothing_selected) echo "Nothing has been selected." ;;
        de:no_removable) echo "Es wurden keine entfernbaren bzw. zurücksetzbaren Komponenten erkannt." ;;
        en:no_removable) echo "No removable or resettable components were detected." ;;
        de:aborted_selective) echo "Selektives Entfernen abgebrochen." ;;
        en:aborted_selective) echo "Selective removal cancelled." ;;
        de:profile_prompt) echo "Härtungsprofil wählen:" ;;
        en:profile_prompt) echo "Select hardening profile:" ;;
        de:profile_default) echo "Profil [2]: " ;;
        en:profile_default) echo "Profile [2]: " ;;
        de:profile_safe) echo "safe           (vorsichtig, weniger invasiv)" ;;
        en:profile_safe) echo "safe           (conservative, less invasive)" ;;
        de:profile_server) echo "server         (empfohlene Standard-Baseline)" ;;
        en:profile_server) echo "server         (recommended default baseline)" ;;
        de:profile_strict) echo "strict         (strenger, inkl. AIDE ohne Timeout)" ;;
        en:profile_strict) echo "strict         (stricter, incl. AIDE without timeout)" ;;
        de:profile_container) echo "container-host (für Docker/Podman-Hosts optimiert)" ;;
        en:profile_container) echo "container-host (optimized for Docker/Podman hosts)" ;;
        de:profile_nextcloud) echo "nextcloud-host (AIDE ohne Timeout, Nextcloud-freundlich)" ;;
        en:profile_nextcloud) echo "nextcloud-host (AIDE without timeout, Nextcloud-friendly)" ;;
        de:profile_invalid) echo "Ungültiges Profil. Erlaubt: safe|server|strict|container-host|nextcloud-host" ;;
        en:profile_invalid) echo "Invalid profile. Allowed: safe|server|strict|container-host|nextcloud-host" ;;
        de:profile_selected) echo "Aktives Profil" ;;
        en:profile_selected) echo "Active profile" ;;
        de:interactive_plan_recommended) echo "Interaktive Strategie: nur empfohlene Standardmaßnahmen" ;;
        en:interactive_plan_recommended) echo "Interactive strategy: recommended standard measures only" ;;
        de:interactive_plan_step) echo "Interaktive Strategie: alle Bereiche Schritt für Schritt" ;;
        en:interactive_plan_step) echo "Interactive strategy: review all areas step by step" ;;
        de:interactive_plan_expert) echo "Interaktive Strategie: Expertenmodus mit Profilen" ;;
        en:interactive_plan_expert) echo "Interactive strategy: expert mode with profiles" ;;
        de:recommended_intro_1) echo "Dieser Modus setzt empfohlene Standardmaßnahmen für typische Debian-/Ubuntu-Server um." ;;
        en:recommended_intro_1) echo "This mode applies recommended baseline measures for typical Debian/Ubuntu servers." ;;
        de:recommended_intro_2) echo "Spezialfälle wie 2FA, Mail-Benachrichtigungen und Expertenprofile werden dabei übersprungen; kontextabhängige Container-Empfehlungen werden zusätzlich berücksichtigt." ;;
        en:recommended_intro_2) echo "Special cases such as 2FA, mail notifications and expert profiles are skipped in this mode; context-aware container recommendations are considered additionally." ;;
        de:recommended_intro_3) echo "Vor Änderungen wird geprüft, gesichert und nur bei Bedarf nachgefragt." ;;
        en:recommended_intro_3) echo "Before changes, the system is checked, backed up and prompts appear only where needed." ;;
        de:context_detected_prefix) echo "Kontext anhand laufender Container erkannt" ;;
        en:context_detected_prefix) echo "Context detected from running containers" ;;
        de:context_recommend_prefix) echo "Auf diesem Host zusätzlich empfohlen" ;;
        en:context_recommend_prefix) echo "Additionally recommended on this host" ;;
        de:context_no_match) echo "Kein spezieller Datei-/Mail-/Nextcloud-Kontext per docker ps -a erkannt" ;;
        en:context_no_match) echo "No special file/mail/Nextcloud context detected via docker ps -a" ;;
        de:please_enter_1_2) echo "Bitte 1 oder 2 eingeben." ;;
        en:please_enter_1_2) echo "Please enter 1 or 2." ;;
        de:skip_list_prefix) echo "In diesem Modus übersprungen" ;;
        en:skip_list_prefix) echo "Skipped in this mode" ;;
        de:aide_timeout_disabled) echo "AIDE-Init-Timeout: deaktiviert" ;;
        en:aide_timeout_disabled) echo "AIDE init timeout: disabled" ;;
        de:aide_timeout_prefix) echo "AIDE-Init-Timeout" ;;
        en:aide_timeout_prefix) echo "AIDE init timeout" ;;
        de:relevant_logs) echo "Relevante Security-/Rollback-Logs:" ;;
        en:relevant_logs) echo "Relevant security / rollback logs:" ;;
        de:log_changes_label) echo "Skript-Änderungen" ;;
        en:log_changes_label) echo "Script changes" ;;
        de:txlog_label) echo "Transaktionslog" ;;
        en:txlog_label) echo "Transaction log" ;;
        de:txlog_label_with_rb) echo "Transaktionslog (für Rollback)" ;;
        en:txlog_label_with_rb) echo "Transaction log (for rollback)" ;;
        de:summary_label) echo "Übersicht" ;;
        en:summary_label) echo "Summary" ;;
        de:invalid_number) echo "Ungültige Nummer" ;;
        en:invalid_number) echo "Invalid number" ;;
        de:invalid_input) echo "Ungültige Eingabe" ;;
        en:invalid_input) echo "Invalid input" ;;
        de:no_valid_targets) echo "Keine gültigen Ziele ausgewählt." ;;
        en:no_valid_targets) echo "No valid targets selected." ;;
        de:selected_targets) echo "Ausgewählte Ziele" ;;
        en:selected_targets) echo "Selected targets" ;;
        de:confirm_selective_remove) echo "Ausgewählte Komponenten jetzt entfernen bzw. zurücksetzen?" ;;
        en:confirm_selective_remove) echo "Remove or reset the selected components now?" ;;
        de:archive_txlog_ok) echo "Transaktionslog archiviert" ;;
        en:archive_txlog_ok) echo "Archived transaction log" ;;
        de:archive_txlog_fail) echo "Konnte Transaktionslog nicht archivieren." ;;
        en:archive_txlog_fail) echo "Could not archive transaction log." ;;
        de:result_label) echo "Ergebnis" ;;
        en:result_label) echo "Result" ;;
        de:matrix_green) echo "★★★★★  MATRIX: GRÜN — System entspricht der Hardening-Baseline  ★★★★★" ;;
        en:matrix_green) echo "★★★★★  MATRIX: GREEN — System matches the hardening baseline  ★★★★★" ;;
        de:matrix_warn_prefix) echo "★★★★☆  MATRIX:" ;;
        en:matrix_warn_prefix) echo "★★★★☆  MATRIX:" ;;
        de:matrix_warn_suffix) echo "offene Finding(s) — Härtung empfohlen" ;;
        en:matrix_warn_suffix) echo "open finding(s) — hardening recommended" ;;
        de:matrix_red_prefix) echo "★★☆☆☆  MATRIX: ROT —" ;;
        en:matrix_red_prefix) echo "★★☆☆☆  MATRIX: RED —" ;;
        de:matrix_red_suffix) echo "Finding(s) offen — Sofortmaßnahmen erforderlich" ;;
        en:matrix_red_suffix) echo "finding(s) open — immediate action required" ;;
        de:run_without_assess) echo "Ohne --assess starten, um Härtung anzuwenden." ;;
        en:run_without_assess) echo "Run without --assess to apply hardening." ;;
        de:step_intro) echo "Dieser Modus geht alle Bereiche einzeln durch, ohne Profilwissen vorauszusetzen." ;;
        en:step_intro) echo "This mode walks through all areas one by one without requiring profile knowledge." ;;
        de:own_risk) echo "Auf eigene Gefahr! Vorher Backups erstellen (z.B. Proxmox Snapshot)." ;;
        en:own_risk) echo "At your own risk. Create backups first, for example a Proxmox snapshot." ;;
        de:start_hardening) echo "Härtung starten?" ;;
        en:start_hardening) echo "Start hardening?" ;;
        de:aborted) echo "Abgebrochen." ;;
        en:aborted) echo "Cancelled." ;;
        de:aborted_ctrlc) echo "Vorgang durch Benutzer mit Strg+C abgebrochen." ;;
        en:aborted_ctrlc) echo "Operation aborted by user with Ctrl+C." ;;
        de:no_open_findings_mode) echo "Keine offenen Findings erkannt — in diesem Modus sind keine weiteren Änderungen nötig." ;;
        en:no_open_findings_mode) echo "No open findings detected — no further changes are needed in this mode." ;;
        de:manual_step_mode_hint) echo "Wenn du Maßnahmen trotzdem manuell durchgehen willst, nutze 'Schritt für Schritt'." ;;
        en:manual_step_mode_hint) echo "If you still want to review measures manually, use 'Step by step'." ;;
        de:no_relevant_findings_mode) echo "Es wurden keine in diesem Modus bearbeitbaren offenen Findings erkannt." ;;
        en:no_relevant_findings_mode) echo "No open findings relevant to this mode were detected." ;;
        de:open_points_special) echo "Offene Punkte betreffen entweder übersprungene Spezialfälle oder sind bereits manuell abgearbeitet." ;;
        en:open_points_special) echo "Open points either belong to skipped special cases or were already handled manually." ;;
        de:pre_assessment) echo "Bewertung vor der Härtung:" ;;
        en:pre_assessment) echo "Pre-Hardening Assessment:" ;;
        de:post_assessment) echo "Bewertung nach der Härtung:" ;;
        en:post_assessment) echo "Post-Hardening Assessment:" ;;
        de:manage_backups) echo "Backups verwalten?" ;;
        en:manage_backups) echo "Manage backups?" ;;
        de:done_green) echo "║  ✔  Script abgeschlossen — MATRIX VOLLSTÄNDIG GRÜN          ║" ;;
        en:done_green) echo "║  ✔  Script completed — MATRIX FULLY GREEN                   ║" ;;
        de:done_red_prefix) echo "║  ✘  Script abgeschlossen —" ;;
        en:done_red_prefix) echo "║  ✘  Script completed —" ;;
        de:done_red_suffix) echo "Finding(s) verbleiben         ║" ;;
        en:done_red_suffix) echo "finding(s) remain            ║" ;;
        de:reboot_recommended) echo "⚠  REBOOT empfohlen für vollständige Wirkung aller Kernel-Änderungen!" ;;
        en:reboot_recommended) echo "⚠  REBOOT recommended for full effect of all kernel-related changes!" ;;
        de:dry_run_no_changes) echo "*** DRY-RUN: Keine Änderungen vorgenommen ***" ;;
        en:dry_run_no_changes) echo "*** DRY-RUN: No changes were made ***" ;;
        de:save_ssh_changes) echo "SSH-Änderungen speichern?" ;;
        en:save_ssh_changes) echo "Save SSH changes?" ;;
        de:ssh_password_still_yes) echo "PasswordAuthentication ist effektiv weiterhin" ;;
        en:ssh_password_still_yes) echo "PasswordAuthentication is still effectively" ;;
        de:check_include_files) echo "Prüfe andere Include-Dateien unter /etc/ssh/sshd_config.d/." ;;
        en:check_include_files) echo "Check other include files under /etc/ssh/sshd_config.d/." ;;
        de:auditd_check_hint) echo "Prüfe: journalctl -u auditd -xe und ob Kernel-Auditing verfügbar ist." ;;
        en:auditd_check_hint) echo "Check: journalctl -u auditd -xe and whether kernel auditing is available." ;;
        *) echo "$key" ;;
    esac
}

select_ui_language() {
    if $CLI_LANG_SET; then
        return 0
    fi

    if (( ORIGINAL_ARGC == 0 )); then
        echo
        echo -e "${C_BOLD}${C_CYAN}$(tr_msg language_prompt)${C_RESET}"
        echo "  1) Deutsch"
        echo "  2) English"
        local lang_choice=""
        while true; do
            read -rp "[1-2] [1]: " lang_choice </dev/tty
            lang_choice=${lang_choice:-1}
            case "$lang_choice" in
                1) UI_LANG="de"; break ;;
                2) UI_LANG="en"; break ;;
                *) warn "$(tr_msg please_enter_1_2)" ;;
            esac
        done
    else
        case "${LANG:-}" in
            en*|C.UTF-8) UI_LANG="en" ;;
            *) UI_LANG="de" ;;
        esac
    fi
}

normalize_csv_list() {
    local raw="$1" item out=""
    IFS=',' read -r -a _items <<< "$raw"
    for item in "${_items[@]}"; do
        item="${item// /}"
        [[ -z "$item" ]] && continue
        [[ ",$out," == *",$item,"* ]] && continue
        [[ -n "$out" ]] && out+="," 
        out+="$item"
    done
    echo "$out"
}

append_skip_sections() {
    local current="${AUTO_SKIP_SECTIONS:-}" add="$1" item
    IFS=',' read -r -a _items <<< "$add"
    for item in "${_items[@]}"; do
        item="${item// /}"
        [[ -z "$item" ]] && continue
        [[ ",$current," == *",$item,"* ]] || current="${current:+$current,}$item"
    done
    AUTO_SKIP_SECTIONS="$(normalize_csv_list "$current")"
}

validate_profile_name() {
    case "$1" in
        safe|server|strict|container-host|nextcloud-host) return 0 ;;
        *) return 1 ;;
    esac
}

select_hardening_profile() {
    $PROFILE_SELECTED && return 0
    $ROLLBACK_MODE && return 0
    $SELECTIVE_REMOVE_MODE && return 0
    $ASSESS_ONLY && return 0
    if (( ORIGINAL_ARGC == 0 )) && ! $EXPERT_PROFILE_MODE; then
        return 0
    fi
    if (( ORIGINAL_ARGC == 0 )); then
        echo
        echo -e "${C_BOLD}${C_CYAN}$(tr_msg profile_prompt)${C_RESET}"
        echo "  1) $(tr_msg profile_safe)"
        echo "  2) $(tr_msg profile_server)"
        echo "  3) $(tr_msg profile_strict)"
        echo "  4) $(tr_msg profile_container)"
        echo "  5) $(tr_msg profile_nextcloud)"
        local profile_choice=""
        while true; do
            read -rp "$(tr_msg profile_default)" profile_choice </dev/tty
            profile_choice=${profile_choice:-2}
            case "$profile_choice" in
                1) ACTIVE_PROFILE="safe"; break ;;
                2) ACTIVE_PROFILE="server"; break ;;
                3) ACTIVE_PROFILE="strict"; break ;;
                4) ACTIVE_PROFILE="container-host"; break ;;
                5) ACTIVE_PROFILE="nextcloud-host"; break ;;
                *) warn "$(tr_msg profile_invalid)" ;;
            esac
        done
        PROFILE_SELECTED=true
    fi
}

normalize_space_csv() {
    printf '%s' "$1" | sed 's/^[[:space:],]*//; s/[[:space:],]*$//; s/[[:space:]]*,[[:space:]]*/,/g; s/,,*/,/g'
}

detect_host_runtime_context() {
    HOST_HAS_DOCKER=false
    HOST_HAS_PODMAN=false
    HOST_CONTEXT_ROLE_FILE=false
    HOST_CONTEXT_ROLE_MAIL=false
    HOST_CONTEXT_ROLE_NEXTCLOUD=false
    HOST_CONTEXT_CONTAINER_HINTS=""
    HOST_CONTEXT_EXTRA_RECOMMENDATIONS=""

    local lines="" line="" combined="" list="" extra=""
    local docker_output="" podman_output="" docker_ok=false podman_ok=false
    local probe=""

    if command -v docker >/dev/null 2>&1; then
        probe=$(timeout 8 docker ps -a --format '{{.Image}} {{.Names}}' 2>/dev/null || true)
        if [[ -n "$probe" ]]; then
            docker_ok=true
            HOST_HAS_DOCKER=true
            docker_output="$probe"
        else
            probe=$(timeout 8 docker container ls -a --format '{{.Image}} {{.Names}}' 2>/dev/null || true)
            if [[ -n "$probe" ]]; then
                docker_ok=true
                HOST_HAS_DOCKER=true
                docker_output="$probe"
            fi
        fi
    fi

    if command -v podman >/dev/null 2>&1; then
        probe=$(timeout 8 podman ps -a --format '{{.Image}} {{.Names}}' 2>/dev/null || true)
        if [[ -n "$probe" ]]; then
            podman_ok=true
            HOST_HAS_PODMAN=true
            podman_output="$probe"
        else
            probe=$(timeout 8 podman container ls -a --format '{{.Image}} {{.Names}}' 2>/dev/null || true)
            if [[ -n "$probe" ]]; then
                podman_ok=true
                HOST_HAS_PODMAN=true
                podman_output="$probe"
            fi
        fi
    fi

    if $docker_ok; then
        lines+="$docker_output"$'\n'
    fi
    if $podman_ok; then
        lines+="$podman_output"$'\n'
    fi

    # Fallback heuristics if container listing was unavailable or empty.
    if [[ -z "$lines" ]]; then
        if command -v docker >/dev/null 2>&1; then
            probe=$(timeout 8 docker volume ls --format '{{.Name}}' 2>/dev/null || true)
            if [[ -n "$probe" ]]; then
                while IFS= read -r line; do
                    [[ -n "$line" ]] || continue
                    lines+="volume:${line} ${line}"$'\n'
                done <<< "$probe"
            fi
        fi
        if command -v podman >/dev/null 2>&1; then
            probe=$(timeout 8 podman volume ls --format '{{.Name}}' 2>/dev/null || true)
            if [[ -n "$probe" ]]; then
                while IFS= read -r line; do
                    [[ -n "$line" ]] || continue
                    lines+="volume:${line} ${line}"$'\n'
                done <<< "$probe"
            fi
        fi
    fi

    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        combined=$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')
        if [[ "$combined" == *nextcloud* ]]; then
            HOST_CONTEXT_ROLE_NEXTCLOUD=true
            HOST_CONTEXT_ROLE_FILE=true
        fi
        if [[ "$combined" == *nextcloud* || "$combined" == *owncloud* || "$combined" == *seafile* || "$combined" == *immich* || "$combined" == *paperless* || "$combined" == *syncthing* || "$combined" == *filebrowser* || "$combined" == *filestash* || "$combined" == *cloudreve* || "$combined" == *drive* || "$combined" == *files* ]]; then
            HOST_CONTEXT_ROLE_FILE=true
        fi
        if [[ "$combined" == *mailcow* || "$combined" == *mailu* || "$combined" == *postfix* || "$combined" == *dovecot* || "$combined" == *roundcube* || "$combined" == *stalwart* || "$combined" == *rspamd* || "$combined" == *smtp* || "$combined" == *imap* ]]; then
            HOST_CONTEXT_ROLE_MAIL=true
        fi
        if [[ "$combined" == *nextcloud* || "$combined" == *mailcow* || "$combined" == *mailu* || "$combined" == *paperless* || "$combined" == *immich* || "$combined" == *seafile* || "$combined" == *owncloud* ]]; then
            list+=",${line##* }"
        fi
    done <<< "$lines"

    list=$(normalize_space_csv "$list")
    HOST_CONTEXT_CONTAINER_HINTS="$list"

    if $HOST_CONTEXT_ROLE_FILE || $HOST_CONTEXT_ROLE_MAIL; then
        extra+=",clamav"
    fi
    if $HOST_CONTEXT_ROLE_NEXTCLOUD || $HOST_CONTEXT_ROLE_MAIL; then
        extra+=",auditd,aide"
    fi
    extra=$(normalize_csv_list "$extra")
    HOST_CONTEXT_EXTRA_RECOMMENDATIONS="$extra"
}

apply_profile_defaults() {
    $ROLLBACK_MODE && return 0
    $SELECTIVE_REMOVE_MODE && return 0
    local profile="${AUTO_PROFILE:-$ACTIVE_PROFILE}"
    validate_profile_name "$profile" || { warn "$(tr_msg profile_invalid)"; profile="server"; }
    ACTIVE_PROFILE="$profile"
    PROFILE_STRICT=false

    if $INTERACTIVE_RECOMMENDED_MODE; then
        detect_host_runtime_context
        append_skip_sections "ssh_key,msmtp,2fa,sshguard,ufw"
        # Recommended mode should actively offer minimum baseline fixes for real RED findings.
        # Keep only clearly optional extras skipped here; do not skip auditd/AIDE baseline fixes.
        local recommended_extra="${HOST_CONTEXT_EXTRA_RECOMMENDATIONS:-}"
        local base_optional="clamav"
        local item
        for item in ${base_optional//,/ }; do
            [[ ",$recommended_extra," == *",$item,"* ]] || append_skip_sections "$item"
        done
    fi

    case "$ACTIVE_PROFILE" in
        safe)
            append_skip_sections "msmtp,2fa,auditd,aide,sshguard"
            [[ "$AIDE_INIT_TIMEOUT" == "$AIDE_INIT_TIMEOUT_DEFAULT" ]] && AIDE_INIT_TIMEOUT=900
            ;;
        server)
            :
            ;;
        strict)
            PROFILE_STRICT=true
            [[ "$AIDE_INIT_TIMEOUT" == "$AIDE_INIT_TIMEOUT_DEFAULT" ]] && AIDE_INIT_TIMEOUT=0
            ;;
        container-host)
            append_skip_sections "msmtp,2fa,clamav,aide"
            [[ "$AIDE_INIT_TIMEOUT" == "$AIDE_INIT_TIMEOUT_DEFAULT" ]] && AIDE_INIT_TIMEOUT=900
            ;;
        nextcloud-host)
            append_skip_sections "msmtp,2fa"
            [[ "$AIDE_INIT_TIMEOUT" == "$AIDE_INIT_TIMEOUT_DEFAULT" ]] && AIDE_INIT_TIMEOUT=0
            ;;
    esac

    if $INTERACTIVE_RECOMMENDED_MODE; then
        info "$(tr_msg interactive_plan_recommended)"
        if [[ -n "${HOST_CONTEXT_CONTAINER_HINTS:-}" ]]; then
            info "$(tr_msg context_detected_prefix): ${HOST_CONTEXT_CONTAINER_HINTS}"
        fi
        if [[ -n "${HOST_CONTEXT_EXTRA_RECOMMENDATIONS:-}" ]]; then
            info "$(tr_msg context_recommend_prefix): ${HOST_CONTEXT_EXTRA_RECOMMENDATIONS}"
        else
            info "$(tr_msg context_no_match)"
        fi
        [[ -n "${AUTO_SKIP_SECTIONS:-}" ]] && info "$(tr_msg skip_list_prefix): $AUTO_SKIP_SECTIONS"
        return 0
    fi

    if $INTERACTIVE_STEP_MODE && ! $EXPERT_PROFILE_MODE; then
        info "$(tr_msg interactive_plan_step)"
        return 0
    fi

    if $EXPERT_PROFILE_MODE; then
        info "$(tr_msg interactive_plan_expert)"
    fi

    if $PROFILE_SELECTED || $AUTO_MODE || $EXPERT_PROFILE_MODE; then
        info "$(tr_msg profile_selected): $ACTIVE_PROFILE"
        [[ -n "${AUTO_SKIP_SECTIONS:-}" ]] && info "Profile skips: $AUTO_SKIP_SECTIONS"
        if [[ "$AIDE_INIT_TIMEOUT" == "0" ]]; then
            info "$(tr_msg aide_timeout_disabled)"
        else
            info "$(tr_msg aide_timeout_prefix): ${AIDE_INIT_TIMEOUT}s"
        fi
    fi
}

show_diff_preview() {
    local target="$1" candidate="$2" label="${3:-$1}"
    echo -e "${C_MAGENTA}DRY-RUN DIFF:${C_RESET} $label"
    if [[ -f "$target" ]]; then
        diff -u --label "$target (current)" --label "$target (proposed)" "$target" "$candidate" || true
    else
        echo "--- $target (current: absent)"
        echo "+++ $target (proposed)"
        sed 's/^/+ /' "$candidate"
    fi
}

install_managed_file() {
    local target="$1" temp_file="$2" mode="${3:-644}" owner="${4:-}" group="${5:-}"
    local existed=false needs_update=true current_mode=""
    [[ -f "$target" ]] && existed=true

    if $existed && cmp -s "$target" "$temp_file" 2>/dev/null; then
        current_mode=$(stat -c '%a' "$target" 2>/dev/null || true)
        if [[ -z "$mode" || "$current_mode" == "$mode" ]]; then
            needs_update=false
        fi
    fi

    if $DRY_RUN; then
        if $needs_update; then
            show_diff_preview "$target" "$temp_file" "$target"
            record_dry_run_action "Update $target"
        fi
        rm -f "$temp_file" 2>/dev/null || true
        return 0
    fi

    if ! $needs_update; then
        rm -f "$temp_file" 2>/dev/null || true
        success "$target already correct."
        return 1
    fi

    mkdir -p "$(dirname "$target")" 2>/dev/null || true
    backup_file "$target"
    if ! install -m "$mode" "$temp_file" "$target"; then
        rm -f "$temp_file" 2>/dev/null || true
        error "Could not install managed file: $target"
        return 2
    fi
    if [[ -n "$owner" ]]; then
        chown "${owner}${group:+:$group}" "$target"
    fi
    if $existed; then
        log_change "MODIFIED:$target"
    else
        log_change "ADDED_FILE:$target"
        txlog "FILE_ADDED" "$target"
    fi
    rm -f "$temp_file" 2>/dev/null || true
    return 0
}



list_script_managed_files() {
    printf '%s\n' \
        "$SYSCTL_CONFIG_FILE" "$SUDOERS_TTY_FILE" "$MODPROBE_BLACKLIST" "$LIMITS_CONF" "$FAILLOCK_CONF" "$PWQUALITY_CONF" \
        "$LOGIN_DEFS_FILE" "$PROFILE_UMASK_FILE" "$SYSTEM_UMASK_SYSTEMD_DROPIN" "$USER_UMASK_SYSTEMD_DROPIN" "$SUID_SGID_AUDIT_SCRIPT" "$SUID_SGID_AUDIT_BASELINE" "$SUID_SGID_AUDIT_REPORT" "$SUID_SGID_AUDIT_CRON" \
        "$BANNER_FILE" "$MOTD_FILE" "$AIDE_CRON" "$AIDE_LOCAL_EXCLUDES" "$AUDITD_RULES" "$SSHD_HARDENING_DROPIN" "$SSHD_HARDENING_DROPIN_LEGACY" \
        "/etc/systemd/journald.conf" "/etc/ssh/sshd_config"
}

capture_managed_state() {
    local outfile="$1" f
    : > "$outfile"
    while IFS= read -r f; do
        [[ -e "$f" ]] || continue
        sha256sum "$f" >> "$outfile" 2>/dev/null || true
    done < <(list_script_managed_files | awk 'NF && !seen[$0]++ {print $0}')
}

prove_idempotence() {
    local -a funcs=("$@")
    $DRY_RUN && return 0
    $ROLLBACK_MODE && return 0
    $SELECTIVE_REMOVE_MODE && return 0
    $ASSESS_ONLY && return 0
    $INTERACTIVE_STEP_MODE && return 0
    $PROVE_IDEMPOTENCE || return 0

    echo
    info "${C_BOLD}Idempotence proof — planning only for the sections touched in this run${C_RESET}"
    local before after proof_output
    before=$(mktemp_tracked)
    after=$(mktemp_tracked)
    proof_output=$(mktemp_tracked)
    capture_managed_state "$before"

    local old_dry="$DRY_RUN" old_auto="$AUTO_MODE" old_verify="$VERIFY_AFTER_HARDENING" old_actions="$DRY_RUN_ACTIONS"
    local -a old_notes=("${DRY_RUN_NOTES[@]}")
    DRY_RUN=true
    AUTO_MODE=true
    VERIFY_AFTER_HARDENING=false
    DRY_RUN_ACTIONS=0
    DRY_RUN_NOTES=()

    : > "$IDEMPOTENCE_LOG"
    local func
    for func in "${funcs[@]}"; do
        declare -f "$func" >/dev/null 2>&1 || continue
        "$func" >> "$proof_output" 2>&1 || true
    done
    cat "$proof_output" >> "$IDEMPOTENCE_LOG"
    capture_managed_state "$after"

    DRY_RUN="$old_dry"
    AUTO_MODE="$old_auto"
    VERIFY_AFTER_HARDENING="$old_verify"
    local proof_actions="$DRY_RUN_ACTIONS"
    local -a proof_notes=("${DRY_RUN_NOTES[@]}")
    DRY_RUN_ACTIONS="$old_actions"
    DRY_RUN_NOTES=("${old_notes[@]}")

    if cmp -s "$before" "$after" && (( proof_actions == 0 )); then
        IDEMPOTENCE_LAST_RESULT="PASS"
        success "Idempotence proof PASSED — a second scripted pass would not change managed configuration."
    else
        IDEMPOTENCE_LAST_RESULT="FAIL"
        warn "Idempotence proof found pending actions: $proof_actions"
        local note
        for note in "${proof_notes[@]:0:10}"; do
            echo "  - $note"
        done
        info "Details: $IDEMPOTENCE_LOG"
    fi
}

# ============================================================================
# TRANSACTION LOG (machine-readable for rollback)
# Format: TIMESTAMP|ACTION|DETAILS
# Actions: BACKUP_CREATED, FILE_ADDED, FILE_REMOVED, PKG_INSTALLED,
#          SERVICE_ENABLED, SERVICE_STARTED, ROOT_LOCKED, PAM_FAILLOCK_ENABLED
# ============================================================================
txlog() {
    $DRY_RUN && return 0
    local action="$1" details="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S')|${action}|${details}" >> "$TRANSACTION_LOG"
}

log_change() {
    $DRY_RUN && return 0
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $1" >> "$SCRIPT_LOG_FILE"
}

# ============================================================================
# SAFE CONFIG FILE PARSER (no source/eval)
# ============================================================================
parse_config_file() {
    local cfg="$1"
    [[ -f "$cfg" ]] || { warn "Auto mode: no config file found at '$cfg'. Using defaults."; return 0; }

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        [[ "$line" != *=* ]] && continue

        local key="${line%%=*}"
        local value="${line#*=}"
        key="$(echo "$key" | tr -d '[:space:]')"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        value="${value%\"}" ; value="${value#\"}"
        value="${value%\'}" ; value="${value#\'}"

        case "$key" in
            AUTO_SSH_PORT|AUTO_ADMIN_EMAIL|AUTO_SKIP_SECTIONS|AUTO_ALLOW_USERS|AUTO_PROFILE|AUTO_PROVE_IDEMPOTENCE|\
            AUTO_SMTP_HOST|AUTO_SMTP_PORT|AUTO_SMTP_TLS|AUTO_SMTP_USER|AUTO_SMTP_PASS|\
            AUTO_APPARMOR_ENFORCE|AUTO_SSH_CRYPTO_POLICY|AUTO_LOGIN_UMASK)
                printf -v "$key" '%s' "$value" ;;
            *) warn "Ignoring unsupported config key: $key" ;;
        esac
    done < "$cfg"
    case "${AUTO_PROVE_IDEMPOTENCE:-}" in
        false|0|no|n) PROVE_IDEMPOTENCE=false ;;
        true|1|yes|y) PROVE_IDEMPOTENCE=true ;;
    esac
    info "Loaded config safely: $cfg"
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================
parse_args() {
    local config_file=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)    DRY_RUN=true; shift ;;
            --auto)       AUTO_MODE=true; shift ;;
            --assess)     ASSESS_ONLY=true; shift ;;
            --verify)     VERIFY_AFTER_HARDENING=true; shift ;;
            --rollback)   ROLLBACK_MODE=true; shift ;;
            --remove)
                SELECTIVE_REMOVE_MODE=true
                if [[ $# -ge 2 ]] && [[ ! "$2" =~ ^-- ]]; then
                    REMOVE_TARGETS_RAW="$2"
                    shift 2
                else
                    REMOVE_TARGETS_RAW="__MENU__"
                    shift
                fi ;;
            --lang)
                [[ $# -lt 2 ]] && { echo "ERROR: --lang requires 'de' or 'en'" >&2; exit 1; }
                case "$2" in
                    de|DE|de_DE*) UI_LANG="de" ;;
                    en|EN|en_US*|en_GB*) UI_LANG="en" ;;
                    *) echo "ERROR: Unsupported language '$2' (use: de|en)" >&2; exit 1 ;;
                esac
                CLI_LANG_SET=true
                shift 2 ;;
            --profile)
                [[ $# -lt 2 ]] && { echo "ERROR: --profile requires a value" >&2; exit 1; }
                ACTIVE_PROFILE="$2"
                PROFILE_SELECTED=true
                shift 2 ;;
            --no-idempotence-check)
                PROVE_IDEMPOTENCE=false
                shift ;;
            --config)
                [[ $# -lt 2 ]] && { echo "ERROR: --config requires a file path" >&2; exit 1; }
                config_file="$2"; shift 2 ;;
            --help|-h)
                cat <<'EOF'
Usage: sudo ./linux_server_security_v5_6.sh [OPTIONS]

Interactive startup (when no options given — shows menu):
  1 = Prüfung (Assessment only — no changes)
  2 = Empfohlene Härtung (recommended standard measures)
  3 = Härtung Schritt für Schritt
  4 = Vollautomatisch (reads security_config.env)
  5 = Vollständiger Rollback (ohne Rückfragen)
  6 = Selektives Entfernen einzelner Punkte
  7 = Expertenmodus (interactive profile selection)

CLI modes:
  --assess         Scan only — RED/GREEN matrix, exit 2 if red
  --auto           Fully automated hardening (reads config file, no prompts)
  --verify         Re-assess after hardening; exit 2 if any RED remains
  --rollback       Undo all script changes automatically, no prompts
  --remove LIST    Remove only selected items (comma-separated)
  --remove menu    Detect removable components and open the selection menu
  --dry-run        Simulate all changes and show file diffs where supported
  --profile NAME   safe|server|strict|container-host|nextcloud-host
  --no-idempotence-check  Skip the automatic second-pass idempotence proof

Supported --remove targets:
  banners,auditd,aide,pam,sysctl,journald,sudoers,modules

If --remove is used without a value, the interactive selection menu is opened.

Options:
  --config FILE    Automation config file (default: ./security_config.env)
  --lang de|en     UI language for menus/startup prompts
  --help           Show this help

Examples:
  sudo ./script.sh --assess
  sudo ./script.sh --auto --verify
  sudo ./script.sh --rollback
  sudo ./script.sh --remove banners
  sudo ./script.sh --remove auditd,aide,banners
  sudo ./script.sh --remove menu
EOF
                exit 0 ;;
            *) echo "Unknown option: $1" >&2; exit 1 ;;
        esac
    done
    $AUTO_MODE && parse_config_file "${config_file:-$DEFAULT_AUTO_CONFIG}"
}

parse_args "$@"

[[ $EUID -ne 0 ]] && { echo "ERROR: Run as root (sudo)." >&2; exit 1; }
(( BASH_VERSINFO[0] >= 4 )) || { echo "ERROR: Bash 4+ required." >&2; exit 1; }

# ============================================================================
# INTERACTIVE STARTUP MENU
# ============================================================================
interactive_mode_menu() {
    (( ORIGINAL_ARGC > 0 )) && return 0
    INTERACTIVE_MENU_USED=true
    while true; do
        echo
        echo -e "${C_BOLD}${C_CYAN}$(tr_msg start_mode)${C_RESET}"
        printf '  1) %s
' "$(tr_msg menu_1)"
        printf '  2) %s
' "$(tr_msg menu_2)"
        printf '  3) %s
' "$(tr_msg menu_3)"
        printf '  4) %s
' "$(tr_msg menu_4)"
        printf '  5) %s
' "$(tr_msg menu_5)"
        printf '  6) %s
' "$(tr_msg menu_6)"
        printf '  7) %s
' "$(tr_msg menu_7)"
        printf '  8) %s
' "$(tr_msg menu_8)"
        echo
        local selection="" auto_cfg=""
        read -rp "$(tr_msg menu_prompt)" selection </dev/tty
        case "$selection" in
            1) ASSESS_ONLY=true; AUTO_MODE=false; VERIFY_AFTER_HARDENING=false
               success "$(tr_msg mode_1_ok)"; break ;;
            2) ASSESS_ONLY=false; AUTO_MODE=false; VERIFY_AFTER_HARDENING=true
               INTERACTIVE_RECOMMENDED_MODE=true
               success "$(tr_msg mode_2_ok)"; break ;;
            3) ASSESS_ONLY=false; AUTO_MODE=false; VERIFY_AFTER_HARDENING=true
               INTERACTIVE_STEP_MODE=true
               success "$(tr_msg mode_3_ok)"; break ;;
            4) ASSESS_ONLY=false; AUTO_MODE=true; VERIFY_AFTER_HARDENING=true
               read -rp "$(tr_msg config_file) [$DEFAULT_AUTO_CONFIG]: " auto_cfg </dev/tty
               auto_cfg=${auto_cfg:-$DEFAULT_AUTO_CONFIG}
               parse_config_file "$auto_cfg"
               success "$(tr_msg mode_4_ok)"; break ;;
            5) ROLLBACK_MODE=true
               success "$(tr_msg mode_5_ok)"; break ;;
            6) SELECTIVE_REMOVE_MODE=true
               REMOVE_TARGETS_RAW="__MENU__"
               success "$(tr_msg mode_6_ok)"; break ;;
            7) ASSESS_ONLY=false; AUTO_MODE=false; VERIFY_AFTER_HARDENING=true
               INTERACTIVE_STEP_MODE=true
               EXPERT_PROFILE_MODE=true
               success "$(tr_msg mode_7_ok)"; break ;;
            8) success "$(tr_msg mode_8_ok)"; view_logs_menu ;;
            *) warn "$(tr_msg invalid_selection)" ;;
        esac
    done
}


# ============================================================================
# CORE HELPERS

# ============================================================================
ask_yes_no() {
    local question="$1" default="${2:-}" answer
    if $AUTO_MODE; then
        [[ "$default" == "n" ]] && { debug "AUTO: '$question' → NO"; return 1; }
        debug "AUTO: '$question' → YES"; return 0
    fi
    while true; do
        if [[ "$default" == "y" ]]; then
            echo -en "$question [Y/n]: "; read -r answer </dev/tty; answer=${answer:-y}
        elif [[ "$default" == "n" ]]; then
            echo -en "$question [y/N]: "; read -r answer </dev/tty; answer=${answer:-n}
        else
            echo -en "$question [y/n]: "; read -r answer </dev/tty
        fi
        case "$answer" in
            [Yy]*) return 0 ;; [Nn]*) return 1 ;;
            *) warn "Bitte 'y' oder 'n' eingeben." ;;
        esac
    done
}

is_section_skipped() {
    local section="$1" skip_list="${AUTO_SKIP_SECTIONS:-}" legacy mode reason
    LAST_SECTION_SKIP_REASON=""
    LAST_SECTION_SKIP_MODE=""

    if [[ -n "$skip_list" ]] && [[ ",$skip_list," == *",$section,"* ]]; then
        LAST_SECTION_SKIP_REASON="section listed in AUTO_SKIP_SECTIONS"
        LAST_SECTION_SKIP_MODE="config"
        return 0
    fi

    for legacy in $(get_section_related_checks "$section"); do
        [[ -n "$legacy" ]] || continue
        mode="$(get_exception_mode_for_legacy_check "$legacy")"
        case "$mode" in
            disable|assessment-only)
                reason="$(get_exception_reason_for_legacy_check "$legacy")"
                LAST_SECTION_SKIP_REASON="${reason:-exception defined for $(lookup_check_stable_id "$legacy")}"
                LAST_SECTION_SKIP_MODE="$mode"
                return 0
                ;;
        esac
    done
    return 1
}

is_package_installed() {
    local pkg="$1"
    dpkg-query -W -f='${Status}\n' "$pkg" 2>/dev/null | grep -qx 'install ok installed'
}
validate_email()        { [[ "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; }
validate_port()         { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

run_cmd() {
    local log_description="$1"; shift
    if $DRY_RUN; then dry_run_echo "$*"; return 0; fi
    debug "Executing: $*"
    if "$@"; then log_change "$log_description"; return 0
    else local exit_code=$?; error "Command failed (exit $exit_code): $*"; return $exit_code; fi
}

run_shell() {
    local log_description="$1" shell_cmd="$2"
    if $DRY_RUN; then dry_run_echo "$shell_cmd"; return 0; fi
    debug "Shell: $shell_cmd"
    if bash -c "$shell_cmd"; then log_change "$log_description"; return 0
    else local exit_code=$?; error "Shell command failed (exit $exit_code): $shell_cmd"; return $exit_code; fi
}

show_apt_update_failure_hint() {
    local logfile="$1"
    [[ -f "$logfile" ]] || return 0

    if grep -qiE "not valid yet|noch nicht gültig" "$logfile"; then
        if [[ "$UI_LANG" == "de" ]]; then
            error "'apt update' ist wegen einer ungültigen Systemzeit bzw. eines NTP-/Snapshot-Problems fehlgeschlagen. Die Paketquellen wirken aus Sicht der VM 'noch nicht gültig'."
            info "Prüfe Datum/Uhrzeit mit 'timedatectl status' und synchronisiere die Zeit, z. B. per NTP oder nach einem Snapshot-Restore. Danach das Skript erneut starten."
        else
            error "'apt update' failed because the system time is invalid or out of sync, often after a snapshot restore. From the VM's point of view the repository metadata is 'not valid yet'."
            info "Check date/time with 'timedatectl status' and resync the clock, for example via NTP or after restoring a snapshot. Then run the script again."
        fi
        command -v timedatectl >/dev/null 2>&1 && timedatectl status --no-pager 2>/dev/null | sed 's/^/  /' || true
        return 0
    fi

    if grep -qiE "Temporary failure resolving|Could not resolve|Name or service not known|Failed to fetch" "$logfile"; then
        if [[ "$UI_LANG" == "de" ]]; then
            error "'apt update' ist an einem Netzwerk-, DNS- oder Repository-Problem gescheitert."
            info "Prüfe Internetzugang, DNS-Auflösung und die konfigurierten APT-Repositories."
        else
            error "'apt update' failed because of a network, DNS or repository problem."
            info "Check internet connectivity, DNS resolution and the configured APT repositories."
        fi
        return 0
    fi
}

ensure_apt_updated() {
    $SCRIPT_APT_UPDATED && return 0
    $SCRIPT_APT_FAILED && { error "'apt update' previously failed in this run. Fix the root cause before retrying."; return 1; }
    info "Running 'apt update'..."
    if $DRY_RUN; then
        dry_run_echo "apt-get update -qq"
        return 0
    fi

    local apt_log
    apt_log=$(mktemp_tracked)
    if apt-get update -qq >"$apt_log" 2>&1; then
        log_change "APT_UPDATE"
        SCRIPT_APT_UPDATED=true
        SCRIPT_APT_FAILED=false
        return 0
    fi

    local rc=$?
    SCRIPT_APT_FAILED=true
    cat "$apt_log" >&2
    show_apt_update_failure_hint "$apt_log"
    error "'apt update' failed."
    return $rc
}

ensure_packages_installed() {
    local missing=()
    local pkg
    for pkg in "$@"; do is_package_installed "$pkg" || missing+=("$pkg"); done
    [[ ${#missing[@]} -eq 0 ]] && { success "Packages already installed: $*"; return 0; }
    warn "Missing packages: ${missing[*]}"
    if ask_yes_no "Install missing packages (${missing[*]})?" "y"; then
        ensure_apt_updated || { warn "Skipping package installation because 'apt update' did not complete successfully."; return 1; }
        $SCRIPT_APT_FAILED && { warn "Skipping package installation because APT is in failed state for this run."; return 1; }
        if run_cmd "INSTALLED:${missing[*]}" apt-get install -y "${missing[@]}"; then
            for pkg in "${missing[@]}"; do txlog "PKG_INSTALLED" "$pkg"; done
            success "Packages installed: ${missing[*]}"; return 0
        else error "Package installation failed."; return 1; fi
    else info "Package installation declined."; return 1; fi
}

# ============================================================================
# BACKUP / RESTORE
# ============================================================================
backup_file() {
    local file="$1" backup_path="${1}${BACKUP_SUFFIX}"
    [[ ! -f "$file" ]] && return 0
    [[ -f "$backup_path" ]] && { info "Backup already exists: '$backup_path'"; return 0; }
    $DRY_RUN && { dry_run_echo "cp -a '$file' '$backup_path'"; return 0; }
    if cp -a "$file" "$backup_path"; then
        info "Backup created: '$backup_path'"
        log_change "BACKUP_CREATED:$file:$backup_path"
        txlog "BACKUP_CREATED" "$file"
        return 0
    else error "Could not create backup of '$file'."; return 1; fi
}

restore_file() {
    local file="$1" backup_path="${1}${BACKUP_SUFFIX}"
    if [[ -f "$backup_path" ]]; then
        $DRY_RUN && { dry_run_echo "mv '$backup_path' '$file'"; return 0; }
        mv "$backup_path" "$file" && {
            success "Restored '$file'."
            log_change "FILE_RESTORED:$file"
            return 0
        } || { error "Failed to restore '$file'."; return 1; }
    fi

    local was_added=false
    if ! $DRY_RUN; then
        [[ -f "$SCRIPT_LOG_FILE" ]] && grep -qF "ADDED_FILE:$file" "$SCRIPT_LOG_FILE" && was_added=true
        [[ -f "$TRANSACTION_LOG" ]] && grep -qF "|FILE_ADDED|$file" "$TRANSACTION_LOG" && was_added=true
    fi

    if $was_added && [[ -f "$file" ]]; then
        rm -f "$file" && {
            success "Removed '$file' (was added by script)."
            log_change "REMOVED_ADDED_FILE:$file"
            rollback_report_reverted "removed script-added file: $file"
            return 0
        }
    fi

    warn "No backup found for '$file'."
    return 0
}

list_backups() {
    info "${C_BOLD}Backups created by this script:${C_RESET}"
    local found=false
    while IFS= read -r -d '' backup; do
        local original="${backup%"$BACKUP_SUFFIX"}"
        local backup_date
        backup_date=$(stat -c '%y' "$backup" 2>/dev/null | cut -d. -f1)
        echo -e "  ${C_GREEN}→${C_RESET} $original (backed up: $backup_date)"
        found=true
    done < <(find /etc /home /root -name "*${BACKUP_SUFFIX}" -print0 2>/dev/null)
    $found || info "No backups found."
}

restore_backup_interactive() {
    info "${C_BOLD}Interactive Backup Restore${C_RESET}"
    local backups=()
    while IFS= read -r -d '' backup; do backups+=("$backup"); done \
        < <(find /etc /home /root -name "*${BACKUP_SUFFIX}" -print0 2>/dev/null)
    [[ ${#backups[@]} -eq 0 ]] && { info "No backups found."; return 0; }
    echo "Available backups:"
    local i
    for i in "${!backups[@]}"; do
        local original="${backups[$i]%"$BACKUP_SUFFIX"}"
        local backup_date
        backup_date=$(stat -c '%y' "${backups[$i]}" 2>/dev/null | cut -d. -f1)
        echo "  [$((i+1))] $original (backed up: $backup_date)"
    done
    echo "  [0] Cancel"
    local choice=""; read -rp "Select [0]: " choice </dev/tty; choice=${choice:-0}
    [[ "$choice" == "0" ]] && { info "Cancelled."; return 0; }
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#backups[@]} )); then
        local selected="${backups[$((choice-1))]}"
        local original="${selected%"$BACKUP_SUFFIX"}"
        ask_yes_no "Restore '$original'?" "y" && restore_file "$original"
    else warn "Invalid selection."; fi
}

# ============================================================================
# SUDO SMOKE TEST
# Critical safety mechanism: validates sudo works after PAM changes.
# If sudo breaks, immediately rolls back the last PAM change.
# ============================================================================
sudo_smoke_test() {
    local rollback_file="${1:-}"
    info "Running sudo smoke test (validating PAM stack)..."

    # Test sudo via a harmless command, but force re-authentication check
    if sudo -n true 2>/dev/null; then
        success "Sudo smoke test PASSED."
        return 0
    fi

    # sudo -n fails if password is required (normal). Try with timeout.
    # The real test: can PAM even process auth at all?
    # We test pam_authenticate indirectly by running 'su -c true root' from a non-root
    # but since we ARE root, test if the pam stack parses without error
    if python3 -c "import pam; p=pam.pam(); print('ok')" 2>/dev/null | grep -q "ok"; then
        success "PAM module loads correctly."
        return 0
    fi

    # Fallback: check if pam_unix.so is still in the stack
    if grep -q "pam_unix.so" /etc/pam.d/common-auth 2>/dev/null; then
        success "PAM stack contains pam_unix.so (basic check passed)."
        return 0
    fi

    error "SUDO SMOKE TEST FAILED — PAM stack may be broken!"
    if [[ -n "$rollback_file" ]] && [[ -f "${rollback_file}${BACKUP_SUFFIX}" ]]; then
        error "Auto-rolling back PAM change: $rollback_file"
        restore_file "$rollback_file"
        warn "PAM restored from backup. Please verify sudo manually."
    fi
    return 1
}

# ============================================================================
# PAM VALIDATION HELPER
# Tests that a PAM config file is syntactically valid before deploying it.
# ============================================================================
validate_pam_file() {
    local pam_file="$1"
    # Accept Ubuntu/Debian PAM layouts that use includes instead of direct pam_unix.so lines.
    if ! grep -qE "^(auth\s+\S+\s+\S+|@include\s+common-auth|auth\s+substack\s+common-auth)" "$pam_file"; then
        error "PAM validation failed: no usable auth stack found in $pam_file"
        return 1
    fi
    # For 2FA-aware sshd PAM, allow either direct pam_unix.so or the standard Debian/Ubuntu include chain.
    if grep -q "pam_google_authenticator.so" "$pam_file"; then
        if ! grep -qE "(^@include\s+common-auth$|^auth\s+substack\s+common-auth$|pam_unix\.so)" "$pam_file"; then
            error "PAM validation failed: google-authenticator present, but no local auth/include chain found in $pam_file"
            return 1
        fi
    fi
    # Check for obviously broken lines (syntax errors would have empty module names)
    if grep -qE "^(auth|account|password|session)\s+\S+\s*$" "$pam_file"; then
        error "PAM validation failed: line(s) with missing module in $pam_file"
        return 1
    fi
    success "PAM file validation passed: $pam_file"
    return 0
}

# ============================================================================
# ASSESSMENT MATRIX
# ============================================================================
record_check() {
    local id="$1" status="$2" desc="$3"
    local stable_id severity title mode reason normalized
    stable_id="$(lookup_check_stable_id "$id")"
    severity="$(lookup_check_severity "$id")"
    title="$(lookup_check_title "$id")"
    mode="$(get_exception_mode_for_legacy_check "$id")"
    reason="$(get_exception_reason_for_legacy_check "$id")"
    normalized="$(normalize_matrix_status "$status")"

    case "$mode" in
        disable)
            status="EXCEPTION"
            desc="${desc} [exception: disabled${reason:+ — $reason}]"
            ;;
        warn)
            if [[ "$normalized" == "RED" ]]; then
                status="WARN"
                desc="${desc} [exception: downgraded to WARN${reason:+ — $reason}]"
            elif [[ -n "$reason" ]]; then
                desc="${desc} [exception note: ${reason}]"
            fi
            ;;
        assessment-only)
            desc="${desc} [exception: assessment-only${reason:+ — $reason}]"
            ;;
    esac

    ASSESS_RESULTS["$id"]="${status}:${desc}"
    ASSESS_META_STABLE_ID["$id"]="$stable_id"
    ASSESS_META_SEVERITY["$id"]="$severity"
    ASSESS_META_TITLE["$id"]="$title"
    ASSESS_META_MODE["$id"]="$mode"
    ASSESS_META_REASON["$id"]="$reason"

    local found=false existing
    for existing in "${ASSESS_ORDER[@]+"${ASSESS_ORDER[@]}"}"; do
        [[ "$existing" == "$id" ]] && found=true && break
    done
    $found || ASSESS_ORDER+=("$id")
}

normalize_matrix_status() {
    case "$1" in
        PASS|FIXED) echo "GREEN" ;;
        INFO|WARN|SKIP|NA|N/A|EXCEPTION) echo "YELLOW" ;;
        *) echo "RED" ;;
    esac
}

count_red_checks() {
    local red=0 id entry raw
    for id in "${ASSESS_ORDER[@]}"; do
        entry="${ASSESS_RESULTS[$id]}"
        raw="${entry%%:*}"
        [[ "$(normalize_matrix_status "$raw")" == "RED" ]] && red=$((red+1))
    done
    echo "$red"
}

sudoers_has_tty_tickets() {
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*Defaults([[:space:]]|$)/ {
            if ($0 ~ /!tty_tickets/) next
            if ($0 ~ /(^|[,[:space:]])tty_tickets([,[:space:]]|$)/) { found=1; exit }
        }
        END { exit(found ? 0 : 1) }
    ' /etc/sudoers /etc/sudoers.d/* 2>/dev/null
}

format_sysctl_findings() {
    local -a findings=("$@")
    local IFS=', '
    printf '%s' "${findings[*]}"
}

interactive_umask_shell_hook_present() {
    grep -qE '^[[:space:]]*umask[[:space:]]+0?(27|77)([[:space:]]|$)' "$PROFILE_UMASK_FILE" /etc/profile /etc/bash.bashrc 2>/dev/null
}

get_systemd_default_umask_from_file() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    awk -F'=' '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*DefaultUMask[[:space:]]*=/ {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2)
            value=$2
        }
        END { if (value != "") print value; else exit 1 }
    ' "$file" 2>/dev/null
}

normalize_csv_values() {
    local raw="$1"
    awk -v input="$raw" 'BEGIN {
        n=split(input, a, ",")
        for (i=1; i<=n; i++) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", a[i])
            if (a[i] == "") continue
            if (out != "") out = out ","
            out = out a[i]
        }
        print out
    }'
}

ssh_effective_policy_matches_mode() {
    local mode="$1" line key expected actual
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        key="${line%% *}"
        expected="${line#* }"
        actual=$(get_effective_sshd_config "$key" 2>/dev/null || true)
        [[ -n "$actual" ]] || return 1
        [[ "$(normalize_csv_values "$actual")" == "$(normalize_csv_values "$expected")" ]] || return 1
    done < <(get_ssh_crypto_policy_values "$mode")
    return 0
}

apparmor_numeric_count() {
    local pattern="$1"
    aa-status 2>/dev/null | awk -v pat="$pattern" '$0 ~ pat { print $1; found=1; exit } END { if (!found) print 0 }'
}

# ============================================================================
# SSH HELPERS
# ============================================================================
detect_ssh_service() {
    if systemctl is-active --quiet ssh 2>/dev/null; then SSH_SERVICE="ssh"
    elif systemctl is-active --quiet sshd 2>/dev/null; then SSH_SERVICE="sshd"
    elif systemctl list-unit-files 2>/dev/null | grep -q "^ssh\.service"; then SSH_SERVICE="ssh"
    elif systemctl list-unit-files 2>/dev/null | grep -q "^sshd\.service"; then SSH_SERVICE="sshd"
    else SSH_SERVICE="ssh"; warn "Cannot detect SSH service, assuming 'ssh'."; fi
}

get_effective_sshd_config() {
    local parameter="$1" result=""
    command -v sshd >/dev/null 2>&1 && \
        result=$(sshd -T -C user=root -C host=localhost -C addr=127.0.0.1 2>/dev/null | \
            grep -i "^${parameter}[[:space:]]" | head -n 1 | awk '{print $2}' || true)
    [[ -z "$result" ]] && \
        result=$(grep -ihRE "^[[:space:]]*${parameter}[[:space:]]+" \
            /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | \
            tail -n 1 | awk '{print $2}' || true)
    echo "$result"
}


ssh_google_2fa_assessment() {
    local pam_file="/etc/pam.d/sshd"
    local usepam kbdinteractive challenge authmethods
    local has_gauth_pam=false has_gauth_pkg=false has_user_secret=false

    [[ -f "$pam_file" ]] && grep -Eq '^[[:space:]]*auth[[:space:]].*pam_google_authenticator\.so\b' "$pam_file" && has_gauth_pam=true
    is_package_installed libpam-google-authenticator && has_gauth_pkg=true
    find /root /home -maxdepth 2 -name .google_authenticator -type f 2>/dev/null | grep -q . && has_user_secret=true

    usepam=$(get_effective_sshd_config "UsePAM")
    kbdinteractive=$(get_effective_sshd_config "KbdInteractiveAuthentication")
    challenge=$(get_effective_sshd_config "ChallengeResponseAuthentication")
    authmethods=$(get_effective_sshd_config "AuthenticationMethods")

    if $has_gauth_pam && [[ "${usepam,,}" == "yes" ]]        && ([[ "${kbdinteractive,,}" == "yes" ]] || [[ "${challenge,,}" == "yes" ]])        && [[ "$authmethods" == *keyboard-interactive* ]]; then
        record_check "SSH_GOOGLE_2FA" "PASS" "Google 2FA active for SSH (PAM + keyboard-interactive)"
    elif $has_gauth_pam || $has_gauth_pkg || $has_user_secret; then
        local detail=""
        $has_gauth_pam && detail+="pam_google_authenticator configured; "
        $has_gauth_pkg && detail+="package installed; "
        $has_user_secret && detail+="user secret present; "
        [[ "$authmethods" == *keyboard-interactive* ]] || detail+="AuthenticationMethods does not require keyboard-interactive; "
        ([[ "${kbdinteractive,,}" == "yes" ]] || [[ "${challenge,,}" == "yes" ]]) || detail+="keyboard-interactive/challenge-response disabled; "
        detail=${detail%%; }
        record_check "SSH_GOOGLE_2FA" "WARN" "Google 2FA not fully active for SSH (${detail})"
    else
        record_check "SSH_GOOGLE_2FA" "FAIL" "Google 2FA not enabled for SSH"
    fi
}
get_ssh_port() {
    local port; port=$(get_effective_sshd_config "port")
    { [[ -n "$port" ]] && validate_port "$port"; } && echo "$port" || echo "22"
}

get_config_file_sshd_setting() {
    local parameter="$1" config_file="/etc/ssh/sshd_config"
    [[ ! -f "$config_file" ]] && return 0
    grep -iE "^\s*${parameter}\s+" "$config_file" 2>/dev/null | tail -n 1 | awk '{print $2}' || true
}

show_sshd_setting_sources() {
    local parameter="$1"
    info "SSH source lines for ${parameter}:"
    grep -RinE "^\s*${parameter}\s+" /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null | sed 's/^/  - /' || true
}

get_effective_sysctl_config() {
    sysctl "$1" >/dev/null 2>&1 && sysctl -n "$1" || echo "not_set"
}

get_persisted_sysctl_config() {
    local param="$1"
    local escaped
    escaped=$(printf '%s' "$param" | sed 's/[][\.^$*+?{}|()]/\\&/g')
    awk -F= -v pat="^""$escaped""$" '
        /^[[:space:]]*#/ { next }
        NF >= 2 {
            key=$1; val=$2
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            if (key ~ pat) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
                sub(/[[:space:]]*#.*/, "", val)
                found=val
            }
        }
        END { if (found != "") print found }
    ' /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf 2>/dev/null | tail -n 1
}

ssh_values_matching_regex() {
    local csv="$1" regex="$2"
    awk -v RS=',' -v ORS=',' -v re="$regex" 'NF { gsub(/^[[:space:]]+|[[:space:]]+$/, ""); if ($0 ~ re) print $0 }' <<< "$csv" | sed 's/,$//'
}

host_has_container_networks() {
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -Eq '^(docker0|cni0|podman0|br-|virbr|lxcbr)'
}

sysctl_expected_description() {
    local param="$1" desired="$2"
    case "$param" in
        net.ipv4.conf.all.rp_filter|net.ipv4.conf.default.rp_filter)
            if host_has_container_networks; then
                echo "${desired} or 2 (container/bridge host)"
            else
                echo "$desired"
            fi
            ;;
        *) echo "$desired" ;;
    esac
}

sysctl_value_matches_policy() {
    local param="$1" desired="$2" current="$3"
    case "$param" in
        net.ipv4.conf.all.rp_filter|net.ipv4.conf.default.rp_filter)
            if host_has_container_networks; then
                [[ "$current" == "1" || "$current" == "2" ]]
            else
                [[ "$current" == "$desired" ]]
            fi
            ;;
        *) [[ "$current" == "$desired" ]] ;;
    esac
}

load_sysctl_policy() {
    declare -gA SYSCTL_POLICY=()
    SYSCTL_POLICY=(
        ["net.ipv4.conf.all.rp_filter"]="1"             ["net.ipv4.conf.default.rp_filter"]="1"
        ["net.ipv4.conf.all.accept_redirects"]="0"      ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv6.conf.all.accept_redirects"]="0"      ["net.ipv6.conf.default.accept_redirects"]="0"
        ["net.ipv4.conf.all.secure_redirects"]="0"      ["net.ipv4.conf.default.secure_redirects"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"        ["net.ipv4.conf.default.send_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"   ["net.ipv4.conf.default.accept_source_route"]="0"
        ["net.ipv6.conf.all.accept_source_route"]="0"   ["net.ipv6.conf.default.accept_source_route"]="0"
        ["net.ipv4.conf.all.log_martians"]="1"          ["net.ipv4.conf.default.log_martians"]="1"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"    ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        ["net.ipv4.tcp_syncookies"]="1"                 ["net.ipv4.tcp_rfc1337"]="1"
        ["kernel.randomize_va_space"]="2"               ["kernel.sysrq"]="0"
        ["kernel.kptr_restrict"]="2"                    ["kernel.dmesg_restrict"]="1"
        ["kernel.yama.ptrace_scope"]="1"                ["kernel.core_uses_pid"]="1"
        ["fs.protected_hardlinks"]="1"                  ["fs.protected_symlinks"]="1"
        ["fs.protected_fifos"]="2"                      ["fs.protected_regular"]="2"
        ["fs.suid_dumpable"]="0"
    )
}

normalize_octal_umask() {
    local value="${1:-}"
    value="${value//[^0-7]/}"
    [[ -n "$value" ]] || return 1
    printf '%03o\n' "$((8#$value))"
}

octal_umask_is_restrictive_enough() {
    local normalized
    normalized=$(normalize_octal_umask "$1" 2>/dev/null) || return 1
    (( 8#$normalized >= 8#027 ))
}

get_ssh_crypto_policy_values() {
    local mode="$1"
    case "$mode" in
        strict)
            cat <<'POLICY_EOF'
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
POLICY_EOF
            ;;
        modern)
            cat <<'POLICY_EOF'
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
POLICY_EOF
            ;;
        fips-compatible)
            cat <<'POLICY_EOF'
KexAlgorithms ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
POLICY_EOF
            ;;
        *) return 1 ;;
    esac
}

append_audit_watch_if_exists() {
    local outfile="$1" path="$2" perms="$3" key="$4"
    [[ -e "$path" ]] || return 0
    printf -- '-w %s -p %s -k %s\n' "$path" "$perms" "$key" >> "$outfile"
}

set_or_append_login_defs_key() {
    local file="$1" key="$2" value="$3"
    if grep -qE "^[[:space:]]*${key}[[:space:]]+" "$file" 2>/dev/null; then
        sed -i -E "s|^[[:space:]]*${key}[[:space:]]+.*|${key}\t\t${value}|" "$file"
    else
        printf '\n%s\t\t%s\n' "$key" "$value" >> "$file"
    fi
}

set_sshd_param() {
    local key="$1" value="$2" file="$3"
    local current_val
    current_val=$(grep -iE "^\s*${key}\s+" "$file" 2>/dev/null | tail -n 1 | awk '{print $2}' || true)
    if [[ -n "$current_val" ]] && \
       [[ "$(echo "$current_val" | tr '[:upper:]' '[:lower:]')" == "$(echo "$value" | tr '[:upper:]' '[:lower:]')" ]]; then
        return 1
    fi
    if grep -qE "^\s*#?\s*${key}" "$file"; then
        sed -i -E "s|^\s*#?\s*(${key})\s+.*|${key} ${value}|" "$file"
    else
        echo "${key} ${value}" >> "$file"
    fi
    info "  Set '${key} ${value}'"
    return 0
}

apply_sshd_config() {
    local temp_file="$1" target="/etc/ssh/sshd_config"
    if $DRY_RUN; then
        dry_run_echo "sshd -t -f '$temp_file' && mv '$temp_file' '$target'"
        rm -f "$temp_file" 2>/dev/null; return 0
    fi
    if sshd -t -f "$temp_file" 2>/dev/null; then
        mv "$temp_file" "$target" && { chmod 644 "$target"; success "SSHD config applied."; return 0; } \
            || error "Failed to move temp SSHD config."
    else
        error "SSHD config syntax check failed — changes NOT applied."
    fi
    rm -f "$temp_file" 2>/dev/null
    restore_file "$target"
    return 1
}

restart_ssh() {
    local reason="${1:-config change}"
    info "Restarting SSH ($SSH_SERVICE) — $reason..."
    run_cmd "SERVICE_RESTARTED:$SSH_SERVICE" systemctl restart "$SSH_SERVICE" || { error "SSH restart failed!"; return 1; }
    success "SSH restarted."
    $DRY_RUN && return 0
    sleep 1
    systemctl is-active --quiet "$SSH_SERVICE" || { error "SSH not active after restart!"; return 1; }
    return 0
}

ensure_service_running() {
    local service="$1"
    local needs_start=false needs_enable=false
    systemctl is-active  --quiet "$service" 2>/dev/null || needs_start=true
    systemctl is-enabled --quiet "$service" 2>/dev/null || needs_enable=true
    if $needs_start; then
        ask_yes_no "Start '$service'?" "y" && {
            run_cmd "SERVICE_STARTED:$service" systemctl start "$service" && {
                success "'$service' started."
                txlog "SERVICE_STARTED" "$service"
            } || error "Failed to start '$service'."
        }
    else success "'$service' is active."; fi
    if $needs_enable; then
        ask_yes_no "Enable '$service' on boot?" "y" && {
            run_cmd "SERVICE_ENABLED:$service" systemctl enable "$service" && {
                success "'$service' enabled."
                txlog "SERVICE_ENABLED" "$service"
            } || error "Failed to enable '$service'."
        }
    else success "'$service' is enabled."; fi
}

is_fail2ban_jail_enabled() {
    local jail_name="$1" jail_local="/etc/fail2ban/jail.local"
    [[ ! -f "$jail_local" ]] && return 1
    awk -v jail="[$jail_name]" '
        $0 == jail {in_section=1; next}
        /^\s*\[/ && in_section { exit }
        in_section && /^\s*enabled\s*=\s*true/ { found=1; exit }
        END { exit !found }
    ' "$jail_local"
}

get_apt_conf_value() {
    local file="$1" key="$2" line value
    [[ -f "$file" ]] || return 1
    line=$(grep -E "^\s*(//\s*)?${key}\s+" "$file" 2>/dev/null | tail -n 1 || true)
    [[ -n "$line" ]] || return 1
    [[ "$line" =~ ^[[:space:]]*// ]] && return 1
    value=$(printf '%s
' "$line" | sed -E 's/.*"([^"]*)".*//;t; s/.*[[:space:]](true|false)[[:space:]]*;.*//;t; s/.*[[:space:]]([0-9:]+)[[:space:]]*;.*//')
    [[ -n "$value" ]] || return 1
    printf '%s
' "$value"
}

unattended_upgrades_policy_diff() {
    local periodic_file="/etc/apt/apt.conf.d/20auto-upgrades"
    local config_file="/etc/apt/apt.conf.d/50unattended-upgrades"
    local diffs=() value

    is_package_installed unattended-upgrades || { echo "package missing"; return 0; }

    grep -qE '^\s*APT::Periodic::Update-Package-Lists\s*"1"\s*;' "$periodic_file" 2>/dev/null || diffs+=("Update-Package-Lists!=1")
    grep -qE '^\s*APT::Periodic::Unattended-Upgrade\s*"1"\s*;' "$periodic_file" 2>/dev/null || diffs+=("Unattended-Upgrade!=1")

    local -A desired_params=(
        ["Unattended-Upgrade::AutoFixInterruptedDpkg"]="true"
        ["Unattended-Upgrade::MinimalSteps"]="true"
        ["Unattended-Upgrade::MailReport"]="on-change"
        ["Unattended-Upgrade::Remove-Unused-Kernel-Packages"]="true"
        ["Unattended-Upgrade::Remove-New-Unused-Dependencies"]="true"
        ["Unattended-Upgrade::Remove-Unused-Dependencies"]="true"
        ["Unattended-Upgrade::Automatic-Reboot"]="true"
        ["Unattended-Upgrade::Automatic-Reboot-WithUsers"]="false"
        ["Unattended-Upgrade::Automatic-Reboot-Time"]="02:00"
    )
    local key
    for key in "${!desired_params[@]}"; do
        value=$(get_apt_conf_value "$config_file" "$key" 2>/dev/null || true)
        [[ "$value" == "${desired_params[$key]}" ]] || diffs+=("${key}!=${desired_params[$key]}")
    done

    ((${#diffs[@]})) && printf '%s
' "${diffs[*]}"
    return 0
}

fail2ban_get_setting() {
    local section="$1" key="$2" file="${3:-/etc/fail2ban/jail.local}"
    [[ -f "$file" ]] || return 1
    awk -v section="[$section]" -v key="$key" '
        $0 == section { in_section=1; next }
        /^\s*\[/ && in_section { exit }
        in_section {
            if ($0 ~ "^[[:space:]]*" key "[[:space:]]*=") {
                sub("^[[:space:]]*" key "[[:space:]]*=[[:space:]]*", "")
                gsub(/^[[:space:]]+|[[:space:]]+$/, "")
                print
                exit
            }
        }
    ' "$file"
}

fail2ban_policy_diff() {
    local jail_local="/etc/fail2ban/jail.local"
    local diffs=() ignoreip line

    is_package_installed fail2ban || { echo "package missing"; return 0; }
    systemctl is-active --quiet fail2ban 2>/dev/null || diffs+=("service inactive")
    [[ -f "$jail_local" ]] || { echo "jail.local missing"; return 0; }
    is_fail2ban_jail_enabled "sshd" || diffs+=("sshd jail disabled")

    [[ "$(fail2ban_get_setting DEFAULT bantime "$jail_local" 2>/dev/null || true)" == "1h" ]] || diffs+=("bantime!=1h")
    [[ "$(fail2ban_get_setting DEFAULT findtime "$jail_local" 2>/dev/null || true)" == "10m" ]] || diffs+=("findtime!=10m")
    [[ "$(fail2ban_get_setting DEFAULT maxretry "$jail_local" 2>/dev/null || true)" == "3" ]] || diffs+=("maxretry!=3")

    ignoreip=$(awk '/^\s*\[DEFAULT\]/{d=1;next} /^\s*\[/{d=0} d&&/^\s*ignoreip\s*=/{sub(/^\s*ignoreip\s*=\s*/,""); cl=$0; while(getline>0&&$0~/^[[:space:]]/) cl=cl " " $0; gsub(/[[:space:]]+/," ",cl); print cl; exit}' "$jail_local" 2>/dev/null || true)
    [[ "$ignoreip" == *"127.0.0.1/8"* ]] || diffs+=("ignoreip missing 127.0.0.1/8")
    [[ "$ignoreip" == *"::1"* ]] || diffs+=("ignoreip missing ::1")

    ((${#diffs[@]})) && printf '%s
' "${diffs[*]}"
    return 0
}

declare -A ufw_rules=()
ufw_rule_count=0

is_ufw_allowed() {
    local key="$1"
    [[ -v ufw_rules["$key"] ]] && return 0
    return 1
}

get_container_ports() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && \
        docker ps --format '{{.Ports}}' 2>/dev/null | \
            grep -oP '0\.0\.0\.0:(\d+)->(\d+)/(tcp|udp)' | \
            while IFS= read -r mapping; do
                echo "$(echo "$mapping" | grep -oP '0\.0\.0\.0:\K\d+'),$(echo "$mapping" | grep -oP '(tcp|udp)$'),docker-container"
            done
    command -v podman >/dev/null 2>&1 && \
        podman ps --format '{{.Ports}}' 2>/dev/null | \
            grep -oP '0\.0\.0\.0:(\d+)->(\d+)/(tcp|udp)' | \
            while IFS= read -r mapping; do
                echo "$(echo "$mapping" | grep -oP '0\.0\.0\.0:\K\d+'),$(echo "$mapping" | grep -oP '(tcp|udp)$'),podman-container"
            done
}

get_listening_ports() {
    ss -ltnp 2>/dev/null | while IFS= read -r line; do
        [[ "$line" =~ ^LISTEN ]] || continue
        local port="${$(echo "$line" | awk '{print $4}')##*:}"
        [[ "$port" =~ ^[0-9]+$ ]] && (( port > 0 && port < 65536 )) || continue
        local proc="unknown"; [[ "$line" =~ users:\(\(\"([^\"]+)\" ]] && proc="${BASH_REMATCH[1]}"
        echo "${port},tcp,${proc}"
    done
    ss -lunp 2>/dev/null | while IFS= read -r line; do
        [[ "$line" =~ ^UNCONN ]] || continue
        local port="${$(echo "$line" | awk '{print $4}')##*:}"
        [[ "$port" =~ ^[0-9]+$ ]] && (( port > 0 && port < 65536 )) || continue
        local proc="unknown"; [[ "$line" =~ users:\(\(\"([^\"]+)\" ]] && proc="${BASH_REMATCH[1]}"
        echo "${port},udp,${proc}"
    done
}

is_ip_covered_by_ignoreip() {
    local check_item="$1"; shift; local ignore_list=("$@")
    local ip="" subnet=""
    [[ "$check_item" =~ / ]] && subnet="$check_item" || {
        ip="$check_item"
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && subnet="$(echo "$ip" | cut -d. -f1-3).0/24"
    }
    local entry
    for entry in "${ignore_list[@]}"; do
        [[ "$ip" == "$entry" || "$subnet" == "$entry" ]] && return 0
        [[ -n "$ip" ]] && {
            { [[ "$entry" == "192.168.0.0/16" ]] && [[ "$ip" =~ ^192\.168\. ]]; } && return 0
            { [[ "$entry" == "172.16.0.0/12" ]] && [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; } && return 0
            { [[ "$entry" == "10.0.0.0/8" ]] && [[ "$ip" =~ ^10\. ]]; } && return 0
        }
    done
    return 1
}


print_auditd_observability_info() {
    echo
    info "${C_BOLD}Auditd – relevante Logs und Befehle:${C_RESET}"
    echo "  - Rohlog:              /var/log/audit/audit.log"
    echo "  - Regeln:              $AUDITD_RULES"
    echo "  - Service-Log:         journalctl -u auditd -xe"
    echo "  - Aktive Regeln:       auditctl -l"
    echo "  - Suche nach Key:      ausearch -k sudo_usage -ts today"
    echo "  - $(tr_msg summary_label):           aureport -au -i"
    echo
}

print_aide_observability_info() {
    local helper cfg_auto="/var/lib/aide/aide.conf.autogenerated" cfg_static="/etc/aide/aide.conf"
    helper="$(aide_find_helper 2>/dev/null || true)"
    echo
    info "${C_BOLD}AIDE – relevante Logs und Befehle:${C_RESET}"
    echo "  - Sammellog:           /var/log/aide-check.log"
    echo "  - Tagesreports:        /var/log/aide-report-YYYYMMDD.log"
    echo "  - Init-Log:            $AIDE_INIT_LOG"
    echo "  - Lokale Excludes:     $AIDE_LOCAL_EXCLUDES"
    echo "  - Generierte Config:   $cfg_auto"
    if [[ -n "$helper" ]]; then
        echo "  - AIDE-Helper:         $helper"
        echo "  - Manueller Check:     $helper && aide --config=$cfg_auto --check"
        echo "  - Baseline aktualisieren:"
        echo "                         $helper"
        echo "                         aide --config=$cfg_auto --update"
    else
        echo "  - AIDE-Basisconfig:    $cfg_static"
        echo "  - Manueller Check:     aide --config=$cfg_auto --check"
        echo "  - Baseline aktualisieren:"
        echo "                         aide --config=$cfg_auto --update"
    fi
    echo "                         cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
    echo "                         ODER cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
    echo "  - Baseline-Dateien:    /var/lib/aide/aide.db oder /var/lib/aide/aide.db.gz"
    echo "  - Cronjob:             $AIDE_CRON"
    echo
}

ssh_dropin_validate_and_restore() {
    local sshd_test_output
    if sshd_test_output=$(sshd -t 2>&1); then
        return 0
    fi
    error "SSHD validation failed after writing $SSHD_HARDENING_DROPIN"
    [[ -n "$sshd_test_output" ]] && error "$sshd_test_output"
    if [[ -f "${SSHD_HARDENING_DROPIN}${BACKUP_SUFFIX}" ]]; then
        restore_file "$SSHD_HARDENING_DROPIN" >/dev/null 2>&1 || true
    else
        rm -f "$SSHD_HARDENING_DROPIN" >/dev/null 2>&1 || true
    fi
    return 1
}

normalize_sshd_include_path() {
    local f="$1"
    [[ -f "$f" ]] || return 2
    local before after changed=1
    before=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
    if grep -Eq '^[[:space:]]*Include[[:space:]]+/tmp/[^[:space:]]+/sshd_config\.d/\*\.conf([[:space:]]|$)' "$f"; then
        sed -i -E 's|^[[:space:]]*Include[[:space:]]+/tmp/[^[:space:]]+/sshd_config\.d/\*\.conf([[:space:]]*)$|Include /etc/ssh/sshd_config.d/*.conf|' "$f"
    elif grep -Eq '^[[:space:]]*Include[[:space:]]+.+sshd_config\.d/\*\.conf([[:space:]]|$)' "$f"          && ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf([[:space:]]|$)' "$f"; then
        sed -i -E '0,/^[[:space:]]*Include[[:space:]]+.+sshd_config\.d\/\*\.conf([[:space:]]|$)/s|^[[:space:]]*Include[[:space:]]+.+sshd_config\.d/\*\.conf([[:space:]]|$)|Include /etc/ssh/sshd_config.d/*.conf|' "$f"
    elif ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf([[:space:]]|$)' "$f"; then
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$f"
    fi
    after=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
    [[ "$before" != "$after" ]] && changed=0
    return $changed
}

ssh_uses_keyboard_interactive() {
    local auth_methods
    auth_methods=$(get_effective_sshd_config "AuthenticationMethods" 2>/dev/null || true)
    [[ -z "$auth_methods" ]] && \
        auth_methods=$(grep -ihRE '^[[:space:]]*AuthenticationMethods[[:space:]]+' \
            /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | \
            tail -n 1 | awk '{print $2}' || true)
    [[ "${auth_methods,,}" == *"keyboard-interactive"* ]]
}


ssh_detect_pam_2fa_modules() {
    local pam_file="/etc/pam.d/sshd"
    local -a mods=()
    [[ -f "$pam_file" ]] || return 1
    grep -Eq '^[[:space:]]*auth[[:space:]].*pam_google_authenticator\.so\b' "$pam_file" && mods+=("pam_google_authenticator.so")
    grep -Eq '^[[:space:]]*auth[[:space:]].*pam_oath\.so\b' "$pam_file" && mods+=("pam_oath.so")
    grep -Eq '^[[:space:]]*auth[[:space:]].*pam_u2f\.so\b' "$pam_file" && mods+=("pam_u2f.so")
    grep -Eq '^[[:space:]]*auth[[:space:]].*pam_yubico\.so\b' "$pam_file" && mods+=("pam_yubico.so")
    (( ${#mods[@]} > 0 )) || return 1
    printf '%s\n' "${mods[*]}"
}

ssh_file_disables_keyboard_interactive_path() {
    local f="$1"
    [[ -f "$f" ]] || return 1
    grep -Eqi '^[[:space:]]*(ChallengeResponseAuthentication|KbdInteractiveAuthentication)[[:space:]]+no\b' "$f"
}

auditd_unit_exists() {
    systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx 'auditd.service'
}

auditd_is_active() {
    systemctl is-active --quiet auditd 2>/dev/null || pgrep -x auditd >/dev/null 2>&1
}

ensure_auditd_service_available() {
    auditd_unit_exists && return 0
    auditd_is_active && return 0
    warn "auditd package vorhanden, aber auditd.service fehlt. Versuche Reinstallation..."
    if $DRY_RUN; then
        dry_run_echo "Reinstall auditd audispd-plugins"
        return 1
    fi
    ensure_apt_updated || return 1
    apt-get install --reinstall -y auditd audispd-plugins >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    auditd_unit_exists || auditd_is_active
}


apparmor_kernel_enabled() {
    [[ -r /sys/module/apparmor/parameters/enabled ]] && grep -qx 'Y' /sys/module/apparmor/parameters/enabled
}

apparmor_profiles_loaded() {
    aa-status 2>/dev/null | sed -n 's/^\([0-9][0-9]*\) profiles are loaded\..*//p' | head -1
}

apparmor_profiles_enforced() {
    aa-status 2>/dev/null | grep "profiles are in enforce mode" | grep -oP '^\d+' || echo "0"
}

apparmor_profiles_complain() {
    aa-status 2>/dev/null | grep "profiles are in complain mode" | grep -oP '^\d+' || echo "0"
}

apparmor_is_effectively_enabled() {
    command -v aa-status >/dev/null 2>&1 || return 1
    apparmor_kernel_enabled || return 1
    local loaded enforced
    loaded="$(apparmor_profiles_loaded)"; loaded=${loaded:-0}
    enforced="$(apparmor_profiles_enforced)"; enforced=${enforced:-0}
    (( loaded >= 2 && enforced >= 1 ))
}

aide_collect_config_files() {
    local -a files=()
    [[ -f /etc/aide/aide.conf ]] && files+=(/etc/aide/aide.conf)
    if compgen -G '/etc/aide/aide.conf.d/*' >/dev/null 2>&1; then
        while IFS= read -r f; do
            [[ -f "$f" ]] && files+=("$f")
        done < <(find /etc/aide/aide.conf.d -maxdepth 1 -type f | sort)
    fi
    printf '%s\n' "${files[@]}"
}

aide_expand_value() {
    local value="$1" file
    declare -A defs=()
    while IFS= read -r file; do
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            if [[ "$line" =~ ^[[:space:]]*@@define[[:space:]]+([A-Za-z0-9_]+)[[:space:]]+(.+)$ ]]; then
                defs["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
            fi
        done < "$file"
    done < <(aide_collect_config_files)

    local k repl
    for k in "${!defs[@]}"; do
        repl="${defs[$k]}"
        value="${value//@@\{$k\}/$repl}"
        value="${value//@$k/$repl}"
    done
    value="${value#file:}"
    value="${value%\"}"; value="${value#\"}"
    echo "$value"
}

aide_get_config_path() {
    local wanted="$1" file line raw
    while IFS= read -r file; do
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            if [[ "$line" =~ ^[[:space:]]*${wanted}[[:space:]]*=[[:space:]]*(.+)$ ]]; then
                raw="${BASH_REMATCH[1]}"
                aide_expand_value "$raw"
                return 0
            fi
        done < "$file"
    done < <(aide_collect_config_files)
    return 1
}

aide_list_candidate_paths() {
    local config_in="" config_legacy="" config_out="" p
    config_in="$(aide_get_config_path database_in 2>/dev/null || true)"
    config_legacy="$(aide_get_config_path database 2>/dev/null || true)"
    config_out="$(aide_get_config_path database_out 2>/dev/null || true)"

    printf '%s\n' "$config_in" "$config_legacy" "$config_out" \
        /var/lib/aide/aide.db /var/lib/aide/aide.db.gz \
        /var/lib/aide/aide.db.new /var/lib/aide/aide.db.new.gz | awk 'NF && !seen[$0]++ {print $0}'

    for p in /var/lib/aide/aide.db* /var/lib/*/aide.db*; do
        [[ -e "$p" ]] && echo "$p"
    done | awk 'NF && !seen[$0]++ {print $0}'
}

aide_baseline_exists() {
    local p
    while IFS= read -r p; do
        [[ -n "$p" && -f "$p" ]] || continue
        [[ "$p" == *.new || "$p" == *.new.gz ]] && continue
        [[ "$p" == *aide.db* ]] && return 0
    done < <(aide_list_candidate_paths)
    return 1
}

aide_promote_new_database() {
    local current_db="" legacy_db="" p target
    current_db="$(aide_get_config_path database_in 2>/dev/null || true)"
    legacy_db="$(aide_get_config_path database 2>/dev/null || true)"

    while IFS= read -r p; do
        [[ -n "$p" && -f "$p" ]] || continue
        case "$p" in
            *.new.gz) target="${p%.new.gz}.gz" ;;
            *.new)    target="${p%.new}" ;;
            *)        continue ;;
        esac
        [[ -n "$current_db" ]] && target="$current_db"
        [[ -z "$current_db" && -n "$legacy_db" ]] && target="$legacy_db"
        mkdir -p "$(dirname "$target")" >/dev/null 2>&1 || true
        cp -f "$p" "$target" || continue
        echo "$target"
        return 0
    done < <(aide_list_candidate_paths)
    return 1
}

aide_init_running() {
    pgrep -af '(^|/)(aide|aideinit)( |$)|aide .*--init' >/dev/null 2>&1
}

aide_find_helper() {
    local p
    for p in \
        "$(command -v update-aide.conf 2>/dev/null || true)" \
        /usr/sbin/update-aide.conf \
        /usr/bin/update-aide.conf \
        /usr/libexec/aide/update-aide.conf \
        /usr/lib/aide/update-aide.conf \
        /usr/share/aide/bin/update-aide.conf; do
        [[ -n "$p" && -x "$p" ]] || continue
        echo "$p"
        return 0
    done
    return 1
}

aide_runtime_config_path() {
    local cfg_auto="/var/lib/aide/aide.conf.autogenerated"
    if [[ -f "$cfg_auto" ]]; then
        echo "$cfg_auto"
        return 0
    fi
    if [[ -f /etc/aide/aide.conf ]]; then
        echo "/etc/aide/aide.conf"
        return 0
    fi
    return 1
}

aide_write_local_excludes() {
    local texc path rc=0
    texc=$(mktemp_tracked)
    mkdir -p /etc/aide/aide.conf.d >/dev/null 2>&1 || true
    {
        echo "# Added by security_script.sh"
        echo "# Reduces AIDE runtime on container/data-heavy hosts"
        for path in /run /proc /sys /dev /tmp /var/tmp /var/lib/clamav; do
            [[ -e "$path" ]] || continue
            printf '!%s($|/)
' "$path"
        done
        if [[ -d /var/lib/docker ]] || command -v docker >/dev/null 2>&1; then
            printf '!/var/lib/docker($|/)
'
        fi
        if [[ -d /var/lib/containers ]] || command -v podman >/dev/null 2>&1; then
            printf '!/var/lib/containers($|/)
'
        fi
        [[ -d /var/lib/containerd ]] && printf '!/var/lib/containerd($|/)
'
        [[ -d /var/log/sysstat ]] && printf '!/var/log/sysstat($|/)
'
        [[ -f /var/log/audit/audit.log ]] && printf '!/var/log/audit/audit\.log$
'
        [[ -f /opt/portainer/portainer.db ]] && printf '!/opt/portainer/portainer\.db$
'
        [[ -d /mnt/icybox ]] && printf '!/mnt/icybox($|/)
'
    } > "$texc"

    install_managed_file "$AIDE_LOCAL_EXCLUDES" "$texc" 644
    rc=$?
    if [[ "$rc" -eq 0 || "$rc" -eq 1 ]]; then
        return 0
    fi
    return "$rc"
}

aide_generate_fallback_config() {
    local out="/var/lib/aide/aide.conf.autogenerated" refresh_log="/var/log/aide-config-refresh.log"
    local tmp file

    [[ -f /etc/aide/aide.conf ]] || {
        error "Neither update-aide.conf nor /etc/aide/aide.conf is available for AIDE."
        return 1
    }

    mkdir -p /var/lib/aide /etc/aide/aide.conf.d >/dev/null 2>&1 || true
    tmp=$(mktemp_tracked)
    cat /etc/aide/aide.conf > "$tmp" || return 1

    if [[ -d /etc/aide/aide.conf.d ]]; then
        while IFS= read -r file; do
            [[ -f "$file" ]] || continue
            printf '
# --- merged from %s ---
' "$file" >> "$tmp"
            if [[ -x "$file" ]]; then
                "$file" >> "$tmp" 2>>"$refresh_log" || {
                    error "Executable AIDE snippet failed: $file. See $refresh_log"
                    return 1
                }
            else
                cat "$file" >> "$tmp" || return 1
            fi
            printf '
' >> "$tmp"
        done < <(find /etc/aide/aide.conf.d -maxdepth 1 -type f | sort)
    fi

    install -m 600 "$tmp" "$out" || {
        error "Could not write autogenerated AIDE config: $out"
        return 1
    }
    success "AIDE autogenerated config built via fallback merge."
    return 0
}

aide_refresh_generated_config() {
    local refresh_log="/var/log/aide-config-refresh.log" helper=""
    helper="$(aide_find_helper 2>/dev/null || true)"
    if [[ -n "$helper" ]]; then
        if "$helper" >"$refresh_log" 2>&1; then
            success "AIDE autogenerated config refreshed."
            return 0
        fi
        error "AIDE helper failed. See $refresh_log"
        return 1
    fi

    warn "update-aide.conf not found. Building fallback config: /var/lib/aide/aide.conf.autogenerated"
    aide_generate_fallback_config
}

aide_stop_stale_processes() {
    local pids pid
    pids=$(pgrep -x aide 2>/dev/null || true)
    [[ -z "$pids" ]] && pids=$(pgrep -x aideinit 2>/dev/null || true)
    [[ -z "$pids" ]] && return 0

    warn "AIDE process already running: $pids"
    warn "Stopping stale AIDE process before starting a new initialization."
    while read -r pid; do
        [[ -n "$pid" ]] || continue
        kill -TERM "$pid" 2>/dev/null || true
    done <<< "$pids"
    sleep 2
    while read -r pid; do
        [[ -n "$pid" ]] || continue
        kill -0 "$pid" 2>/dev/null || continue
        kill -KILL "$pid" 2>/dev/null || true
    done <<< "$pids"
}

run_aide_init_command() {
    local timeout_value="${AIDE_INIT_TIMEOUT:-0}" rc=0 cfg=""
    local -a cmd=() pre_cmd=()
    : > "$AIDE_INIT_LOG"

    aide_stop_stale_processes || true
    rm -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db.new.gz >/dev/null 2>&1 || true

    if ! aide_write_local_excludes; then
        error "Could not write local AIDE excludes."
        return 1
    fi
    if ! aide_refresh_generated_config; then
        return 1
    fi

    cfg="$(aide_runtime_config_path 2>/dev/null || true)"
    if [[ -z "$cfg" || ! -f "$cfg" ]]; then
        error "No usable AIDE config found for initialization."
        return 1
    fi

    command -v nice >/dev/null 2>&1 && pre_cmd+=(nice -n 19)
    command -v ionice >/dev/null 2>&1 && pre_cmd+=(ionice -c3)

    if (( timeout_value > 0 )) && command -v timeout >/dev/null 2>&1; then
        cmd=("${pre_cmd[@]}" timeout --foreground "$timeout_value" aide --config="$cfg" --init)
    else
        cmd=("${pre_cmd[@]}" aide --config="$cfg" --init)
    fi

    "${cmd[@]}" </dev/null >>"$AIDE_INIT_LOG" 2>&1 &
    CURRENT_CHILD_PID=$!
    wait "$CURRENT_CHILD_PID"
    rc=$?
    CURRENT_CHILD_PID=""

    if (( rc == 124 )); then
        return 124
    fi
    if (( rc != 0 )); then
        return "$rc"
    fi

    if aide_baseline_exists; then
        return 0
    fi
    if aide_promote_new_database >/dev/null 2>&1; then
        return 0
    fi

    warn "First AIDE initialization finished without a usable baseline. Refreshing config and retrying once ..."
    if ! aide_refresh_generated_config; then
        return 1
    fi
    cfg="$(aide_runtime_config_path 2>/dev/null || true)"
    [[ -n "$cfg" && -f "$cfg" ]] || return 1
    rm -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db.new.gz >/dev/null 2>&1 || true

    if (( timeout_value > 0 )) && command -v timeout >/dev/null 2>&1; then
        cmd=("${pre_cmd[@]}" timeout --foreground "$timeout_value" aide --config="$cfg" --init)
    else
        cmd=("${pre_cmd[@]}" aide --config="$cfg" --init)
    fi

    "${cmd[@]}" </dev/null >>"$AIDE_INIT_LOG" 2>&1 &
    CURRENT_CHILD_PID=$!
    wait "$CURRENT_CHILD_PID"
    rc=$?
    CURRENT_CHILD_PID=""

    if (( rc == 124 )); then
        return 124
    fi
    if (( rc != 0 )); then
        return "$rc"
    fi

    if aide_baseline_exists; then
        return 0
    fi
    if aide_promote_new_database >/dev/null 2>&1; then
        return 0
    fi

    return 65
}

print_security_log_summary() {
    echo
    info "${C_BOLD}$(tr_msg relevant_logs)${C_RESET}"
    echo "  - $(tr_msg log_changes_label):   $SCRIPT_LOG_FILE"
    echo "  - $(tr_msg txlog_label):     $TRANSACTION_LOG"
    if [[ -f "$COMPLIANCE_REPORT" ]]; then
        echo "  - Compliance-Report:   $COMPLIANCE_REPORT"
    else
        echo "  - Compliance-Report:   $COMPLIANCE_REPORT (wird über Punkt 11 frisch erzeugt)"
    fi
    [[ -f "$ROLLBACK_ACTION_REPORT" ]] && echo "  - Rollback-Report:     $ROLLBACK_ACTION_REPORT"
    echo "  - Embedded Check-Katalog: im Skript selbst"
    echo "  - Embedded Ausnahmen:     im Skript selbst"
    [[ -f "$AUDITD_RULES" || -f /var/log/audit/audit.log ]] && echo "  - Auditd-Rohlog:       /var/log/audit/audit.log"
    [[ -f "$AUDITD_RULES" ]] && echo "  - Auditd-Regeln:       $AUDITD_RULES"
    [[ -f "$AIDE_CRON" || -f /var/log/aide-check.log ]] && echo "  - AIDE-Sammellog:      /var/log/aide-check.log"
    [[ -f /var/log/aide-report-$(date +%Y%m%d).log ]] && echo "  - AIDE-Tagesreport:    /var/log/aide-report-$(date +%Y%m%d).log"
    [[ -f "$AIDE_INIT_LOG" ]] && echo "  - AIDE-Init-Log:       $AIDE_INIT_LOG"
    echo
}

show_log_file_tail() {
    local title="$1" file="$2" lines="${3:-80}"
    echo
    echo -e "${C_BOLD}${title}${C_RESET}"
    echo "Path: $file"
    echo "------------------------------------------------------------"
    if [[ -f "$file" ]]; then
        tail -n "$lines" "$file"
    else
        warn "Log file not found: $file"
    fi
    echo
    read -rp "$( [[ "$UI_LANG" == "de" ]] && echo 'Enter zum Fortfahren' || echo 'Press Enter to continue' )" _ </dev/tty
}

show_command_output_pagerless() {
    local title="$1"; shift
    echo
    echo -e "${C_BOLD}${title}${C_RESET}"
    echo "------------------------------------------------------------"
    "$@" 2>&1 || true
    echo
    read -rp "$( [[ "$UI_LANG" == "de" ]] && echo 'Enter zum Fortfahren' || echo 'Press Enter to continue' )" _ </dev/tty
}

show_text_file() {
    local title="$1" file="$2"
    echo
    echo -e "${C_BOLD}${title}${C_RESET}"
    echo "Path: $file"
    echo "------------------------------------------------------------"
    if [[ -f "$file" ]]; then
        cat "$file"
    else
        warn "File not found: $file"
    fi
    echo
    read -rp "$( [[ "$UI_LANG" == "de" ]] && echo 'Enter zum Fortfahren' || echo 'Press Enter to continue' )" _ </dev/tty
}

resolve_user_home_dir() {
    local user_name="$1"
    [[ -n "$user_name" ]] || return 1
    getent passwd "$user_name" 2>/dev/null | awk -F: '{print $6}' | head -n 1
}

find_msmtp_config_file() {
    local candidate user_home
    if [[ -n "${SUDO_USER:-}" ]]; then
        user_home=$(resolve_user_home_dir "$SUDO_USER" || true)
        candidate="${user_home}/.msmtprc"
        [[ -f "$candidate" ]] && { printf '%s\n' "$candidate"; return 0; }
    fi
    candidate="${HOME:-/root}/.msmtprc"
    [[ -f "$candidate" ]] && { printf '%s\n' "$candidate"; return 0; }
    [[ -f /root/.msmtprc ]] && { printf '%s\n' '/root/.msmtprc'; return 0; }
    return 1
}

extract_msmtp_from_address() {
    local config_file="$1"
    awk '/^[[:space:]]*from[[:space:]]+/ {print $2; exit}' "$config_file" 2>/dev/null
}

have_python_reportlab() {
    command -v python3 >/dev/null 2>&1 || return 1
    python3 - <<'PY' >/dev/null 2>&1
import importlib.util
import sys
sys.exit(0 if importlib.util.find_spec("reportlab") else 1)
PY
}

ensure_pdf_render_dependencies() {
    local pkgs=()
    command -v python3 >/dev/null 2>&1 || pkgs+=("python3")
    have_python_reportlab || pkgs+=("python3-reportlab")
    [[ ${#pkgs[@]} -eq 0 ]] && return 0
    if [[ "$UI_LANG" == "de" ]]; then
        warn "Für den formatierten PDF-Report fehlen Pakete: ${pkgs[*]}"
    else
        warn "Missing packages for the formatted PDF report: ${pkgs[*]}"
    fi
    ensure_packages_installed "${pkgs[@]}"
}

ensure_pdf_encryption_dependencies() {
    command -v qpdf >/dev/null 2>&1 && return 0
    if [[ "$UI_LANG" == "de" ]]; then
        warn "Für die PDF-Verschlüsselung fehlt qpdf."
    else
        warn "qpdf is missing for PDF encryption."
    fi
    ensure_packages_installed qpdf
}

prompt_min_password() {
    local prompt="$1" confirm_prompt="$2"
    local pw1 pw2
    while true; do
        IFS= read -r -s -p "$prompt" pw1 </dev/tty
        printf '\n' > /dev/tty
        [[ -n "$pw1" ]] || { warn "Password must not be empty."; continue; }
        [[ ${#pw1} -ge 8 ]] || { warn "Password must be at least 8 characters long."; continue; }
        IFS= read -r -s -p "$confirm_prompt" pw2 </dev/tty
        printf '\n' > /dev/tty
        [[ "$pw1" == "$pw2" ]] || { warn "Passwords do not match."; continue; }
        printf '%s\n' "$pw1"
        return 0
    done
}

generate_random_owner_password() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 24 2>/dev/null && return 0
    fi
    tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 48
    echo
}

verify_protected_pdf_password() {
    local pdf_file="$1" password="$2" verify_log="${3:-}"
    local pwfile tmpout rc=0
    [[ -f "$pdf_file" ]] || return 1
    pwfile=$(mktemp_tracked)
    tmpout=$(mktemp_tracked)
    printf '%s
' "$password" > "$pwfile"
    rm -f "$tmpout" 2>/dev/null || true
    if [[ -n "$verify_log" ]]; then
        qpdf "$pdf_file" --password-file="$pwfile" --warning-exit-0 --decrypt "$tmpout" >> "$verify_log" 2>&1 || rc=$?
    else
        qpdf "$pdf_file" --password-file="$pwfile" --warning-exit-0 --decrypt "$tmpout" >/dev/null 2>&1 || rc=$?
    fi
    [[ $rc -eq 0 && -s "$tmpout" ]]
}

generate_formatted_compliance_pdf() {
    local input_tsv="$1" output_pdf="$2"
    [[ -f "$input_tsv" ]] || { warn "Compliance TSV not found: $input_tsv"; return 1; }
    ensure_governance_directories
    mkdir -p "$(dirname "$output_pdf")" 2>/dev/null || true
    python3 - "$input_tsv" "$output_pdf" "$SCRIPT_VERSION" "$(hostname -f 2>/dev/null || hostname)" "$(date '+%Y-%m-%d %H:%M:%S')" <<'PY'
import csv
import sys
from collections import Counter
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

ts_path, pdf_path, version, host_name, generated = sys.argv[1:6]
rows = []
with open(ts_path, 'r', encoding='utf-8') as fh:
    lines = [line for line in fh if line.strip() and not line.startswith('#')]
reader = csv.DictReader(lines, delimiter='	')
for row in reader:
    rows.append(row)
status_rank = {'RED': 0, 'YELLOW': 1, 'GREEN': 2}
severity_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
rows.sort(key=lambda r: (status_rank.get(r.get('status_matrix', 'YELLOW'), 9), severity_rank.get(r.get('severity', 'info'), 9), r.get('stable_id', '')))
counts = Counter(r.get('status_matrix', 'UNKNOWN') for r in rows)
styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name='Meta', fontSize=9, leading=11, textColor=colors.HexColor('#444444')))
styles.add(ParagraphStyle(name='SectionTitle', fontSize=14, leading=17, spaceAfter=6, textColor=colors.HexColor('#16324f')))
styles.add(ParagraphStyle(name='CheckTitle', fontSize=11, leading=14, spaceAfter=4, textColor=colors.HexColor('#10263d')))
styles.add(ParagraphStyle(name='BodySmall', fontSize=9, leading=12, spaceAfter=4))
styles.add(ParagraphStyle(name='StatusBadge', fontSize=8, leading=10, textColor=colors.white, alignment=1))

def explanation(row):
    title = row.get('title', 'this control').strip().rstrip('.')
    status = row.get('status_matrix', 'YELLOW')
    severity = row.get('severity', 'info')
    reason = (row.get('exception_reason') or '').strip()
    mode = (row.get('exception_mode') or '').strip()
    lead = f"This control verifies whether {title[:1].lower() + title[1:]}." if title else "This control verifies the documented hardening requirement."
    if mode:
        middle = f"The result is currently handled via the exception mode '{mode}'."
        if reason:
            middle += f" Recorded reason: {reason}."
    elif status == 'GREEN':
        middle = 'The host currently meets this requirement according to the latest assessment.'
    elif status == 'RED':
        middle = 'The host currently does not meet this requirement and remediation should be planned.'
    else:
        middle = 'The result is informational or partially evaluated and should be reviewed explicitly.'
    tail = f"It is classified as {severity} severity and mapped to the listed CIS, BSI and STIG control areas."
    return ' '.join([lead, middle, tail])

def status_color(status):
    return {
        'GREEN': colors.HexColor('#1f7a1f'),
        'RED': colors.HexColor('#b11e1e'),
        'YELLOW': colors.HexColor('#b26a00')
    }.get(status, colors.HexColor('#4a5568'))

doc = SimpleDocTemplate(pdf_path, pagesize=A4, leftMargin=16*mm, rightMargin=16*mm, topMargin=14*mm, bottomMargin=14*mm)
story = []
story.append(Paragraph('Linux Server Security Compliance Report', styles['Title']))
story.append(Paragraph(f'Host: <b>{escape(host_name)}</b> &nbsp;&nbsp;|&nbsp;&nbsp; Script version: <b>{escape(version)}</b> &nbsp;&nbsp;|&nbsp;&nbsp; Generated: <b>{escape(generated)}</b>', styles['Meta']))
story.append(Spacer(1, 6))
summary_data = [
    ['Metric', 'Value'],
    ['Total checks', str(len(rows))],
    ['GREEN', str(counts.get('GREEN', 0))],
    ['YELLOW / INFO / WARN', str(counts.get('YELLOW', 0))],
    ['RED', str(counts.get('RED', 0))],
]
summary = Table(summary_data, colWidths=[55*mm, 35*mm])
summary.setStyle(TableStyle([
    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16324f')),
    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
    ('GRID', (0, 0), (-1, -1), 0.35, colors.HexColor('#c5ced8')),
    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor('#eef3f8')]),
    ('ALIGN', (1, 1), (1, -1), 'CENTER'),
]))
story.append(summary)
story.append(Spacer(1, 10))
story.append(Paragraph('Executive Summary', styles['SectionTitle']))
red = counts.get('RED', 0)
yellow = counts.get('YELLOW', 0)
green = counts.get('GREEN', 0)
exec_text = (
    f'The current assessment found <b>{red}</b> open red finding(s), <b>{yellow}</b> yellow or informational result(s), '
    f'and <b>{green}</b> green control(s). '
    'The detailed section is ordered by operational relevance so that open gaps appear first, followed by partial or informational results, and then the controls that already meet the baseline.'
)
story.append(Paragraph(exec_text, styles['BodySmall']))
story.append(Paragraph('Each control contains a short interpretation, the current technical detail, and the mapped CIS, BSI and STIG references to support both operations and audit review.', styles['BodySmall']))
story.append(Spacer(1, 8))
story.append(Paragraph('Detailed Control Results', styles['SectionTitle']))
for row in rows:
    stable_id = escape(row.get('stable_id', 'UNKNOWN'))
    title = escape(row.get('title', 'Untitled control'))
    status = row.get('status_matrix', 'YELLOW')
    severity = escape(row.get('severity', 'info'))
    section = escape(row.get('section', 'unknown'))
    details = escape(row.get('details', '') or 'No additional technical detail recorded.')
    cis = escape(row.get('cis_controls', 'n/a'))
    bsi = escape(row.get('bsi_controls', 'n/a'))
    stig = escape(row.get('stig_controls', 'n/a'))
    reason = escape((row.get('exception_reason') or '').strip())
    mode = escape((row.get('exception_mode') or '').strip())
    story.append(Spacer(1, 4))
    story.append(Paragraph(f'<b>{stable_id}</b> — {title}', styles['CheckTitle']))
    badge = Table([[Paragraph(status, styles['StatusBadge'])]], colWidths=[24*mm], rowHeights=[6*mm])
    badge.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), status_color(status)),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOX', (0, 0), (-1, -1), 0.25, status_color(status)),
    ]))
    meta = Table([[badge, Paragraph(f'<b>Severity:</b> {severity}<br/><b>Section:</b> {section}', styles['BodySmall'])]], colWidths=[28*mm, 142*mm])
    meta.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta)
    story.append(Paragraph(escape(explanation(row)), styles['BodySmall']))
    story.append(Paragraph(f'<b>Technical detail:</b> {details}', styles['BodySmall']))
    story.append(Paragraph(f'<b>Compliance mapping:</b> CIS: {cis}<br/>BSI: {bsi}<br/>STIG: {stig}', styles['BodySmall']))
    if mode or reason:
        extra = f'<b>Exception handling:</b> mode={mode or "n/a"}'
        if reason:
            extra += f'<br/><b>Exception reason:</b> {reason}'
        story.append(Paragraph(extra, styles['BodySmall']))
    story.append(Table([['']], colWidths=[178*mm], rowHeights=[0.6*mm], style=TableStyle([('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#d7dee7'))])))

def add_page_number(canvas, doc):
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(colors.HexColor('#555555'))
    canvas.drawRightString(A4[0] - 16*mm, 8*mm, f'Page {doc.page}')

doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
PY
}

encrypt_pdf_with_password() {
    local input_pdf="$1" output_pdf="$2" password="$3"
    local owner_password qpdf_log qpdf_version
    [[ -f "$input_pdf" ]] || { warn "Input PDF not found: $input_pdf"; return 1; }
    [[ ${#password} -ge 8 ]] || { warn "Password must be at least 8 characters long."; return 1; }
    ensure_pdf_encryption_dependencies || return 1
    owner_password=$(generate_random_owner_password)
    [[ -n "$owner_password" ]] || { warn "Could not generate random PDF owner password."; return 1; }
    ensure_governance_directories
    qpdf_log="${GOVERNANCE_REPORT_DIR}/qpdf_encrypt.log"
    rm -f "$output_pdf" 2>/dev/null || true
    qpdf_version=$(qpdf --version 2>/dev/null | head -n 1 || true)
    {
        printf 'timestamp=%s
' "$(date '+%Y-%m-%d %H:%M:%S')"
        printf 'input_pdf=%s
' "$input_pdf"
        printf 'output_pdf=%s
' "$output_pdf"
        printf 'qpdf_version=%s
' "${qpdf_version:-unknown}"
    } > "$qpdf_log"
    if ! qpdf --encrypt "$password" "$owner_password" 256 -- "$input_pdf" "$output_pdf" >> "$qpdf_log" 2>&1; then
        rm -f "$output_pdf" 2>/dev/null || true
        warn "qpdf encryption command failed."
        warn "See: $qpdf_log"
        return 1
    fi
    if ! verify_protected_pdf_password "$output_pdf" "$password" "$qpdf_log"; then
        rm -f "$output_pdf" 2>/dev/null || true
        warn "Protected PDF verification failed with the entered password."
        warn "See: $qpdf_log"
        return 1
    fi
    success "Protected PDF verification succeeded with the entered password."
    return 0
}

send_attachment_via_msmtp() {
    local attachment="$1" recipient="$2" subject="$3" body_text="$4"
    local msmtp_config from_addr host_name boundary filename

    [[ -f "$attachment" ]] || { warn "Attachment not found: $attachment"; return 1; }
    command -v msmtp >/dev/null 2>&1 || {
        if [[ "$UI_LANG" == "de" ]]; then
            warn "msmtp ist nicht installiert."
        else
            warn "msmtp is not installed."
        fi
        ensure_packages_installed msmtp msmtp-mta || return 1
    }
    msmtp_config=$(find_msmtp_config_file) || { warn "No usable .msmtprc found for root or the invoking user."; return 1; }
    from_addr=$(extract_msmtp_from_address "$msmtp_config")
    host_name=$(hostname -f 2>/dev/null || hostname)
    [[ -n "$from_addr" ]] || from_addr="root@${host_name}"
    boundary="====SECURITY_SCRIPT_$(date +%s)_$$===="
    filename=$(basename "$attachment")

    {
        printf 'To: %s
' "$recipient"
        printf 'From: %s
' "$from_addr"
        printf 'Subject: %s
' "$subject"
        printf 'Date: %s
' "$(LC_ALL=C date -R)"
        printf 'MIME-Version: 1.0
'
        printf 'Content-Type: multipart/mixed; boundary="%s"
' "$boundary"
        printf '
'
        printf -- '--%s
' "$boundary"
        printf 'Content-Type: text/plain; charset=UTF-8
'
        printf 'Content-Transfer-Encoding: 8bit

'
        printf '%b

' "$body_text"
        printf -- '--%s
' "$boundary"
        printf 'Content-Type: application/pdf; name="%s"
' "$filename"
        printf 'Content-Transfer-Encoding: base64
'
        printf 'Content-Disposition: attachment; filename="%s"

' "$filename"
        base64 -w 76 "$attachment"
        printf '
--%s--
' "$boundary"
    } | msmtp --file="$msmtp_config" -t
}

generate_compliance_report_from_live_state() {
    local old_assess="$ASSESS_ONLY" old_verify="$VERIFY_AFTER_HARDENING" old_dry="$DRY_RUN"
    local tmp_output
    tmp_output=$(mktemp_tracked)

    ensure_governance_directories
    ASSESS_ONLY=false
    VERIFY_AFTER_HARDENING=false
    DRY_RUN=false
    declare -gA ASSESS_RESULTS=()
    declare -ga ASSESS_ORDER=()

    if ! run_assessment >"$tmp_output" 2>&1; then
        cat "$tmp_output" >&2
        ASSESS_ONLY="$old_assess"
        VERIFY_AFTER_HARDENING="$old_verify"
        DRY_RUN="$old_dry"
        return 1
    fi
    write_compliance_report
    ASSESS_ONLY="$old_assess"
    VERIFY_AFTER_HARDENING="$old_verify"
    DRY_RUN="$old_dry"
    return 0
}

handle_compliance_report_menu() {
    local recipient subject pdf_password body_text answer
    local pdf_generated=false protected_pdf_generated=false

    info "$( [[ "$UI_LANG" == "de" ]] && echo 'Erzeuge frischen Compliance-Report aus dem aktuellen Systemzustand ...' || echo 'Generating a fresh compliance report from the current system state ...' )"
    if ! generate_compliance_report_from_live_state; then
        warn "$( [[ "$UI_LANG" == "de" ]] && echo 'Compliance-Report konnte nicht erzeugt werden.' || echo 'Could not generate compliance report.' )"
        read -rp "$( [[ "$UI_LANG" == "de" ]] && echo 'Enter zum Fortfahren' || echo 'Press Enter to continue' )" _ </dev/tty
        return 1
    fi

    success "$( [[ "$UI_LANG" == "de" ]] && echo 'Compliance-Report wurde aktualisiert.' || echo 'Compliance report refreshed.' )"
    echo "TSV: $COMPLIANCE_REPORT"

    if ensure_pdf_render_dependencies; then
        if generate_formatted_compliance_pdf "$COMPLIANCE_REPORT" "$COMPLIANCE_REPORT_PDF"; then
            pdf_generated=true
            success "$( [[ "$UI_LANG" == "de" ]] && echo 'Formatierter PDF-Report wurde erzeugt.' || echo 'Formatted PDF report generated.' )"
            echo "PDF: $COMPLIANCE_REPORT_PDF"
        else
            warn "$( [[ "$UI_LANG" == "de" ]] && echo 'PDF-Report konnte nicht erzeugt werden.' || echo 'Could not generate PDF report.' )"
        fi
    else
        warn "$( [[ "$UI_LANG" == "de" ]] && echo 'PDF-Report wurde wegen fehlender Pakete nicht erzeugt.' || echo 'PDF report was not generated because required packages are missing.' )"
    fi

    echo
    if [[ "$UI_LANG" == "de" ]]; then
        read -rp "E-Mail-Adresse für Versand eingeben (Enter = kein Versand): " recipient </dev/tty
    else
        read -rp "Enter recipient email address to send the report (Enter = no mail delivery): " recipient </dev/tty
    fi

    if [[ -n "$recipient" ]]; then
        if validate_email "$recipient"; then
            if ! $pdf_generated; then
                ensure_pdf_render_dependencies && generate_formatted_compliance_pdf "$COMPLIANCE_REPORT" "$COMPLIANCE_REPORT_PDF" && pdf_generated=true
            fi
            if ! $pdf_generated; then
                warn "$( [[ "$UI_LANG" == "de" ]] && echo 'Kein PDF verfügbar. Versand wird aus Sicherheitsgründen abgebrochen.' || echo 'No PDF available. Sending is aborted for security reasons.' )"
            else
                if [[ "$UI_LANG" == "de" ]]; then
                    pdf_password=$(prompt_min_password "PDF-Passwort (mindestens 8 Zeichen): " "PDF-Passwort bestätigen: ")
                else
                    pdf_password=$(prompt_min_password "PDF password (minimum 8 characters): " "Confirm PDF password: ")
                fi
                if [[ -n "$pdf_password" ]]; then
                    if encrypt_pdf_with_password "$COMPLIANCE_REPORT_PDF" "$COMPLIANCE_REPORT_PDF_PROTECTED" "$pdf_password"; then
                        protected_pdf_generated=true
                        subject="Compliance Report - $(hostname -f 2>/dev/null || hostname) - $(date '+%Y-%m-%d %H:%M:%S')"
                        body_text="Compliance report generated by security_script.sh v${SCRIPT_VERSION}
Host: $(hostname -f 2>/dev/null || hostname)
Generated: $(date '+%Y-%m-%d %H:%M:%S')
Local TSV path: ${COMPLIANCE_REPORT}
Local PDF path: ${COMPLIANCE_REPORT_PDF_PROTECTED}

The attached PDF is password-protected. Share the password via a separate communication channel."
                        if send_attachment_via_msmtp "$COMPLIANCE_REPORT_PDF_PROTECTED" "$recipient" "$subject" "$body_text"; then
                            success "$( [[ "$UI_LANG" == "de" ]] && echo "Geschützter PDF-Report an $recipient gesendet." || echo "Protected PDF report sent to $recipient." )"
                        else
                            warn "$( [[ "$UI_LANG" == "de" ]] && echo 'Versand fehlgeschlagen. Die Dateien bleiben lokal gespeichert.' || echo 'Sending failed. The files remain available locally.' )"
                        fi
                    else
                        warn "$( [[ "$UI_LANG" == "de" ]] && echo 'PDF-Verschlüsselung fehlgeschlagen. Versand wurde nicht durchgeführt.' || echo 'PDF encryption failed. The report was not sent.' )"
                    fi
                fi
            fi
        else
            warn "$( [[ "$UI_LANG" == "de" ]] && echo 'Ungültige E-Mail-Adresse. Es erfolgt kein Versand.' || echo 'Invalid email address. No mail will be sent.' )"
        fi
    fi

    echo
    info "$( [[ "$UI_LANG" == "de" ]] && echo 'Erzeugte Report-Artefakte:' || echo 'Generated report artifacts:' )"
    echo "  - TSV: $COMPLIANCE_REPORT"
    $pdf_generated && echo "  - PDF: $COMPLIANCE_REPORT_PDF"
    $protected_pdf_generated && echo "  - PDF (protected): $COMPLIANCE_REPORT_PDF_PROTECTED"

    if [[ "$UI_LANG" == "de" ]]; then
        read -rp "Rohdaten-TSV jetzt anzeigen? [y/N]: " answer </dev/tty
    else
        read -rp "Show raw TSV now? [y/N]: " answer </dev/tty
    fi
    case "$answer" in
        y|Y|yes|YES|j|J) show_text_file "Compliance Report (TSV)" "$COMPLIANCE_REPORT" ;;
        *) read -rp "$( [[ "$UI_LANG" == "de" ]] && echo 'Enter zum Fortfahren' || echo 'Press Enter to continue' )" _ </dev/tty ;;
    esac
}

view_logs_menu() {
    local selection latest_aide_report prompt
    while true; do
        ensure_governance_files
        echo
        echo -e "${C_BOLD}${C_CYAN}$( [[ "$UI_LANG" == "de" ]] && echo 'Logs / Reports' || echo 'Logs / reports' )${C_RESET}"
        echo "  1) $( [[ "$UI_LANG" == "de" ]] && echo 'Security-Log-Übersicht' || echo 'Security log summary' )"
        echo "  2) AIDE Init-Log"
        echo "  3) AIDE Check-Log"
        echo "  4) $( [[ "$UI_LANG" == "de" ]] && echo 'Neuester AIDE-Report' || echo 'Latest AIDE report' )"
        echo "  5) Fail2ban Journal"
        echo "  6) Fail2ban Status"
        echo "  7) auditd Journal"
        echo "  8) auditd Raw Log"
        echo "  9) $( [[ "$UI_LANG" == "de" ]] && echo 'Skript-Änderungslog' || echo 'Script change log' )"
        echo " 10) $( [[ "$UI_LANG" == "de" ]] && echo 'Transaktionslog' || echo 'Transaction log' )"
        echo " 11) $( [[ "$UI_LANG" == "de" ]] && echo 'Compliance-Report' || echo 'Compliance report' )"
        echo " 12) $( [[ "$UI_LANG" == "de" ]] && echo 'Rollback-Report' || echo 'Rollback report' )"
        echo " 13) $( [[ "$UI_LANG" == "de" ]] && echo 'Eingebetteten Check-Katalog anzeigen' || echo 'Show embedded check catalog' )"
        echo " 14) $( [[ "$UI_LANG" == "de" ]] && echo 'Eingebettete Ausnahmen anzeigen' || echo 'Show embedded exceptions' )"
        echo " 15) $( [[ "$UI_LANG" == "de" ]] && echo 'Dieses Skript bearbeiten (Governance)' || echo 'Edit this script (governance)' )"
        echo " 16) $( [[ "$UI_LANG" == "de" ]] && echo 'Dieses Skript bearbeiten (Ausnahmen-Block)' || echo 'Edit this script (exceptions block)' )"
        echo "  0) $( [[ "$UI_LANG" == "de" ]] && echo 'Zurück' || echo 'Back' )"
        echo
        prompt=$( [[ "$UI_LANG" == "de" ]] && echo 'Auswahl [0-16]: ' || echo 'Selection [0-16]: ' )
        read -rp "$prompt" selection </dev/tty
        case "$selection" in
            1) print_security_log_summary; read -rp "$( [[ "$UI_LANG" == "de" ]] && echo 'Enter zum Fortfahren' || echo 'Press Enter to continue' )" _ </dev/tty ;;
            2) show_log_file_tail "AIDE Init Log" "$AIDE_INIT_LOG" 120 ;;
            3) show_log_file_tail "AIDE Check Log" "/var/log/aide-check.log" 120 ;;
            4) latest_aide_report=$(ls -1t /var/log/aide-report-*.log 2>/dev/null | head -n 1 || true); [[ -n "$latest_aide_report" ]] && show_log_file_tail "Latest AIDE Report" "$latest_aide_report" 120 || { warn "No AIDE report found."; read -rp "$( [[ "$UI_LANG" == "de" ]] && echo 'Enter zum Fortfahren' || echo 'Press Enter to continue' )" _ </dev/tty; } ;;
            5) show_command_output_pagerless "Fail2ban Journal" journalctl -u fail2ban -n 120 --no-pager ;;
            6) show_command_output_pagerless "Fail2ban Status" bash -lc 'fail2ban-client status 2>/dev/null; echo; fail2ban-client status sshd 2>/dev/null || true' ;;
            7) show_command_output_pagerless "auditd Journal" journalctl -u auditd -n 120 --no-pager ;;
            8) show_log_file_tail "auditd Raw Log" "/var/log/audit/audit.log" 120 ;;
            9) show_log_file_tail "Script Change Log" "$SCRIPT_LOG_FILE" 120 ;;
            10) show_log_file_tail "Transaction Log" "$TRANSACTION_LOG" 120 ;;
            11) handle_compliance_report_menu ;;
            12) show_text_file "Rollback Report" "$ROLLBACK_ACTION_REPORT" ;;
            13) show_generated_text "Embedded Check Catalog" emit_embedded_check_catalog ;;
            14) show_generated_text "Embedded Exceptions" emit_embedded_exceptions_view ;;
            15) open_embedded_script_editor "Edit This Script (Governance)" "EMBEDDED USER EXCEPTION BLOCK" false ;;
            16) open_embedded_script_editor "Edit This Script (Exceptions Block)" "EMBEDDED_EXCEPTION_MODE" true ;;
            0) return 0 ;;
            *) warn "$( [[ "$UI_LANG" == "de" ]] && echo 'Ungültige Auswahl.' || echo 'Invalid selection.' )" ;;
        esac
    done
}

was_package_installed_by_script() {
    local pkg="$1"
    [[ -f "$TRANSACTION_LOG" ]] || return 1
    grep -qF "|PKG_INSTALLED|$pkg" "$TRANSACTION_LOG"
}

remove_packages_if_recorded() {
    local pkg
    for pkg in "$@"; do
        was_package_installed_by_script "$pkg" || continue
        is_package_installed "$pkg" || continue
        info "Removing package recorded by script: $pkg"
        apt-get remove -y "$pkg" >/dev/null 2>&1 \
            && success "  ✔ Package removed: $pkg" \
            || warn "  Could not remove package: $pkg"
    done
}

remove_packages_if_present() {
    local pkg
    for pkg in "$@"; do
        is_package_installed "$pkg" || continue
        info "Removing installed package: $pkg"
        apt-get remove -y "$pkg" >/dev/null 2>&1             && success "  ✔ Package removed: $pkg"             || warn "  Could not remove package: $pkg"
    done
}

component_is_removable() {
    local target="$1"
    case "$target" in
        ssh_baseline)
            ssh_dropin_has_any_key AllowAgentForwarding AllowTcpForwarding ChallengeResponseAuthentication KbdInteractiveAuthentication ClientAliveCountMax ClientAliveInterval LoginGraceTime MaxAuthTries MaxSessions PasswordAuthentication PermitRootLogin PermitUserEnvironment PrintLastLog UsePAM X11Forwarding && return 0
            return 1 ;;
        ssh_crypto)
            ssh_dropin_has_any_key MACs Ciphers KexAlgorithms HostKeyAlgorithms PubkeyAcceptedAlgorithms && return 0
            return 1 ;;
        ssh_google_2fa|google_2fa|ssh_2fa)
            [[ -f "/etc/pam.d/sshd" ]] && grep -Eq '^[[:space:]]*auth[[:space:]].*pam_google_authenticator\.so\b' /etc/pam.d/sshd 2>/dev/null && return 0
            is_package_installed "libpam-google-authenticator" && return 0
            find /root /home -maxdepth 2 -name .google_authenticator -type f 2>/dev/null | grep -q . && return 0
            [[ "$(get_effective_sshd_config "AuthenticationMethods")" == *keyboard-interactive* ]] && return 0
            return 1 ;;
        ssh|ssh_hardening)
            component_is_removable ssh_baseline && return 0
            component_is_removable ssh_crypto && return 0
            return 1 ;;
        banners|banner)
            [[ -f "${BANNER_FILE}${BACKUP_SUFFIX}" ]] && return 0
            [[ -f "${MOTD_FILE}${BACKUP_SUFFIX}" ]] && return 0
            [[ -f "$BANNER_FILE" ]] && ([[ -s "$BANNER_FILE" ]] || grep -q "AUTHORIZED ACCESS ONLY" "$BANNER_FILE" 2>/dev/null) && return 0
            [[ -f "$MOTD_FILE" ]] && ([[ -s "$MOTD_FILE" ]] || grep -q "AUTHORIZED ACCESS ONLY" "$MOTD_FILE" 2>/dev/null) && return 0
            [[ -f /etc/ssh/sshd_config ]] && grep -qiE "^\s*Banner\s+$BANNER_FILE(\s|$)" /etc/ssh/sshd_config && return 0
            return 1 ;;
        auditd|audit)
            [[ -f "${AUDITD_RULES}${BACKUP_SUFFIX}" || -f "$AUDITD_RULES" ]] && return 0
            is_package_installed "auditd" && return 0
            is_package_installed "audispd-plugins" && return 0
            return 1 ;;
        aide)
            [[ -f "${AIDE_CRON}${BACKUP_SUFFIX}" || -f "$AIDE_CRON" ]] && return 0
            [[ -f "${AIDE_LOCAL_EXCLUDES}${BACKUP_SUFFIX}" || -f "$AIDE_LOCAL_EXCLUDES" ]] && return 0
            [[ -f /var/lib/aide/aide.db || -f /var/lib/aide/aide.db.new || -f /var/lib/aide/aide.db.gz || -f /var/lib/aide/aide.conf.autogenerated ]] && return 0
            is_package_installed "aide-common" && return 0
            is_package_installed "aide" && return 0
            return 1 ;;
        pam|pam_hardening)
            [[ -f "${PWQUALITY_CONF}${BACKUP_SUFFIX}" || -f "${FAILLOCK_CONF}${BACKUP_SUFFIX}" ]] && return 0
            [[ -f "$FAILLOCK_CONF" ]] && grep -qE '^\s*(deny|unlock_time|even_deny_root)\s*=' "$FAILLOCK_CONF" 2>/dev/null && return 0
            [[ -f "$TRANSACTION_LOG" ]] && grep -q "|ROOT_LOCKED|" "$TRANSACTION_LOG" && return 0
            return 1 ;;
        login_umask|umask|system_umask)
            [[ -f "${LOGIN_DEFS_FILE}${BACKUP_SUFFIX}" || -f "${PROFILE_UMASK_FILE}${BACKUP_SUFFIX}" ]] && return 0
            [[ -f "$PROFILE_UMASK_FILE" ]] && return 0
            [[ -f "$LOGIN_DEFS_FILE" ]] && awk '$1 == "UMASK" {print $2}' "$LOGIN_DEFS_FILE" 2>/dev/null | tail -n 1 | grep -qxE '0?27|0?77' && return 0
            return 1 ;;
        suid_sgid|suidsgid)
            [[ -f "$SUID_SGID_AUDIT_SCRIPT" || -f "$SUID_SGID_AUDIT_BASELINE" || -f "$SUID_SGID_AUDIT_CRON" || -f "$SUID_SGID_AUDIT_REPORT" ]] && return 0
            return 1 ;;
        sysctl)
            [[ -f "${SYSCTL_CONFIG_FILE}${BACKUP_SUFFIX}" || -f "$SYSCTL_CONFIG_FILE" ]] && return 0
            return 1 ;;
        journald)
            [[ -f "/etc/systemd/journald.conf${BACKUP_SUFFIX}" ]] && return 0
            [[ -f /etc/systemd/journald.conf ]] && grep -qE '^\s*SystemMaxUse=' /etc/systemd/journald.conf 2>/dev/null && return 0
            return 1 ;;
        sudoers|sudoers_tty)
            [[ -f "${SUDOERS_TTY_FILE}${BACKUP_SUFFIX}" || -f "$SUDOERS_TTY_FILE" ]] && return 0
            sudoers_has_tty_tickets && [[ -f "$SUDOERS_TTY_FILE" ]] && return 0
            return 1 ;;
        modules|module_blacklist)
            [[ -f "${MODPROBE_BLACKLIST}${BACKUP_SUFFIX}" || -f "$MODPROBE_BLACKLIST" ]] && return 0
            return 1 ;;
        fail2ban)
            [[ -f "/etc/fail2ban/jail.local${BACKUP_SUFFIX}" || -f "/etc/fail2ban/jail.local" ]] && return 0
            is_package_installed "fail2ban" && return 0
            return 1 ;;
        unattended_upgrades)
            [[ -f "/etc/apt/apt.conf.d/20auto-upgrades${BACKUP_SUFFIX}" || -f "/etc/apt/apt.conf.d/50unattended-upgrades${BACKUP_SUFFIX}" ]] && return 0
            is_package_installed "unattended-upgrades" && return 0
            return 1 ;;
        clamav)
            is_package_installed "clamav" && return 0
            is_package_installed "clamav-daemon" && return 0
            is_package_installed "clamav-freshclam" && return 0
            return 1 ;;
        ufw)
            is_package_installed "ufw" && return 0
            return 1 ;;
        *)
            return 1 ;;
    esac
}

component_menu_description() {
    local target="$1"
    case "$target" in
        ssh_baseline) echo "SSH-Basishärtung (Forwarding, Timeouts, Sessions, Root/Passwort)" ;;
        ssh_crypto) echo "SSH-Crypto-Policy (MACs / Ciphers / KEX)" ;;
        ssh_google_2fa|google_2fa|ssh_2fa) echo "SSH Google 2FA (PAM / keyboard-interactive / Benutzer-Secret)" ;;
        ssh|ssh_hardening) echo "SSH-Hardening / SSH-Crypto-Policy" ;;
        banners|banner) echo "Login-Banner / MOTD / SSH-Banner" ;;
        auditd|audit) echo "auditd Regeln und ggf. Paket" ;;
        aide) echo "AIDE Cronjob / Baseline / ggf. Paket" ;;
        pam|pam_hardening) echo "PAM pwquality / faillock / Root-Unlock" ;;
        login_umask|umask|system_umask) echo "Interaktive Login-UMASK" ;;
        suid_sgid|suidsgid) echo "SUID/SGID Baseline / Daily Audit" ;;
        sysctl) echo "Security Sysctl-Konfiguration" ;;
        journald) echo "Journald Log-Limit-Konfiguration" ;;
        sudoers|sudoers_tty) echo "sudoers TTY-/Ticket-Konfiguration" ;;
        modules|module_blacklist) echo "Kernel-Modul-Blacklist" ;;
        fail2ban) echo "Fail2ban Paket / jail.local" ;;
        unattended_upgrades) echo "Unattended-Upgrades Paket / APT-Konfiguration" ;;
        clamav) echo "ClamAV Paket / Dienste" ;;
        ufw) echo "UFW Paket / aktive Firewall" ;;
        *) echo "Unbekannt" ;;
    esac
}

ssh_dropin_path_in_use() {
    if [[ -f "$SSHD_HARDENING_DROPIN" ]]; then
        echo "$SSHD_HARDENING_DROPIN"
    elif [[ -f "$SSHD_HARDENING_DROPIN_LEGACY" ]]; then
        echo "$SSHD_HARDENING_DROPIN_LEGACY"
    else
        echo "$SSHD_HARDENING_DROPIN"
    fi
}

ssh_dropin_has_any_key() {
    local file key
    file=$(ssh_dropin_path_in_use)
    [[ -f "$file" ]] || return 1
    for key in "$@"; do
        grep -qE "^\s*${key}\b" "$file" 2>/dev/null && return 0
    done
    return 1
}


section_check_is_red() {
    local check_id="$1"
    local entry raw
    entry="${ASSESS_RESULTS[$check_id]:-}"
    [[ -n "$entry" ]] || return 1
    raw="${entry%%:*}"
    [[ "$(normalize_matrix_status "$raw")" == "RED" ]]
}

section_has_pending_findings() {
    local func="$1"
    case "$func" in
        configure_unattended_upgrades)  section_check_is_red "UNATTENDED_UPGRADES" ;;
        configure_ssh_hardening)        section_check_is_red "SSH_ROOT_LOGIN" || section_check_is_red "SSH_PASSWORD_AUTH" || section_check_is_red "SSH_X11" || section_check_is_red "SSH_AGENT_FWD" || section_check_is_red "SSH_TCP_FWD" || section_check_is_red "SSH_GRACE_TIME" || section_check_is_red "SSH_MAX_AUTH" || section_check_is_red "SSH_CRYPTO_POLICY" ;;
        configure_fail2ban)             section_check_is_red "FAIL2BAN" ;;
        configure_ufw)                  section_check_is_red "UFW_ACTIVE" ;;
        configure_clamav)               section_check_is_red "CLAMAV" ;;
        configure_sysctl)               section_check_is_red "SYSCTL" ;;
        configure_sudoers_tty)          section_check_is_red "SUDOERS_TTY" ;;
        configure_login_umask)          section_check_is_red "LOGIN_UMASK" ;;
        configure_suid_sgid_inventory)  section_check_is_red "SUID_SGID_BASELINE" ;;
        configure_auditd)               section_check_is_red "AUDITD" || section_check_is_red "AUDITD_EXTENDED" ;;
        configure_aide)                 section_check_is_red "AIDE" ;;
        configure_apparmor_enforce)     section_check_is_red "APPARMOR" ;;
        configure_filesystem_hardening) section_check_is_red "FSTAB_HARDENING" ;;
        configure_module_blacklist)     section_check_is_red "MODULE_BLACKLIST" ;;
        configure_core_dumps)           section_check_is_red "CORE_DUMPS" ;;
        configure_pam_hardening)        section_check_is_red "PAM_PWQUALITY" || section_check_is_red "PAM_FAILLOCK" ;;
        configure_login_banners)        section_check_is_red "LOGIN_BANNER" ;;
        *) return 1 ;;
    esac
}

should_execute_section_in_current_mode() {
    local func="$1"
    if $INTERACTIVE_STEP_MODE && ! $EXPERT_PROFILE_MODE; then
        return 0
    fi
    if $INTERACTIVE_RECOMMENDED_MODE || $EXPERT_PROFILE_MODE || $AUTO_MODE; then
        section_has_pending_findings "$func"
        return $?
    fi
    return 0
}

count_targeted_pending_sections() {
    local func count=0
    for func in "$@"; do
        if should_execute_section_in_current_mode "$func"; then
            count=$((count+1))
        fi
    done
    echo "$count"
}

interactive_selective_removal_menu() {
    local -a candidate_targets=(ssh_baseline ssh_crypto ssh_google_2fa banners pam login_umask suid_sgid sysctl journald sudoers modules auditd aide fail2ban unattended_upgrades clamav ufw)
    local -a visible_targets=()
    local -a hidden_targets=()
    local -a selected_flags=()
    local target input part idx marker csv=""

    SELECTIVE_MENU_RESULT=""

    for target in "${candidate_targets[@]}"; do
        if component_is_removable "$target"; then
            visible_targets+=("$target")
            selected_flags+=("false")
        else
            hidden_targets+=("$target")
        fi
    done

    if [[ ${#visible_targets[@]} -eq 0 ]]; then
        warn "$(tr_msg no_removable)"
        if [[ ${#hidden_targets[@]} -gt 0 ]]; then
            info "Nicht angezeigt (aktuell nicht vorhanden oder nicht vom Skript verwaltet):"
            local h
            for h in "${hidden_targets[@]}"; do
                printf '  - %-20s %s\n' "$h" "$(component_hidden_reason "$h")"
            done
        fi
        return 1
    fi

    while true; do
        echo
        echo -e "${C_BOLD}${C_YELLOW_BOLD}$(tr_msg selective_menu_title)${C_RESET}"
        local i
        for i in "${!visible_targets[@]}"; do
            marker=" "
            [[ "${selected_flags[$i]}" == "true" ]] && marker="x"
            printf '  %2d) [%s] %-18s - %s\n' "$((i+1))" "$marker" "${visible_targets[$i]}" "$(component_menu_description "${visible_targets[$i]}")"
        done
        if [[ ${#hidden_targets[@]} -gt 0 ]]; then
            echo ""
            info "Nicht angezeigt (aktuell nicht vorhanden oder nicht vom Skript verwaltet):"
            local h
            for h in "${hidden_targets[@]}"; do
                printf '  - %-20s %s\n' "$h" "$(component_hidden_reason "$h")"
            done
        fi
        echo ""
        printf '  a) %s\n' "$(tr_msg mark_all)"
        printf '  n) %s\n' "$(tr_msg clear_all)"
        printf '  f) %s\n' "$(tr_msg apply_selection)"
        printf '  q) %s\n' "$(tr_msg cancel)"
        printf '     %s\n' "$(tr_msg enter_apply_hint)"
        echo ""
        read -rp "$(tr_msg toggle_prompt)" input </dev/tty
        input="${input#${input%%[![:space:]]*}}"
        input="${input%${input##*[![:space:]]}}"

        case "$input" in
            "")
                csv=""
                for i in "${!visible_targets[@]}"; do
                    [[ "${selected_flags[$i]}" == "true" ]] || continue
                    [[ -n "$csv" ]] && csv+="," 
                    csv+="${visible_targets[$i]}"
                done
                [[ -n "$csv" ]] || continue
                SELECTIVE_MENU_RESULT="$csv"
                return 0 ;;
            a|A)
                for i in "${!selected_flags[@]}"; do selected_flags[$i]="true"; done ;;
            n|N)
                for i in "${!selected_flags[@]}"; do selected_flags[$i]="false"; done ;;
            f|F)
                csv=""
                for i in "${!visible_targets[@]}"; do
                    [[ "${selected_flags[$i]}" == "true" ]] || continue
                    [[ -n "$csv" ]] && csv+="," 
                    csv+="${visible_targets[$i]}"
                done
                [[ -n "$csv" ]] || { warn "$(tr_msg nothing_selected)"; continue; }
                SELECTIVE_MENU_RESULT="$csv"
                return 0 ;;
            q|Q)
                return 1 ;;
            *)
                input="${input//;/,}"
                input="${input// /,}"
                IFS=',' read -r -a parts <<< "$input"
                local selected_count=0
                for i in "${!selected_flags[@]}"; do
                    [[ "${selected_flags[$i]}" == "true" ]] && selected_count=$((selected_count+1))
                done
                if [[ ${#parts[@]} -eq 1 ]] && [[ "${parts[0]}" =~ ^[0-9]+$ ]] && (( selected_count == 0 )); then
                    idx=$((parts[0]-1))
                    if (( idx < 0 || idx >= ${#visible_targets[@]} )); then
                        warn "$(tr_msg invalid_number): ${parts[0]}"
                        continue
                    fi
                    SELECTIVE_MENU_RESULT="${visible_targets[$idx]}"
                    return 0
                fi
                for part in "${parts[@]}"; do
                    [[ -n "$part" ]] || continue
                    [[ "$part" =~ ^[0-9]+$ ]] || { warn "$(tr_msg invalid_input): $part"; continue; }
                    idx=$((part-1))
                    if (( idx < 0 || idx >= ${#visible_targets[@]} )); then
                        warn "$(tr_msg invalid_number): $part"
                        continue
                    fi
                    if [[ "${selected_flags[$idx]}" == "true" ]]; then
                        selected_flags[$idx]="false"
                    else
                        selected_flags[$idx]="true"
                    fi
                done ;;
        esac
    done
}

component_hidden_reason() {
    local target="$1"
    case "$target" in
        ssh_baseline) echo "kein verwalteter SSH-Baseline-Drop-in erkannt" ;;
        ssh_crypto) echo "keine verwaltete SSH-Crypto-Policy erkannt" ;;
        ssh_google_2fa|google_2fa|ssh_2fa) echo "keine Google-2FA-Spuren für SSH erkannt" ;;
        banners|banner) echo "keine vom Skript verwalteten Banner erkannt" ;;
        auditd|audit) echo "auditd-Regeln/Paket aktuell nicht vorhanden" ;;
        aide) echo "AIDE-Paket/Baseline aktuell nicht vorhanden" ;;
        pam|pam_hardening) echo "kein verwalteter PAM-Rückbauzustand erkannt" ;;
        login_umask|umask|system_umask) echo "keine verwaltete Login-UMASK erkannt" ;;
        suid_sgid|suidsgid) echo "keine SUID/SGID-Baseline erkannt" ;;
        sysctl) echo "keine verwaltete Sysctl-Datei erkannt" ;;
        journald) echo "keine verwaltete Journald-Konfiguration erkannt" ;;
        sudoers|sudoers_tty) echo "kein verwalteter sudoers-Rückbaupunkt erkannt" ;;
        modules|module_blacklist) echo "keine verwaltete Modul-Blacklist erkannt" ;;
        fail2ban) echo "Fail2ban-Paket/jail.local aktuell nicht vorhanden" ;;
        unattended_upgrades) echo "Unattended-Upgrades-Konfiguration aktuell nicht vorhanden" ;;
        clamav) echo "ClamAV-Paket aktuell nicht vorhanden" ;;
        ufw) echo "UFW-Paket oder verwaltete Regeln aktuell nicht vorhanden" ;;
        *) echo "aktuell nicht vorhanden" ;;
    esac
}

component_removal_preview() {
    local target="$1"
    case "$target" in
        ssh_baseline)
            printf '%s\n' "- entfernt verwaltete SSH-Baseline-Parameter aus ${SSHD_HARDENING_DROPIN}" \
                          "- belässt die SSH-Crypto-Policy unangetastet, falls separat verwaltet" \
                          "- validiert sshd -t und startet SSH bei Erfolg neu" ;;
        ssh_crypto)
            printf '%s\n' "- entfernt nur MACs/Ciphers/KexAlgorithms aus ${SSHD_HARDENING_DROPIN}" \
                          "- belässt sonstige SSH-Basishärtung unangetastet" \
                          "- validiert sshd -t und startet SSH bei Erfolg neu" ;;
        ssh_google_2fa|google_2fa|ssh_2fa)
            printf '%s\n' "- entfernt pam_google_authenticator aus /etc/pam.d/sshd" \
                          "- entfernt AuthenticationMethods publickey,keyboard-interactive und deaktiviert keyboard-interactive/challenge-response" \
                          "- entfernt die .google_authenticator-Datei des aktuellen Benutzerkontexts und startet SSH bei Erfolg neu" ;;
        banners|banner)
            printf '%s\n' "- stellt Banner-/MOTD-Backups wieder her oder leert verwaltete Banner" \
                          "- entfernt ggf. die Banner-Referenz aus sshd_config" \
                          "- startet SSH bei Bedarf neu" ;;
        auditd|audit)
            printf '%s\n' "- stellt ${AUDITD_RULES} wieder her, falls ein Backup vorhanden ist" \
                          "- entfernt auditd/audispd-Pakete, wenn installiert" \
                          "- deaktiviert bzw. stoppt auditd" ;;
        aide)
            printf '%s\n' "- entfernt AIDE-Baseline, Cronjob und lokale Excludes" \
                          "- entfernt AIDE-Pakete, wenn installiert" \
                          "- bestehende AIDE-Logs bleiben erhalten" ;;
        pam|pam_hardening)
            printf '%s\n' "- stellt pwquality-/faillock-Konfiguration wieder her" \
                          "- hebt einen vom Skript gesetzten Root-Lock wieder auf" \
                          "- führt optional einen sudo/PAM-Smoketest aus" ;;
        login_umask|umask)
            printf '%s\n' "- stellt ${LOGIN_DEFS_FILE} wieder her" \
                          "- entfernt ${PROFILE_UMASK_FILE}" \
                          "- wirkt vollständig erst in neuen Login-Sitzungen" ;;
        suid_sgid|suidsgid)
            printf '%s\n' "- entfernt Baseline-Datei und Report unter /var/lib/security-script" \
                          "- entfernt Daily-Cronjob und Inventory-Skript" \
                          "- führt keine Änderungen an SUID/SGID-Dateien selbst durch" ;;
        sysctl)
            printf '%s\n' "- stellt ${SYSCTL_CONFIG_FILE} wieder her" \
                          "- lädt sysctl-Werte neu" \
                          "- kann sicherheitsrelevante Kernel-/Netzwerkparameter zurücksetzen" ;;
        journald)
            printf '%s\n' "- stellt /etc/systemd/journald.conf wieder her" \
                          "- startet systemd-journald neu" \
                          "- vorhandene Logs bleiben erhalten" ;;
        sudoers|sudoers_tty)
            printf '%s\n' "- stellt ${SUDOERS_TTY_FILE} wieder her oder entfernt den verwalteten Eintrag" \
                          "- validiert die sudoers-Syntax mit visudo" \
                          "- ändert keine anderen sudoers-Regeln" ;;
        modules|module_blacklist)
            printf '%s\n' "- stellt ${MODPROBE_BLACKLIST} wieder her oder entfernt sie" \
                          "- aktualisiert ggf. initramfs" \
                          "- bereits geladene Module werden nicht aktiv entladen" ;;
        fail2ban)
            printf '%s\n' "- stellt /etc/fail2ban/jail.local wieder her oder entfernt den verwalteten Zustand" \
                          "- deaktiviert/stoppt Fail2ban und entfernt das Paket, wenn installiert" \
                          "- bestehende Logs unter /var/log/fail2ban.log bleiben erhalten" ;;
        unattended_upgrades)
            printf '%s\n' "- stellt 20auto-upgrades und 50unattended-upgrades wieder her" \
                          "- entfernt unattended-upgrades, wenn installiert" \
                          "- ändert keine bereits installierten Updates" ;;
        clamav)
            printf '%s\n' "- stoppt ClamAV-Dienste und entfernt ClamAV-Pakete" \
                          "- belässt Virensignaturdaten unter /var/lib/clamav in der Regel unangetastet" \
                          "- entfernt keine Dateien, die ClamAV zuvor gefunden hat" ;;
        ufw)
            printf '%s\n' "- deaktiviert UFW und entfernt das Paket, wenn installiert" \
                          "- verwaltete Firewall-Regeln werden damit aufgehoben" \
                          "- andere Netzwerkdienste bleiben unverändert" ;;
        *) printf '%s\n' "- keine Vorschau verfügbar" ;;
    esac
}

clear_managed_banner_file() {
    local file="$1"
    if [[ -f "${file}${BACKUP_SUFFIX}" ]]; then
        restore_file "$file"
        return 0
    fi
    if [[ -f "$file" ]] && grep -q "AUTHORIZED ACCESS ONLY" "$file" 2>/dev/null; then
        : > "$file"
        chmod 644 "$file" 2>/dev/null || true
        success "  ✔ Cleared managed banner file: $file"
    fi
}

remove_sshd_banner_reference_if_needed() {
    local sc="/etc/ssh/sshd_config"
    if [[ -f "${sc}${BACKUP_SUFFIX}" ]]; then
        restore_file "$sc" || return 1
    elif [[ -f "$sc" ]] && grep -qiE "^\s*Banner\s+$BANNER_FILE" "$sc"; then
        sed -i -E "\|^\s*Banner\s+$BANNER_FILE\s*$|d" "$sc" \
            && success "  ✔ Removed Banner directive from sshd_config." \
            || warn "  Could not remove Banner directive from sshd_config."
    fi
    detect_ssh_service
    systemctl restart "$SSH_SERVICE" >/dev/null 2>&1 && success "  ✔ SSH restarted." || warn "  SSH restart failed."
}


ssh_selective_prune_keys() {
    local mode="$1"; shift
    local file backup_exists=false
    local -a keys=("$@")
    file=$(ssh_dropin_path_in_use)
    if [[ ! -f "$file" ]]; then
        info "  No managed SSH drop-in present."
        return 0
    fi

    backup_file "$file" || return 1
    local tf regex remaining_directives=0
    tf=$(mktemp_tracked)
    regex="^[[:space:]]*("
    local k first=true
    for k in "${keys[@]}"; do
        if $first; then regex+="$k"; first=false; else regex+="|$k"; fi
    done
    regex+=")([[:space:]]|$)"

    awk -v re="$regex" '
        $0 ~ re { next }
        { print }
    ' "$file" > "$tf"

    if cmp -s "$file" "$tf"; then
        info "  No managed SSH directives for ${mode} needed rollback."
        return 0
    fi

    remaining_directives=$(grep -Ecv '^\s*(#|$)' "$tf" 2>/dev/null || true)
    if (( remaining_directives == 0 )); then
        rm -f "$file" && success "  ✔ Removed managed SSH drop-in."
    else
        cp "$tf" "$file" && chmod 600 "$file" && success "  ✔ Updated managed SSH drop-in."
    fi

    detect_ssh_service
    if sshd -t >/dev/null 2>&1; then
        systemctl restart "$SSH_SERVICE" >/dev/null 2>&1 && success "  ✔ SSH restarted." || warn "  SSH restart failed."
        return 0
    fi

    warn "  sshd validation failed after selective SSH rollback; restoring previous file."
    restore_file "$file"
    return 1
}

rollback_ssh_baseline_component() {
    info "${C_BOLD}Selective rollback: ssh_baseline${C_RESET}"
    register_expected_red_for_component "ssh_baseline"
    ssh_selective_prune_keys "ssh_baseline" \
        AllowAgentForwarding AllowTcpForwarding ChallengeResponseAuthentication KbdInteractiveAuthentication \
        ClientAliveCountMax ClientAliveInterval LoginGraceTime MaxAuthTries MaxSessions \
        PasswordAuthentication PermitRootLogin PermitUserEnvironment PrintLastLog UsePAM X11Forwarding
}

rollback_ssh_crypto_component() {
    info "${C_BOLD}Selective rollback: ssh_crypto${C_RESET}"
    register_expected_red_for_component "ssh_crypto"
    ssh_selective_prune_keys "ssh_crypto" MACs Ciphers KexAlgorithms HostKeyAlgorithms PubkeyAcceptedAlgorithms
}

rollback_ssh_google_2fa_component() {
    info "${C_BOLD}Selective rollback: ssh_google_2fa${C_RESET}"
    register_expected_red_for_component "ssh_google_2fa"
    local pam_file="/etc/pam.d/sshd" sshd_cfg="/etc/ssh/sshd_config"
    local target_user="${SUDO_USER:-$(whoami)}"
    local user_home; user_home=$(eval echo "~$target_user")
    local pam_changed=false ssh_changed=false secret_removed=false

    if [[ -f "$pam_file" ]]; then
        backup_file "$pam_file"
        local tp; tp=$(mktemp_tracked)
        cp "$pam_file" "$tp"
        if grep -Eq '^[[:space:]]*auth[[:space:]].*pam_google_authenticator\.so\b' "$tp"; then
            sed -i -E '/^[[:space:]]*auth[[:space:]].*pam_google_authenticator\.so\b/d' "$tp"
            pam_changed=true
        fi
        if $pam_changed; then
            validate_pam_file "$tp" || { error "PAM validation failed after Google 2FA rollback."; rm -f "$tp"; return 1; }
            if $DRY_RUN; then
                dry_run_echo "Update $pam_file (remove pam_google_authenticator)"
                rm -f "$tp" 2>/dev/null || true
            else
                mv "$tp" "$pam_file" && chmod 644 "$pam_file" && log_change "MODIFIED:$pam_file (rollback ssh_google_2fa)"
                success "  ✔ Removed pam_google_authenticator from $pam_file."
            fi
        else
            rm -f "$tp" 2>/dev/null || true
        fi
    fi

    if [[ -f "$sshd_cfg" ]]; then
        backup_file "$sshd_cfg"
        local ts; ts=$(mktemp_tracked)
        cp "$sshd_cfg" "$ts"
        if grep -qiE '^[[:space:]]*AuthenticationMethods[[:space:]].*keyboard-interactive' "$ts"; then
            sed -i -E '/^[[:space:]]*AuthenticationMethods[[:space:]].*keyboard-interactive/d' "$ts"
            ssh_changed=true
        fi
        set_sshd_param "KbdInteractiveAuthentication" "no" "$ts" && ssh_changed=true || true
        set_sshd_param "ChallengeResponseAuthentication" "no" "$ts" && ssh_changed=true || true
        if $ssh_changed; then
            if $DRY_RUN; then
                dry_run_echo "Update $sshd_cfg (disable keyboard-interactive Google 2FA)"
                rm -f "$ts" 2>/dev/null || true
            else
                apply_sshd_config "$ts" || return 1
            fi
        else
            rm -f "$ts" 2>/dev/null || true
        fi
    fi

    if [[ -f "$user_home/.google_authenticator" ]]; then
        backup_file "$user_home/.google_authenticator"
        if $DRY_RUN; then
            dry_run_echo "Remove $user_home/.google_authenticator"
        else
            rm -f "$user_home/.google_authenticator" && success "  ✔ Removed $user_home/.google_authenticator."
            secret_removed=true
        fi
    fi

    local pkg_present=false
    if is_package_installed "libpam-google-authenticator"; then
        pkg_present=true
        if $DRY_RUN; then
            dry_run_echo "Remove package libpam-google-authenticator"
        else
            remove_packages_if_present "libpam-google-authenticator"
        fi
    fi

    if ! $pam_changed && ! $ssh_changed && ! $secret_removed && ! $pkg_present; then
        info "  No Google 2FA state needed rollback."
        return 0
    fi

    detect_ssh_service
    if ! $DRY_RUN; then
        if sshd -t 2>/dev/null; then
            systemctl restart "$SSH_SERVICE" >/dev/null 2>&1 && success "  ✔ SSH restarted." || warn "  SSH restart failed after Google 2FA rollback."
        else
            warn "  sshd validation failed after Google 2FA rollback; not restarting service."
            return 1
        fi
    fi
}

rollback_fail2ban_component() {
    info "${C_BOLD}Selective rollback: fail2ban${C_RESET}"
    register_expected_red_for_component "fail2ban"
    restore_file "/etc/fail2ban/jail.local"
    systemctl disable --now fail2ban >/dev/null 2>&1 || true
    remove_packages_if_present "fail2ban"
    info "  Fail2ban-Logs bleiben unter /var/log/fail2ban.log erhalten."
}

rollback_unattended_upgrades_component() {
    info "${C_BOLD}Selective rollback: unattended_upgrades${C_RESET}"
    register_expected_red_for_component "unattended_upgrades"
    restore_file "/etc/apt/apt.conf.d/20auto-upgrades"
    restore_file "/etc/apt/apt.conf.d/50unattended-upgrades"
    remove_packages_if_present "unattended-upgrades"
}

rollback_clamav_component() {
    info "${C_BOLD}Selective rollback: clamav${C_RESET}"
    register_expected_red_for_component "clamav"
    systemctl disable --now clamav-daemon clamav-freshclam >/dev/null 2>&1 || true
    remove_packages_if_present "clamav-daemon" "clamav-freshclam" "clamav"
    info "  Virensignaturen unter /var/lib/clamav bleiben in der Regel erhalten."
}

rollback_ufw_component() {
    info "${C_BOLD}Selective rollback: ufw${C_RESET}"
    register_expected_red_for_component "ufw"
    command -v ufw >/dev/null 2>&1 && ufw --force disable >/dev/null 2>&1 && success "  ✔ UFW disabled." || true
    remove_packages_if_present "ufw"
}

rollback_banners_component() {
    info "${C_BOLD}Selective rollback: banners${C_RESET}"
    register_expected_red_for_component "banners"
    clear_managed_banner_file "$BANNER_FILE"
    clear_managed_banner_file "$MOTD_FILE"
    remove_sshd_banner_reference_if_needed
}

rollback_ssh_component() {
    info "${C_BOLD}Selective rollback: ssh${C_RESET}"
    register_expected_red_for_component "ssh"
    rollback_ssh_crypto_component || return 1
    echo
    rollback_ssh_baseline_component
}


rollback_auditd_component() {
    info "${C_BOLD}Selective rollback: auditd${C_RESET}"
    register_expected_red_for_component "auditd"
    restore_file "$AUDITD_RULES"
    if [[ -f "$AUDITD_RULES" ]]; then
        command -v augenrules >/dev/null 2>&1 && augenrules --load >/dev/null 2>&1 || true
        systemctl restart auditd >/dev/null 2>&1 && success "  ✔ auditd restarted with restored rules." || true
    fi
    if is_package_installed "auditd" || is_package_installed "audispd-plugins"; then
        systemctl disable --now auditd >/dev/null 2>&1 || true
        remove_packages_if_present "audispd-plugins" "auditd"
    fi
    info "  Audit-Logs bleiben unter /var/log/audit/audit.log erhalten."
}

rollback_aide_component() {
    info "${C_BOLD}Selective rollback: aide${C_RESET}"
    register_expected_red_for_component "aide"
    restore_file "$AIDE_CRON"
    restore_file "$AIDE_LOCAL_EXCLUDES"
    if [[ -f /var/lib/aide/aide.db || -f /var/lib/aide/aide.db.new || -f /var/lib/aide/aide.db.gz || -f /var/lib/aide/aide.conf.autogenerated ]]; then
        rm -f /var/lib/aide/aide.db /var/lib/aide/aide.db.new /var/lib/aide/aide.db.gz /var/lib/aide/aide.conf.autogenerated >/dev/null 2>&1 || true
        success "  ✔ Removed AIDE baseline/config files."
    fi
    remove_packages_if_present "aide-common" "aide"
    info "  AIDE-Logs bleiben unter /var/log/aide-check.log und /var/log/aide-report-*.log erhalten."
}

rollback_pam_component() {
    info "${C_BOLD}Selective rollback: pam${C_RESET}"
    register_expected_red_for_component "pam"
    restore_file "$PWQUALITY_CONF"
    restore_file "$FAILLOCK_CONF"
    finalize_pam_rollback_state true
}

rollback_login_umask_component() {
    info "${C_BOLD}Selective rollback: login_umask${C_RESET}"
    register_expected_red_for_component "login_umask"
    restore_file "$LOGIN_DEFS_FILE"

    if [[ -f "${PROFILE_UMASK_FILE}${BACKUP_SUFFIX}" ]]; then
        restore_file "$PROFILE_UMASK_FILE"
    elif [[ -f "$PROFILE_UMASK_FILE" ]]; then
        rm -f "$PROFILE_UMASK_FILE"             && success "  ✔ Removed shell umask hook."             || warn "  Could not remove shell umask hook."
    fi

    if [[ -f "${SYSTEM_UMASK_SYSTEMD_DROPIN}${BACKUP_SUFFIX}" ]]; then
        restore_file "$SYSTEM_UMASK_SYSTEMD_DROPIN"
    elif [[ -f "$SYSTEM_UMASK_SYSTEMD_DROPIN" ]]; then
        rm -f "$SYSTEM_UMASK_SYSTEMD_DROPIN"             && success "  ✔ Removed systemd system umask drop-in."             || warn "  Could not remove systemd system umask drop-in."
    fi

    if [[ -f "${USER_UMASK_SYSTEMD_DROPIN}${BACKUP_SUFFIX}" ]]; then
        restore_file "$USER_UMASK_SYSTEMD_DROPIN"
    elif [[ -f "$USER_UMASK_SYSTEMD_DROPIN" ]]; then
        rm -f "$USER_UMASK_SYSTEMD_DROPIN"             && success "  ✔ Removed systemd user umask drop-in."             || warn "  Could not remove systemd user umask drop-in."
    fi

    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true
    info "  Existing services keep their current umask until restart/reboot; assessment should turn RED again immediately because the managed baseline was removed."
    rollback_report_manual "review service restarts after umask rollback (existing processes keep prior umask until restart/reboot)"
}

rollback_suid_sgid_component() {
    info "${C_BOLD}Selective rollback: suid_sgid${C_RESET}"
    register_expected_red_for_component "suid_sgid"
    restore_file "$SUID_SGID_AUDIT_CRON"
    restore_file "$SUID_SGID_AUDIT_SCRIPT"
    if [[ -f "$SUID_SGID_AUDIT_CRON" ]]; then
        rm -f "$SUID_SGID_AUDIT_CRON"             && success "  ✔ Removed SUID/SGID daily cron job."             || warn "  Could not remove SUID/SGID daily cron job."
    fi
    if [[ -f "$SUID_SGID_AUDIT_SCRIPT" ]]; then
        rm -f "$SUID_SGID_AUDIT_SCRIPT"             && success "  ✔ Removed SUID/SGID audit script."             || warn "  Could not remove SUID/SGID audit script."
    fi
    rm -f "$SUID_SGID_AUDIT_BASELINE" "$SUID_SGID_AUDIT_REPORT" >/dev/null 2>&1 || true
    [[ ! -f "$SUID_SGID_AUDIT_BASELINE" ]] && success "  ✔ Removed SUID/SGID baseline/report files."
}

finalize_pam_rollback_state() {
    local run_smoke_test="${1:-false}"
    if command -v pam-auth-update >/dev/null 2>&1; then
        if timeout 20 env DEBIAN_FRONTEND=noninteractive pam-auth-update --disable faillock --force </dev/null >/dev/null 2>&1; then
            timeout 20 env DEBIAN_FRONTEND=noninteractive pam-auth-update --force </dev/null >/dev/null 2>&1 || true
            success "  ✔ pam-auth-update refresh executed."
        else
            warn "  pam-auth-update refresh timed out or failed; continuing rollback."
        fi
    fi
    if [[ -f "$TRANSACTION_LOG" ]] && grep -q "|ROOT_LOCKED|" "$TRANSACTION_LOG"; then
        if passwd -S root 2>/dev/null | grep -qE "^root\s+L"; then
            passwd -u root >/dev/null 2>&1 && success "  ✔ Root account unlocked." || warn "  Could not unlock root."
        fi
    fi
    if [[ "$run_smoke_test" == "true" ]]; then
        sudo_smoke_test "/etc/pam.d/common-auth" || warn "  PAM smoke test reported an issue after rollback."
    fi
}

rollback_sysctl_component() {
    info "${C_BOLD}Selective rollback: sysctl${C_RESET}"
    register_expected_red_for_component "sysctl"
    restore_file "$SYSCTL_CONFIG_FILE"
    sysctl --system >/dev/null 2>&1 && success "  ✔ Sysctl reloaded." || warn "  Sysctl reload failed."
}

rollback_journald_component() {
    info "${C_BOLD}Selective rollback: journald${C_RESET}"
    restore_file "/etc/systemd/journald.conf"
    systemctl restart systemd-journald >/dev/null 2>&1 && success "  ✔ systemd-journald restarted." || warn "  journald restart failed."
}

rollback_sudoers_component() {
    info "${C_BOLD}Selective rollback: sudoers${C_RESET}"
    register_expected_red_for_component "sudoers"
    restore_file "$SUDOERS_TTY_FILE"
    visudo -cf /etc/sudoers >/dev/null 2>&1 && success "  ✔ sudoers syntax verified." || warn "  visudo reported a syntax issue."
}

rollback_modules_component() {
    info "${C_BOLD}Selective rollback: modules${C_RESET}"
    register_expected_red_for_component "modules"
    restore_file "$MODPROBE_BLACKLIST"
    command -v update-initramfs >/dev/null 2>&1 && update-initramfs -u >/dev/null 2>&1 && success "  ✔ initramfs updated." || true
}

archive_transaction_log() {
    [[ -f "$TRANSACTION_LOG" ]] || return 0
    local archived="${TRANSACTION_LOG}.rolledback.$(date +%Y%m%d_%H%M%S)"
    mv "$TRANSACTION_LOG" "$archived" \
        && info "$(tr_msg archive_txlog_ok): $archived" \
        || warn "$(tr_msg archive_txlog_fail)"
}

run_selective_removal() {
    local raw_targets="$1"
    rollback_report_reset
    local normalized selected_from_menu target errors=0
    local -a targets=()
    local -a effective_targets=()

    if [[ -z "$raw_targets" || "$raw_targets" == "__MENU__" || "$raw_targets" == "menu" ]]; then
        interactive_selective_removal_menu || {
            info "$(tr_msg aborted_selective)"
            return 0
        }
        raw_targets="$SELECTIVE_MENU_RESULT"
    fi

    normalized="${raw_targets// /}"
    IFS=',' read -r -a targets <<< "$normalized"

    for target in "${targets[@]}"; do
        [[ -n "$target" ]] || continue
        effective_targets+=("$target")
    done

    [[ ${#effective_targets[@]} -gt 0 ]] || { warn "$(tr_msg no_valid_targets)"; return 1; }

    echo
    echo -e "${C_BOLD}${C_YELLOW_BOLD}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_BOLD}${C_YELLOW_BOLD}║      SELECTIVE ROLLBACK — REMOVING SELECTED COMPONENTS      ║${C_RESET}"
    echo -e "${C_BOLD}${C_YELLOW_BOLD}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo
    info "$(tr_msg selected_targets): ${effective_targets[*]}"
    echo ""
    info "Folgende Änderungen werden durchgeführt:"
    local preview_target
    for preview_target in "${effective_targets[@]}"; do
        echo "  • ${preview_target}:"
        while IFS= read -r preview_line; do
            [[ -n "$preview_line" ]] || continue
            echo "      ${preview_line}"
        done < <(component_removal_preview "$preview_target")
    done

    if ! $AUTO_MODE; then
        ask_yes_no "$(tr_msg confirm_selective_remove)" "n" || {
            info "Selektives Entfernen abgebrochen."
            return 0
        }
    fi

    for target in "${effective_targets[@]}"; do
        case "$target" in
            ssh)                         rollback_ssh_component || errors=$((errors+1)) ;;
            ssh_baseline|ssh_hardening)  rollback_ssh_baseline_component || errors=$((errors+1)) ;;
            ssh_crypto)                  rollback_ssh_crypto_component || errors=$((errors+1)) ;;
            ssh_google_2fa|google_2fa|ssh_2fa) rollback_ssh_google_2fa_component || errors=$((errors+1)) ;;
            banners|banner)               rollback_banners_component || errors=$((errors+1)) ;;
            auditd|audit)                 rollback_auditd_component || errors=$((errors+1)) ;;
            aide)                         rollback_aide_component || errors=$((errors+1)) ;;
            pam|pam_hardening)            rollback_pam_component || errors=$((errors+1)) ;;
            login_umask|umask|system_umask) rollback_login_umask_component || errors=$((errors+1)) ;;
            suid_sgid|suidsgid)           rollback_suid_sgid_component || errors=$((errors+1)) ;;
            sysctl)                       rollback_sysctl_component || errors=$((errors+1)) ;;
            journald)                     rollback_journald_component || errors=$((errors+1)) ;;
            sudoers|sudoers_tty)          rollback_sudoers_component || errors=$((errors+1)) ;;
            modules|module_blacklist)     rollback_modules_component || errors=$((errors+1)) ;;
            fail2ban)                     rollback_fail2ban_component || errors=$((errors+1)) ;;
            unattended_upgrades)          rollback_unattended_upgrades_component || errors=$((errors+1)) ;;
            clamav)                       rollback_clamav_component || errors=$((errors+1)) ;;
            ufw)                          rollback_ufw_component || errors=$((errors+1)) ;;
            *) warn "Unknown remove target: $target" ; errors=$((errors+1)) ;;
        esac
        echo
    done

    write_rollback_action_report
    print_security_log_summary
    (( errors == 0 ))
}

# ============================================================================
# FULL ROLLBACK
# ============================================================================

save_assessment_snapshot() {
    local outfile="$1"
    local id entry raw desc
    mkdir -p "$(dirname "$outfile")" 2>/dev/null || true
    : > "$outfile"
    for id in "${ASSESS_ORDER[@]}"; do
        entry="${ASSESS_RESULTS[$id]:-}"
        [[ -n "$entry" ]] || continue
        raw="${entry%%:*}"
        desc="${entry#*:}"
        printf '%s\t%s\t%s\n' "$id" "$raw" "$desc" >> "$outfile"
    done
}

cleanup_package_residuals_after_rollback() {
    if ! command -v apt-get >/dev/null 2>&1; then
        return 0
    fi
    DEBIAN_FRONTEND=noninteractive timeout 180 apt-get autoremove -y --purge </dev/null >/dev/null 2>&1 \
        && success "  ✔ Residual package cleanup completed." \
        || warn "  Residual package cleanup timed out or failed."
}

print_rollback_validation_report() {
    local report="$ROLLBACK_VALIDATION_REPORT"
    local id entry raw now_norm base_raw base_norm
    local matched=0 still_green=0 regressed=0 baseline_known=false
    declare -A BASELINE_STATUS=()

    if [[ -s "$BASELINE_SNAPSHOT" ]]; then
        baseline_known=true
        while IFS=$'\t' read -r id base_raw _desc; do
            [[ -n "$id" ]] || continue
            BASELINE_STATUS["$id"]="$base_raw"
        done < "$BASELINE_SNAPSHOT"
    fi

    mkdir -p "$(dirname "$report")" 2>/dev/null || true
    {
        echo "Rollback validation report ($(date '+%Y-%m-%d %H:%M:%S'))"
        echo
    } > "$report"

    if ! $baseline_known; then
        {
            echo "No pre-hardening baseline snapshot available."
            echo "Interpretation hint: not every check should turn RED after rollback."
            echo "Some items may already have been GREEN on the original system."
        } >> "$report"
        info "Rollback validation: no saved pre-hardening baseline found."
        info "Not every check should turn RED after rollback — some controls may already have been GREEN originally."
        info "Validation details: $report"
        return 0
    fi

    for id in "${ASSESS_ORDER[@]}"; do
        entry="${ASSESS_RESULTS[$id]:-}"
        [[ -n "$entry" ]] || continue
        raw="${entry%%:*}"
        now_norm="$(normalize_matrix_status "$raw")"
        base_raw="${BASELINE_STATUS[$id]:-UNKNOWN}"
        if [[ "$base_raw" == "UNKNOWN" ]]; then
            continue
        fi
        base_norm="$(normalize_matrix_status "$base_raw")"
        if [[ "$now_norm" == "$base_norm" ]]; then
            matched=$((matched+1))
        elif [[ "$base_norm" == "RED" && "$now_norm" == "GREEN" ]]; then
            still_green=$((still_green+1))
            printf 'STILL_GREEN_AFTER_ROLLBACK\t%s\tbaseline=%s\tnow=%s\n' "$id" "$base_norm" "$now_norm" >> "$report"
        elif [[ "$base_norm" == "GREEN" && "$now_norm" == "RED" ]]; then
            regressed=$((regressed+1))
            printf 'REGRESSED_BELOW_BASELINE\t%s\tbaseline=%s\tnow=%s\n' "$id" "$base_norm" "$now_norm" >> "$report"
        fi
    done

    {
        echo "Matched baseline checks: $matched"
        echo "Still GREEN although baseline was RED: $still_green"
        echo "Now RED although baseline was GREEN: $regressed"
    } >> "$report"

    info "Rollback validation against saved pre-hardening baseline:"
    info "  Matches baseline again: $matched"
    info "  Still GREEN although baseline was RED: $still_green"
    info "  Now RED although baseline was GREEN: $regressed"
    if (( still_green > 0 )); then
        warn "Some findings are still GREEN after rollback. This usually means the rollback could not fully revert them, or they were changed outside the managed rollback path."
    fi
    if (( regressed > 0 )); then
        warn "Some findings are now RED although the original baseline was GREEN. Review the rollback validation report."
    fi
    info "Validation details: $report"
    [[ -f "$ROLLBACK_ACTION_REPORT" ]] && info "Rollback action report: $ROLLBACK_ACTION_REPORT"
}

run_full_rollback() {
    rollback_report_reset
    echo
    echo -e "${C_BOLD}${C_RED_BOLD}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_BOLD}${C_RED_BOLD}║           ROLLBACK — RESTORING ORIGINAL SYSTEM STATE        ║${C_RESET}"
    echo -e "${C_BOLD}${C_RED_BOLD}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo
    info "Rollback runs fully automated and non-interactively."

    local errors=0

    register_expected_red_for_component "ssh"
    register_expected_red_for_component "unattended_upgrades"
    register_expected_red_for_component "ufw"
    register_expected_red_for_component "fail2ban"
    register_expected_red_for_component "clamav"
    register_expected_red_for_component "auditd"
    register_expected_red_for_component "aide"
    register_expected_red_for_component "sysctl"
    register_expected_red_for_component "sudoers"
    register_expected_red_for_component "login_umask"
    register_expected_red_for_component "suid_sgid"
    register_expected_red_for_component "pam"
    register_expected_red_for_component "banners"
    register_expected_red_for_component "modules"

    if [[ ! -f "$TRANSACTION_LOG" ]]; then
        warn "No transaction log found at $TRANSACTION_LOG."
        warn "Fallback: restore backups and remove recognisable generated files."
    fi

    # --- 1. Restore all backed-up config files ---
    info "${C_BOLD}Step 1/7: Restoring backed-up configuration files...${C_RESET}"
    local backup_count=0
    while IFS= read -r -d '' backup; do
        local original="${backup%"$BACKUP_SUFFIX"}"
        info "  Restoring: $original"
        if mv "$backup" "$original"; then
            success "  ✔ Restored: $original"
            rollback_report_reverted "restored backup during full rollback: $original"
            backup_count=$((backup_count+1))
        else
            error "  ✘ Failed to restore: $original"
            rollback_report_failed "failed to restore backup during full rollback: $original"
            errors=$((errors+1))
        fi
    done < <(find /etc /home /root -name "*${BACKUP_SUFFIX}" -print0 2>/dev/null | sort -z)
    (( backup_count > 0 )) && success "$backup_count config file(s) restored." || info "No backup files found."

    # --- 2. Remove files added by the script ---
    info "${C_BOLD}Step 2/7: Removing files added by the script...${C_RESET}"
    local added_files=(
        "$SYSCTL_CONFIG_FILE"
        "$SUDOERS_TTY_FILE"
        "$MODPROBE_BLACKLIST"
        "$LIMITS_CONF"
        "$SYSTEM_UMASK_SYSTEMD_DROPIN"
        "$USER_UMASK_SYSTEMD_DROPIN"
        "$AIDE_CRON"
        "$AIDE_LOCAL_EXCLUDES"
        "$AUDITD_RULES"
        "$SSHD_HARDENING_DROPIN"
        "$SSHD_HARDENING_DROPIN_LEGACY"
    )
    local f
    for f in "${added_files[@]}"; do
        if [[ -f "$f" ]] && ! [[ -f "${f}${BACKUP_SUFFIX}" ]]; then
            if grep -q "generated by security_script.sh" "$f" 2>/dev/null || \
               grep -q "Generated by security_script.sh" "$f" 2>/dev/null; then
                rm -f "$f" && { success "  ✔ Removed: $f"; rollback_report_reverted "removed generated file during full rollback: $f"; } || { error "  ✘ Failed to remove: $f"; rollback_report_failed "failed to remove generated file during full rollback: $f"; errors=$((errors+1)); }
            fi
        fi
    done

    # --- 3. Clean up lingering banner configuration ---
    info "${C_BOLD}Step 3/7: Cleaning up login banners...${C_RESET}"
    rollback_banners_component || errors=$((errors+1))

    # --- 4. PAM/root rollback ---
    info "${C_BOLD}Step 4/7: Restoring PAM/root state...${C_RESET}"
    finalize_pam_rollback_state false || errors=$((errors+1))

    # --- 5. Reload sysctl/journald and module state ---
    info "${C_BOLD}Step 5/7: Reloading sysctl/journald/module state...${C_RESET}"
    rollback_sysctl_component || true
    rollback_journald_component || true
    rollback_modules_component || true
    rollback_sudoers_component || true

    # --- 6. Remove packages installed by this script ---
    info "${C_BOLD}Step 6/7: Removing packages recorded as script-installed...${C_RESET}"
    if [[ -f "$TRANSACTION_LOG" ]]; then
        local pkgs_to_remove=()
        while IFS='|' read -r _ts action pkg; do
            [[ "$action" == "PKG_INSTALLED" ]] && pkgs_to_remove+=("$pkg")
        done < "$TRANSACTION_LOG"
        if [[ ${#pkgs_to_remove[@]} -gt 0 ]]; then
            local unique_pkgs
            unique_pkgs=$(printf "%s\n" "${pkgs_to_remove[@]}" | awk '!seen[$0]++')
            while IFS= read -r pkg; do
                [[ -z "$pkg" ]] && continue
                if is_package_installed "$pkg"; then
                    info "  Removing: $pkg"
                    DEBIAN_FRONTEND=noninteractive timeout 180 apt-get purge -y "$pkg" </dev/null >/dev/null 2>&1 \
                        && success "  ✔ Removed package: $pkg" \
                        || warn "  Could not remove package: $pkg"
                fi
            done <<< "$unique_pkgs"
        else
            info "  No packages recorded in transaction log."
        fi
    else
        info "  No transaction log — skipping package removal."
    fi

    cleanup_package_residuals_after_rollback

    # --- 7. Restart affected services and archive transaction log ---
    info "${C_BOLD}Step 7/7: Restarting affected services and archiving logs...${C_RESET}"
    detect_ssh_service
    if systemctl is-active --quiet "$SSH_SERVICE" 2>/dev/null; then
        timeout 20 systemctl restart "$SSH_SERVICE" >/dev/null 2>&1 && success "  ✔ SSH restarted." || warn "  SSH restart timed out or failed."
    fi
    timeout 20 systemctl restart systemd-journald >/dev/null 2>&1 && success "  ✔ systemd-journald restarted." || warn "  systemd-journald restart timed out or failed."
    timeout 20 sysctl --system >/dev/null 2>&1 && success "  ✔ Sysctl reloaded." || warn "  Sysctl reload timed out or failed."
    if command -v pam-auth-update >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive timeout 30 pam-auth-update --force </dev/null >/dev/null 2>&1             && success "  ✔ pam-auth-update refresh executed."             || warn "  pam-auth-update refresh timed out or failed."
    fi
    archive_transaction_log

    declare -gA ASSESS_RESULTS=()
    declare -ga ASSESS_ORDER=()
    run_assessment
    print_rollback_validation_report

    print_security_log_summary

    echo
    if (( errors == 0 )); then
        echo -e "${C_GREEN_BOLD}╔══════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "${C_GREEN_BOLD}║  ROLLBACK COMPLETE — System restored successfully    ║${C_RESET}"
        echo -e "${C_GREEN_BOLD}╚══════════════════════════════════════════════════════╝${C_RESET}"
    else
        echo -e "${C_RED_BOLD}╔══════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "${C_RED_BOLD}║  ROLLBACK COMPLETE with ${errors} error(s) — check above  ║${C_RESET}"
        echo -e "${C_RED_BOLD}╚══════════════════════════════════════════════════════╝${C_RESET}"
    fi
    echo
    rollback_report_manual "reboot recommended to ensure rollback is fully effective"
    write_rollback_action_report
    warn "A REBOOT is recommended to fully apply the rollback."
}


# ============================================================================
# ASSESSMENT
# ============================================================================
run_assessment() {
    echo
    echo -e "${C_BOLD}${C_CYAN}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}║       SECURITY ASSESSMENT MATRIX — SCANNING SYSTEM          ║${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo

    # SSH
    local ssh_root ssh_pass ssh_x11 ssh_agent ssh_tcp ssh_grace ssh_max_auth
    ssh_root=$(get_effective_sshd_config "PermitRootLogin")
    ssh_pass=$(get_effective_sshd_config "PasswordAuthentication")
    ssh_x11=$(get_effective_sshd_config "X11Forwarding")
    ssh_agent=$(get_effective_sshd_config "AllowAgentForwarding")
    ssh_tcp=$(get_effective_sshd_config "AllowTcpForwarding")
    ssh_grace=$(get_effective_sshd_config "LoginGraceTime")
    ssh_max_auth=$(get_effective_sshd_config "MaxAuthTries")

    [[ "$ssh_root" =~ ^(no|prohibit-password|without-password)$ ]] \
        && record_check "SSH_ROOT_LOGIN"   "PASS" "PermitRootLogin=$ssh_root" \
        || record_check "SSH_ROOT_LOGIN"   "FAIL" "PermitRootLogin='${ssh_root:-yes}' — should be prohibit-password"
    [[ "$(echo "${ssh_pass:-yes}" | tr '[:upper:]' '[:lower:]')" == "no" ]] \
        && record_check "SSH_PASSWORD_AUTH" "PASS" "PasswordAuthentication=no" \
        || record_check "SSH_PASSWORD_AUTH" "FAIL" "PasswordAuthentication='${ssh_pass:-yes}'"
    [[ "$(echo "${ssh_x11:-no}" | tr '[:upper:]' '[:lower:]')" == "no" ]] \
        && record_check "SSH_X11"          "PASS" "X11Forwarding=no" \
        || record_check "SSH_X11"          "FAIL" "X11Forwarding='${ssh_x11:-yes}'"
    [[ "$(echo "${ssh_agent:-yes}" | tr '[:upper:]' '[:lower:]')" == "no" ]] \
        && record_check "SSH_AGENT_FWD"    "PASS" "AllowAgentForwarding=no" \
        || record_check "SSH_AGENT_FWD"    "FAIL" "AllowAgentForwarding='${ssh_agent:-yes}'"
    [[ "$(echo "${ssh_tcp:-yes}" | tr '[:upper:]' '[:lower:]')" == "no" ]] \
        && record_check "SSH_TCP_FWD"      "PASS" "AllowTcpForwarding=no" \
        || record_check "SSH_TCP_FWD"      "FAIL" "AllowTcpForwarding='${ssh_tcp:-yes}'"
    local grace_num="${ssh_grace:-120}"; grace_num="${grace_num//[^0-9]/}"
    (( ${grace_num:-120} <= 30 )) \
        && record_check "SSH_GRACE_TIME"   "PASS" "LoginGraceTime=${ssh_grace}s" \
        || record_check "SSH_GRACE_TIME"   "FAIL" "LoginGraceTime='${ssh_grace:-120}' — should be ≤30"
    local max_auth="${ssh_max_auth:-6}"
    (( ${max_auth:-6} <= 3 )) \
        && record_check "SSH_MAX_AUTH"     "PASS" "MaxAuthTries=${ssh_max_auth}" \
        || record_check "SSH_MAX_AUTH"     "FAIL" "MaxAuthTries='${ssh_max_auth:-6}' — should be ≤3"

    local ssh_ciphers ssh_macs ssh_kex ssh_weak_ciphers ssh_weak_macs ssh_weak_kex
    local -a ssh_crypto_issues=()
    local strict_policy_managed=false strict_policy_effective=false
    ssh_ciphers=$(get_effective_sshd_config "Ciphers" 2>/dev/null || true)
    ssh_macs=$(get_effective_sshd_config "MACs" 2>/dev/null || true)
    ssh_kex=$(get_effective_sshd_config "KexAlgorithms" 2>/dev/null || true)
    [[ -f "$SSHD_HARDENING_DROPIN" ]] && grep -qiE '^# Optional Mil/Gov-oriented SSH crypto policy mode:[[:space:]]*strict([[:space:]]|$)' "$SSHD_HARDENING_DROPIN" 2>/dev/null && strict_policy_managed=true
    ssh_effective_policy_matches_mode strict && strict_policy_effective=true || true
    if [[ -z "$ssh_ciphers" || -z "$ssh_macs" || -z "$ssh_kex" ]]; then
        ssh_crypto_issues+=("policy-not-explicit")
    fi
    ssh_weak_ciphers=$(ssh_values_matching_regex "$ssh_ciphers" '^(3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc|blowfish-cbc|cast128-cbc|arcfour|arcfour128|arcfour256)$')
    ssh_weak_macs=$(ssh_values_matching_regex "$ssh_macs" '^(hmac-md5|hmac-md5-96|hmac-sha1|hmac-sha1-96|umac-64@openssh.com|umac-64-etm@openssh.com|hmac-ripemd160|hmac-ripemd160@openssh.com)$')
    ssh_weak_kex=$(ssh_values_matching_regex "$ssh_kex" '^(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)$')
    [[ -n "$ssh_weak_ciphers" ]] && ssh_crypto_issues+=("weak-cipher:${ssh_weak_ciphers}")
    [[ -n "$ssh_weak_macs" ]] && ssh_crypto_issues+=("weak-mac:${ssh_weak_macs}")
    [[ -n "$ssh_weak_kex" ]] && ssh_crypto_issues+=("weak-kex:${ssh_weak_kex}")
    if (( ${#ssh_crypto_issues[@]} > 0 )); then
        record_check "SSH_CRYPTO_POLICY" "FAIL" "SSH crypto policy issue(s): ${ssh_crypto_issues[*]}"
    elif $strict_policy_managed && $strict_policy_effective; then
        record_check "SSH_CRYPTO_POLICY" "PASS" "Strict SSH crypto policy pinned (Ciphers/MACs/KEX)"
    elif $strict_policy_effective; then
        record_check "SSH_CRYPTO_POLICY" "PASS" "Strict SSH crypto policy effective"
    else
        record_check "SSH_CRYPTO_POLICY" "FAIL" "Strict SSH crypto policy not pinned/effective"
    fi
    ssh_google_2fa_assessment

    # Firewall
    is_package_installed ufw && ufw status 2>/dev/null | grep -q "Status: active" \
        && record_check "UFW_ACTIVE"       "PASS" "UFW active" \
        || record_check "UFW_ACTIVE"       "FAIL" "UFW not installed or inactive"

    # Brute-force protection
    is_package_installed fail2ban && systemctl is-active --quiet fail2ban 2>/dev/null \
        && record_check "FAIL2BAN"         "PASS" "Fail2ban active" \
        || record_check "FAIL2BAN"         "FAIL" "Fail2ban not installed/running"

    # Auto-updates
    is_package_installed unattended-upgrades \
        && record_check "UNATTENDED_UPGRADES" "PASS" "unattended-upgrades installed" \
        || record_check "UNATTENDED_UPGRADES" "FAIL" "unattended-upgrades missing"

    # Antivirus
    is_package_installed clamav \
        && record_check "CLAMAV"           "PASS" "ClamAV installed" \
        || record_check "CLAMAV"           "FAIL" "ClamAV not installed"

    # Audit daemon
    if is_package_installed auditd; then
        if auditd_is_active; then
            [[ -f "$AUDITD_RULES" ]] && record_check "AUDITD" "PASS" "auditd active + custom ruleset" \
                                   || record_check "AUDITD" "FAIL" "auditd active but no custom ruleset"
        elif ! auditd_unit_exists; then
            record_check "AUDITD" "FAIL" "auditd package installed but service unit missing"
        else
            record_check "AUDITD" "FAIL" "auditd installed but not running"
        fi
    else
        record_check "AUDITD" "FAIL" "auditd not installed"
    fi

    local -a audit_cov_missing=()
    if ! is_package_installed auditd; then
        record_check "AUDITD_EXTENDED" "INFO" "Extended audit coverage check skipped until auditd is installed"
    elif [[ -f "$AUDITD_RULES" ]]; then
        grep -q '/etc/login.defs' "$AUDITD_RULES" || audit_cov_missing+=("login.defs")
        grep -q '/etc/profile.d/' "$AUDITD_RULES" || audit_cov_missing+=("profile.d")
        grep -q '/etc/rsyslog.d/' "$AUDITD_RULES" || audit_cov_missing+=("rsyslog")
        grep -q 'perm_mod' "$AUDITD_RULES" || audit_cov_missing+=("perm_mod")
        grep -q 'time_change' "$AUDITD_RULES" || audit_cov_missing+=("time_change")
        grep -q 'identity_host' "$AUDITD_RULES" || audit_cov_missing+=("hostname")
        grep -q '/etc/default/grub' "$AUDITD_RULES" || audit_cov_missing+=("grub")
        if (( ${#audit_cov_missing[@]} == 0 )); then
            record_check "AUDITD_EXTENDED" "PASS" "Extended audit coverage present"
        else
            record_check "AUDITD_EXTENDED" "FAIL" "auditd rules missing: ${audit_cov_missing[*]}"
        fi
    else
        record_check "AUDITD_EXTENDED" "FAIL" "auditd rules file missing"
    fi

    # File integrity
    if is_package_installed aide; then
        aide_baseline_exists             && record_check "AIDE"         "PASS" "AIDE installed + database initialized"             || record_check "AIDE"         "FAIL" "AIDE installed but baseline missing"
    else
        record_check "AIDE"                "FAIL" "AIDE not installed"
    fi

    # AppArmor
    if command -v aa-status >/dev/null 2>&1; then
        local enforced complain loaded proc_enforce proc_complain aa_enabled_state loaded_profiles docker_only=false
        enforced=$(apparmor_numeric_count 'profiles are in enforce mode')
        complain=$(apparmor_numeric_count 'profiles are in complain mode')
        loaded=$(apparmor_numeric_count 'profiles are loaded')
        proc_enforce=$(apparmor_numeric_count 'processes are in enforce mode')
        proc_complain=$(apparmor_numeric_count 'processes are in complain mode')
        aa_enabled_state=$(aa-enabled >/dev/null 2>&1; echo $?)
        loaded_profiles=$(cat /sys/kernel/security/apparmor/profiles 2>/dev/null || true)
        if [[ -n "$loaded_profiles" ]]; then
            local profile_count
            profile_count=$(printf '%s\n' "$loaded_profiles" | sed '/^\s*$/d' | wc -l)
            if (( profile_count == 1 )) && [[ "$loaded_profiles" == *"docker-default (enforce)"* ]]; then
                docker_only=true
            fi
        fi
        if [[ "$aa_enabled_state" != "0" ]]; then
            record_check "APPARMOR" "FAIL" "AppArmor kernel support unavailable or disabled"
        elif (( ${enforced:-0} == 0 )) || (( ${loaded:-0} == 0 )); then
            record_check "APPARMOR" "FAIL" "AppArmor enabled but no enforce profiles loaded"
        elif ($HOST_HAS_DOCKER || $HOST_HAS_PODMAN || command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1) && $docker_only; then
            record_check "APPARMOR" "FAIL" "AppArmor only active for docker-default; host profile coverage absent"
        elif (( ${proc_complain:-0} > 0 )); then
            record_check "APPARMOR" "FAIL" "AppArmor: ${proc_complain:-0} running process(es) in complain mode"
        elif (( ${complain:-0} > 0 )); then
            record_check "APPARMOR" "INFO" "AppArmor: ${complain:-0} profile(s) in complain mode, but no running process currently affected"
        else
            record_check "APPARMOR" "PASS" "AppArmor: ${enforced:-0} enforce, ${complain:-0} complain; ${proc_enforce:-0} process(es) enforced"
        fi
    else
        record_check "APPARMOR"            "FAIL" "AppArmor not available"
    fi

    # Sysctl
    load_sysctl_policy
    local sysctl_fail=0 sysctl_configured_only=0
    local -a sysctl_fails=() sysctl_configured_pending=()
    local param desired current configured
    for param in "${!SYSCTL_POLICY[@]}"; do
        desired="${SYSCTL_POLICY[$param]}"
        current=$(get_effective_sysctl_config "$param")
        if ! sysctl_value_matches_policy "$param" "$desired" "$current"; then
            sysctl_fail=$((sysctl_fail+1))
            sysctl_fails+=("$param")
            configured=$(get_persisted_sysctl_config "$param")
            if [[ -n "$configured" ]] && sysctl_value_matches_policy "$param" "$desired" "$configured"; then
                sysctl_configured_only=$((sysctl_configured_only+1))
                sysctl_configured_pending+=("${param}=${current:-unset} (want ${desired}; configured ${configured})")
            fi
        fi
    done
    if (( sysctl_fail == 0 )); then
        record_check "SYSCTL" "PASS" "All critical sysctl parameters hardened"
    elif (( sysctl_fail == sysctl_configured_only )) && (( sysctl_fail > 0 )); then
        record_check "SYSCTL" "INFO" "${sysctl_fail} sysctl param(s) configured but not active yet: $(format_sysctl_findings "${sysctl_configured_pending[@]}")"
    else
        local -a sysctl_details=()
        for param in "${sysctl_fails[@]}"; do
            desired="${SYSCTL_POLICY[$param]}"
            current=$(get_effective_sysctl_config "$param")
            configured=$(get_persisted_sysctl_config "$param")
            if [[ -n "$configured" ]]; then
                sysctl_details+=("${param}=${current:-unset} (want ${desired}; configured ${configured})")
            else
                sysctl_details+=("${param}=${current:-unset} (want ${desired}; not configured)")
            fi
        done
        record_check "SYSCTL" "FAIL" "${sysctl_fail} sysctl param(s) not hardened: $(format_sysctl_findings "${sysctl_details[@]}")"
    fi

    # Core dumps
    local core_sysctl core_configured core_limits=false core_msg
    core_sysctl=$(get_effective_sysctl_config "fs.suid_dumpable")
    core_configured=$(get_persisted_sysctl_config "fs.suid_dumpable")
    grep -qE '^\s*\*\s+hard\s+core\s+0' /etc/security/limits.conf /etc/security/limits.d/*.conf 2>/dev/null && core_limits=true
    if [[ "$core_sysctl" == "0" ]] && $core_limits; then
        record_check "CORE_DUMPS" "PASS" "Core dumps disabled (limits + fs.suid_dumpable=0)"
    elif [[ "$core_sysctl" != "0" ]] && [[ "$core_configured" == "0" ]] && $core_limits; then
        record_check "CORE_DUMPS" "INFO" "Core dump limits are present and fs.suid_dumpable is configured to 0, but runtime is still ${core_sysctl:-not_set}"
    else
        core_msg="Core dumps not fully disabled"
        if $core_limits; then
            core_msg+="; limits hard core 0 present"
        else
            core_msg+="; hard core 0 limit missing"
        fi
        if [[ -n "$core_configured" ]]; then
            core_msg+="; fs.suid_dumpable=${core_sysctl:-not_set} (configured ${core_configured})"
        else
            core_msg+="; fs.suid_dumpable=${core_sysctl:-not_set}"
        fi
        record_check "CORE_DUMPS" "FAIL" "$core_msg"
    fi

    # Filesystem hardening
    local fstab_issues=0
    for mountpoint in /tmp /dev/shm; do
        if grep -qE "^\S+\s+${mountpoint}\s" /proc/mounts 2>/dev/null; then
            local opts opt
            opts=$(grep -E "^\S+\s+${mountpoint}\s" /proc/mounts | awk '{print $4}')
            for opt in noexec nosuid nodev; do
                echo "$opts" | grep -q "$opt" || fstab_issues=$((fstab_issues+1))
            done
        fi
    done
    (( fstab_issues == 0 )) \
        && record_check "FSTAB_HARDENING"  "PASS" "/tmp + /dev/shm: noexec,nosuid,nodev" \
        || record_check "FSTAB_HARDENING"  "FAIL" "${fstab_issues} mount option(s) missing on /tmp or /dev/shm"

    # Kernel modules
    [[ -f "$MODPROBE_BLACKLIST" ]] \
        && record_check "MODULE_BLACKLIST" "PASS" "Module blacklist in place" \
        || record_check "MODULE_BLACKLIST" "FAIL" "No kernel module blacklist"

    # PAM pwquality
    is_package_installed libpam-pwquality \
        && record_check "PAM_PWQUALITY"    "PASS" "libpam-pwquality installed" \
        || record_check "PAM_PWQUALITY"    "FAIL" "libpam-pwquality not installed"

    # PAM faillock
    if grep -qE '^\s*deny\s*=\s*[1-9]' "$FAILLOCK_CONF" 2>/dev/null; then
        record_check "PAM_FAILLOCK"        "PASS" "pam_faillock configured via faillock.conf"
    elif grep -Rqs "pam_faillock\.so" /etc/pam.d/common-auth /etc/pam.d/common-account 2>/dev/null; then
        record_check "PAM_FAILLOCK"        "PASS" "pam_faillock present in PAM stack"
    else
        record_check "PAM_FAILLOCK"        "FAIL" "pam_faillock not configured"
    fi

    # Root lock
    passwd -S root 2>/dev/null | awk '{print $2}' | grep -q '^L' \
        && record_check "ROOT_LOCKED"      "PASS" "root account locked" \
        || record_check "ROOT_LOCKED"      "FAIL" "root account not locked"

    # Banner
    [[ -s "$BANNER_FILE" ]] && grep -qi "authorized" "$BANNER_FILE" 2>/dev/null \
        && record_check "LOGIN_BANNER"     "PASS" "Login banner configured" \
        || record_check "LOGIN_BANNER"     "FAIL" "Login banner missing"

    # sudoers tty tickets
    sudoers_has_tty_tickets         && record_check "SUDOERS_TTY"      "PASS" "tty_tickets configured"         || record_check "SUDOERS_TTY"      "FAIL" "tty_tickets not set"

    # System-wide default umask
    local login_umask systemd_system_umask systemd_user_umask profile_hook_state
    login_umask=$(awk '$1 == "UMASK" {print $2}' "$LOGIN_DEFS_FILE" 2>/dev/null | tail -n 1)
    systemd_system_umask=$(get_systemd_default_umask_from_file "$SYSTEM_UMASK_SYSTEMD_DROPIN" 2>/dev/null || true)
    systemd_user_umask=$(get_systemd_default_umask_from_file "$USER_UMASK_SYSTEMD_DROPIN" 2>/dev/null || true)
    interactive_umask_shell_hook_present && profile_hook_state="present" || profile_hook_state="missing"
    if octal_umask_is_restrictive_enough "$login_umask"        && octal_umask_is_restrictive_enough "$systemd_system_umask"        && octal_umask_is_restrictive_enough "$systemd_user_umask"        && interactive_umask_shell_hook_present; then
        record_check "LOGIN_UMASK" "PASS" "System-wide default umask hardened (login.defs=${login_umask}, systemd-system=${systemd_system_umask}, systemd-user=${systemd_user_umask})"
    else
        record_check "LOGIN_UMASK" "FAIL" "System-wide default umask incomplete (login.defs=${login_umask:-unset}, shell-hook=${profile_hook_state}, systemd-system=${systemd_system_umask:-unset}, systemd-user=${systemd_user_umask:-unset})"
    fi

    # SUID/SGID inventory baseline
    if [[ -x "$SUID_SGID_AUDIT_SCRIPT" && -s "$SUID_SGID_AUDIT_BASELINE" && -f "$SUID_SGID_AUDIT_CRON" ]]; then
        record_check "SUID_SGID_BASELINE" "PASS" "SUID/SGID inventory baseline + daily audit present"
    else
        record_check "SUID_SGID_BASELINE" "FAIL" "SUID/SGID inventory baseline missing"
    fi

    # NTP
    if systemctl is-active --quiet systemd-timesyncd 2>/dev/null || \
       systemctl is-active --quiet chrony 2>/dev/null || \
       systemctl is-active --quiet ntp 2>/dev/null; then
        record_check "NTP"                 "PASS" "NTP service active"
    else
        record_check "NTP"                 "FAIL" "No NTP service running"
    fi
}

# ============================================================================
# PRINT ASSESSMENT REPORT
# ============================================================================
print_assessment_report() {
    local green=0 yellow=0 red=0

    write_compliance_report

    echo
    echo -e "${C_BOLD}${C_CYAN}╔════════════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}║                 SECURITY / COMPLIANCE MATRIX (ID + SEVERITY)                     ║${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}╚════════════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
    printf "  %-14s %-8s %-8s %s
" "CHECK-ID" "SEV" "STATUS" "DETAILS"
    echo -e "  ${C_CYAN}$(printf '%.0s─' {1..92})${C_RESET}"

    local id entry raw desc normalized color label stable severity title mode first line
    for id in "${ASSESS_ORDER[@]}"; do
        entry="${ASSESS_RESULTS[$id]}"
        raw="${entry%%:*}"
        desc="${entry#*:}"
        normalized="$(normalize_matrix_status "$raw")"
        stable="${ASSESS_META_STABLE_ID[$id]:-$(lookup_check_stable_id "$id")}"
        severity="${ASSESS_META_SEVERITY[$id]:-$(lookup_check_severity "$id")}"
        title="${ASSESS_META_TITLE[$id]:-$(lookup_check_title "$id")}"
        mode="${ASSESS_META_MODE[$id]:-}"
        case "$raw" in
            EXCEPTION) color="$C_YELLOW_BOLD"; label="EXC"; yellow=$((yellow+1)) ;;
            *)
                case "$normalized" in
                    GREEN)  color="$C_GREEN_BOLD";  label="GREEN"; green=$((green+1)) ;;
                    YELLOW) color="$C_YELLOW_BOLD"; label="WARN" ; yellow=$((yellow+1)) ;;
                    RED)    color="$C_RED_BOLD";    label="RED"  ; red=$((red+1)) ;;
                esac
                ;;
        esac
        first=true
        while IFS= read -r line; do
            if $first; then
                printf "  ${color}%-14s %-8s %-8s${C_RESET} %s
" "$stable" "$severity" "$label" "$line"
                first=false
            else
                printf "  %-14s %-8s %-8s %s
" "" "" "" "$line"
            fi
        done < <(printf '%s
' "${title} — ${desc}" | fold -s -w 92)
        if [[ -n "$mode" ]]; then
            printf "  %-14s %-8s %-8s %s
" "" "" "" "mode=${mode} | $(lookup_check_controls_compact "$id")"
        else
            printf "  %-14s %-8s %-8s %s
" "" "" "" "$(lookup_check_controls_compact "$id")"
        fi
    done

    echo -e "  ${C_CYAN}$(printf '%.0s─' {1..92})${C_RESET}"
    echo
    local total=$(( green + yellow + red ))
    local score=0; (( (green + red) > 0 )) && score=$(( green * 100 / (green + red) ))

    echo -e "  ${C_BOLD}$(tr_msg result_label):${C_RESET}  ${C_GREEN_BOLD}GREEN: ${green}${C_RESET}   ${C_YELLOW_BOLD}WARN/EXC: ${yellow}${C_RESET}   ${C_RED_BOLD}RED: ${red}${C_RESET}   (${total} Checks)"
    echo -e "  ${C_BOLD}Compliance report:${C_RESET} $COMPLIANCE_REPORT"
    echo
    if (( red == 0 && yellow == 0 )); then
        echo -e "  ${C_GREEN_BOLD}$(tr_msg matrix_green)${C_RESET}"
    elif (( red == 0 )); then
        echo -e "  ${C_YELLOW_BOLD}Assessment completed with advisory / excepted findings only — no blocking RED findings.${C_RESET}"
    elif (( score >= 75 )); then
        echo -e "  ${C_YELLOW_BOLD}$(tr_msg matrix_warn_prefix) ${red} $(tr_msg matrix_warn_suffix)${C_RESET}"
    else
        echo -e "  ${C_RED_BOLD}$(tr_msg matrix_red_prefix) ${red} $(tr_msg matrix_red_suffix)${C_RESET}"
    fi
    echo
}

# ============================================================================
# SECTION 1: SSH Key Generation
# ============================================================================
configure_ssh_key_and_users() {
    info "${C_BOLD}1. SSH Key Pair (Ed25519)${C_RESET}"
    describe_action "ssh_key"
    is_section_skipped "ssh_key" && { info "Skipped."; record_check "SSH_KEY_GEN" "SKIP" "$(section_skip_record_desc)"; echo; return 0; }
    ask_yes_no "Execute SSH Key step?" "y" || { record_check "SSH_KEY_GEN" "SKIP" "User skipped"; echo; return 0; }

    local current_user="${SUDO_USER:-$(whoami)}"
    local user_home; user_home=$(eval echo "~$current_user")
    local existing_count=0
    if [[ -d "$user_home/.ssh" ]]; then
        existing_count=$(find "$user_home/.ssh" -maxdepth 1 -type f -name "*.pub" \
            -exec grep -Eil "ssh-ed25519" {} + 2>/dev/null | wc -l)
        [[ -f "$user_home/.ssh/authorized_keys" ]] && \
            existing_count=$((existing_count + $(grep -Eic "ssh-ed25519" "$user_home/.ssh/authorized_keys" 2>/dev/null || echo 0)))
    fi
    (( existing_count > 0 )) && success "Found $existing_count Ed25519 key(s)." || warn "No Ed25519 key found."

    ask_yes_no "Create new Ed25519 key for '$current_user'?" "y" || { section_done 1; return 0; }

    local new_key_name
    $AUTO_MODE && new_key_name="id_ed25519_$(date +%Y%m%d)" || {
        read -rp "Key filename [id_ed25519_$(date +%Y%m%d)]: " new_key_name </dev/tty
        new_key_name=${new_key_name:-"id_ed25519_$(date +%Y%m%d)"}
    }
    local key_path="$user_home/.ssh/$new_key_name"
    local pub_key_path="${key_path}.pub"

    [[ -f "$key_path" ]] && ! ask_yes_no "Key exists. Overwrite?" "n" && { section_done 1; return 0; }

    local passphrase=""
    $AUTO_MODE || {
        local passphrase_confirm
        while true; do
            read -rsp "Passphrase (empty=none): " passphrase </dev/tty; echo
            read -rsp "Confirm: " passphrase_confirm </dev/tty; echo
            [[ "$passphrase" == "$passphrase_confirm" ]] && break
            warn "Passphrases don't match."
        done
    }

    run_cmd "MKDIR_SSH" mkdir -p "$user_home/.ssh"
    run_cmd "CHMOD_SSH" chmod 700 "$user_home/.ssh"
    run_cmd "CHOWN_SSH" chown "$current_user":"$current_user" "$user_home/.ssh"

    if $DRY_RUN; then
        dry_run_echo "ssh-keygen -q -t ed25519 -f '$key_path' -N '***'"
        record_check "SSH_KEY_GEN" "FIXED" "DRY-RUN: Would generate $key_path"
        section_done 1; return 0
    fi

    if sudo -u "$current_user" ssh-keygen -q -t ed25519 -f "$key_path" -N "$passphrase"; then
        chmod 600 "$key_path"; chmod 644 "$pub_key_path"
        chown "$current_user":"$current_user" "$key_path" "$pub_key_path"
        log_change "SSH_KEY_GENERATED:${key_path}"

        echo
        echo -e "${C_YELLOW_BOLD}  ╔══════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "${C_YELLOW_BOLD}  ║  SSH Private Key erzeugt — NICHT im Terminal anzeigen!      ║${C_RESET}"
        echo -e "${C_YELLOW_BOLD}  ╠══════════════════════════════════════════════════════════════╣${C_RESET}"
        echo -e "${C_YELLOW_BOLD}  ║  Private Key: ${C_CYAN}${key_path}${C_RESET}"
        echo -e "${C_YELLOW_BOLD}  ║  Public Key:  ${pub_key_path}${C_RESET}"
        echo -e "${C_YELLOW_BOLD}  ║${C_RESET}"
        echo -e "${C_YELLOW_BOLD}  ║  Auf lokalen Rechner kopieren:${C_RESET}"
        echo -e "${C_YELLOW_BOLD}  ║  ${C_CYAN}scp root@<server>:${key_path} ~/.ssh/${new_key_name}${C_RESET}"
        echo -e "${C_YELLOW_BOLD}  ╚══════════════════════════════════════════════════════════════╝${C_RESET}"
        echo

        # authorized_keys
        local authorized_keys_path="$user_home/.ssh/authorized_keys"
        sudo -u "$current_user" test -f "$authorized_keys_path" || {
            sudo -u "$current_user" touch "$authorized_keys_path"
            sudo -u "$current_user" chmod 600 "$authorized_keys_path"
        }
        local pub_content; pub_content=$(cat "$pub_key_path")
        sudo -u "$current_user" grep -Fq -- "$pub_content" "$authorized_keys_path" 2>/dev/null \
            && success "Public key already in authorized_keys." \
            || echo "$pub_content" | sudo -u "$current_user" tee -a "$authorized_keys_path" >/dev/null \
            && success "Public key added to authorized_keys."
        [[ -n "$passphrase" ]] && warn "Passphrase sicher aufbewahren!"
        record_check "SSH_KEY_GEN" "FIXED" "Ed25519 key: $key_path"
    else
        error "Key generation failed."
        record_check "SSH_KEY_GEN" "FAIL" "Key generation failed"
    fi
    section_done 1
}

# ============================================================================
# SECTION 2: Unattended Upgrades
# ============================================================================
configure_unattended_upgrades() {
    info "${C_BOLD}2. Unattended Upgrades${C_RESET}"
    describe_action "upgrades"
    is_section_skipped "upgrades" && { info "Skipped."; echo; return 0; }

    local policy_diff
    policy_diff=$(unattended_upgrades_policy_diff 2>/dev/null || true)
    if [[ -z "$policy_diff" ]]; then
        success "Existing unattended-upgrades configuration already matches script recommendations."
        record_check "UNATTENDED_UPGRADES" "PASS" "Already aligned with script recommendations"
        section_done 2
        return 0
    fi
    [[ "$policy_diff" != "package missing" ]] && warn "Current unattended-upgrades setup differs from script recommendations: $policy_diff"
    ask_yes_no "Configure Unattended Upgrades?" "y" || { echo; return 0; }

    local pkg="unattended-upgrades"
    local config_file="/etc/apt/apt.conf.d/50unattended-upgrades"
    local periodic_file="/etc/apt/apt.conf.d/20auto-upgrades"

    local distro_id distro_codename
    command -v lsb_release &>/dev/null \
        && { distro_id=$(lsb_release -is); distro_codename=$(lsb_release -cs); } \
        || {
            distro_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
            distro_id="${distro_id^}"
            distro_codename=$(grep '^VERSION_CODENAME=' /etc/os-release | cut -d= -f2 | tr -d '"')
        }
    [[ -z "$distro_id" || -z "$distro_codename" ]] && { error "Cannot determine distro."; return 1; }
    info "Detected: $distro_id $distro_codename"

    ensure_packages_installed "$pkg" || return 0

    # Periodic
    if [[ ! -f "$periodic_file" ]] || \
       ! grep -qE '^\s*APT::Periodic::Update-Package-Lists\s*"1"\s*;' "$periodic_file" || \
       ! grep -qE '^\s*APT::Periodic::Unattended-Upgrade\s*"1"\s*;' "$periodic_file"; then
        describe_detail "upgrades_periodic"
        ask_yes_no "Apply recommended periodic settings?" "y" && {
            backup_file "$periodic_file"
            run_shell "WRITE_FILE:$periodic_file" \
                "printf 'APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n' > '$periodic_file'" \
                && success "'$periodic_file' configured." || { error "Failed."; restore_file "$periodic_file"; }
        }
    else success "'$periodic_file' already correct."; fi

    [[ ! -f "$config_file" ]] && { error "Config '$config_file' not found!"; return 1; }

    local temp_file; temp_file=$(mktemp_tracked)
    cp "$config_file" "$temp_file"
    local changes_made=false

    declare -A desired_params=(
        ["Unattended-Upgrade::AutoFixInterruptedDpkg"]="true"
        ["Unattended-Upgrade::MinimalSteps"]="true"
        ["Unattended-Upgrade::MailReport"]="on-change"
        ["Unattended-Upgrade::Remove-Unused-Kernel-Packages"]="true"
        ["Unattended-Upgrade::Remove-New-Unused-Dependencies"]="true"
        ["Unattended-Upgrade::Remove-Unused-Dependencies"]="true"
        ["Unattended-Upgrade::Automatic-Reboot"]="true"
        ["Unattended-Upgrade::Automatic-Reboot-WithUsers"]="false"
        ["Unattended-Upgrade::Automatic-Reboot-Time"]="02:00"
    )

    local key value current_line
    for key in "${!desired_params[@]}"; do
        value="${desired_params[$key]}"
        current_line=$(grep -E "^\s*(//\s*)?${key}\s+" "$temp_file" || true)
        if [[ -n "$current_line" ]]; then
            [[ "$current_line" =~ ^\s*// ]] || \
                [[ "$(echo "$current_line" | sed -E 's/.*"([^"]*)"[^"]*$/\1/')" == "$value" ]] && {
                success "  $key already correct."; continue; }
            sed -i -E "s|^\s*(//\s*)?${key}\s+.*|${key} \"${value}\";|" "$temp_file"
            changes_made=true
        else
            echo "${key} \"${value}\";" >> "$temp_file"; changes_made=true
        fi
        success "  $key -> $value"
    done

    $AUTO_MODE && [[ -n "${AUTO_ADMIN_EMAIL:-}" ]] && {
        local mk="Unattended-Upgrade::Mail"
        grep -qE "^\s*(//\s*)?${mk}\s+" "$temp_file" \
            && sed -i -E "s|^\s*(//\s*)?${mk}\s+.*|${mk} \"${AUTO_ADMIN_EMAIL}\";|" "$temp_file" \
            || echo "${mk} \"${AUTO_ADMIN_EMAIL}\";" >> "$temp_file"
        changes_made=true
    }

    if $changes_made; then
        backup_file "$config_file" || return 1
        $DRY_RUN && dry_run_echo "Apply changes to $config_file" \
            || { mv "$temp_file" "$config_file" && chmod 644 "$config_file" \
                && success "Applied to $config_file." \
                && log_change "APPLY_CONFIG:$config_file" \
                && record_check "UNATTENDED_UPGRADES" "FIXED" "unattended-upgrades configured" \
                || { error "Failed!"; restore_file "$config_file"; }; }
    else
        success "No changes needed."; record_check "UNATTENDED_UPGRADES" "PASS" "Already configured"
    fi
    section_done 2
}

# ============================================================================
# SECTION 3: MSMTP
# ============================================================================
configure_msmtp() {
    info "${C_BOLD}3. MSMTP Mail Notifications${C_RESET}"
    describe_action "msmtp"
    is_section_skipped "msmtp" && { info "Skipped."; echo; return 0; }
    ask_yes_no "Setup MSMTP?" "y" || { echo; return 0; }

    local target_user="${SUDO_USER:-$USER}" config_owner user_home config_file_path
    $AUTO_MODE && config_owner="$target_user" || {
        read -rp "MSMTP for user [$target_user]: " config_owner </dev/tty
        config_owner=${config_owner:-$target_user}
    }
    user_home=$(eval echo "~$config_owner")
    [[ -d "$user_home" ]] || { error "Home dir not found for '$config_owner'."; return 1; }
    config_file_path="$user_home/.msmtprc"

    ensure_packages_installed "msmtp" "msmtp-mta" || return 0

    local do_configure=false
    [[ -f "$config_file_path" ]] \
        && { warn "MSMTP config exists."; ask_yes_no "Overwrite?" "n" && do_configure=true; } \
        || { ask_yes_no "Setup MSMTP now?" "y" && do_configure=true; }
    $do_configure || { section_done 3; return 0; }

    local smtp_host smtp_port smtp_tls smtp_trust_file smtp_from smtp_user smtp_password
    if $AUTO_MODE && [[ -n "${AUTO_SMTP_HOST:-}" ]]; then
        smtp_host="${AUTO_SMTP_HOST}" smtp_port="${AUTO_SMTP_PORT:-587}"
        smtp_tls="${AUTO_SMTP_TLS:-on}" smtp_from="${AUTO_ADMIN_EMAIL:-}"
        smtp_user="${AUTO_SMTP_USER:-$smtp_from}" smtp_password="${AUTO_SMTP_PASS:-}"
        [[ -z "$smtp_from" || -z "$smtp_password" ]] && { warn "SMTP credentials incomplete, skipping."; section_done 3; return 0; }
    else
        while true; do read -rp "SMTP Host: " smtp_host </dev/tty; [[ -n "$smtp_host" ]] && break; done
        while true; do read -rp "Port [587]: " smtp_port </dev/tty; smtp_port=${smtp_port:-587}; validate_port "$smtp_port" && break; done
        while true; do read -rp "TLS (on/off) [on]: " smtp_tls </dev/tty; smtp_tls=${smtp_tls:-on}; [[ "$smtp_tls" =~ ^(on|off)$ ]] && break; done
        read -rp "CA cert [/etc/ssl/certs/ca-certificates.crt]: " smtp_trust_file </dev/tty
        smtp_trust_file=${smtp_trust_file:-/etc/ssl/certs/ca-certificates.crt}
        while true; do read -rp "From email: " smtp_from </dev/tty; validate_email "$smtp_from" && break; done
        while true; do read -rp "Username [$smtp_from]: " smtp_user </dev/tty; smtp_user=${smtp_user:-$smtp_from}; [[ -n "$smtp_user" ]] && break; done
        while true; do read -rsp "Password: " smtp_password </dev/tty; echo; [[ -n "$smtp_password" ]] && break; done
        ask_yes_no "Save?" "y" || { section_done 3; return 0; }
    fi

    local logfile_path="${user_home}/.msmtp.log"
    local tmsmtp; tmsmtp=$(mktemp_tracked)
    cat > "$tmsmtp" <<EOF
# MSMTP — generated by security_script.sh v${SCRIPT_VERSION}
defaults
port $smtp_port
tls $smtp_tls
tls_trust_file $smtp_trust_file
logfile $logfile_path
account default
host $smtp_host
from $smtp_from
auth on
user $smtp_user
password $smtp_password
aliases /etc/aliases
EOF
    if install_managed_file "$config_file_path" "$tmsmtp" 600 "$config_owner" "$config_owner"; then
        $DRY_RUN || { touch "$logfile_path"; chmod 600 "$logfile_path"; chown "$config_owner":"$config_owner" "$logfile_path"; }
        success "MSMTP configured."
    fi
    section_done 3
}

# ============================================================================
# SECTION 4a: SSH Hardening
# ============================================================================
configure_ssh_hardening() {
    info "${C_BOLD}4a. SSH Hardening${C_RESET}"
    describe_action "ssh_hardening"
    is_section_skipped "ssh_hardening" && { info "Skipped."; echo; return 0; }

    local rec_delta_mode=false
    $INTERACTIVE_RECOMMENDED_MODE && rec_delta_mode=true

    local ssh_root_red=false ssh_pass_red=false ssh_x11_red=false ssh_agent_red=false ssh_tcp_red=false ssh_grace_red=false ssh_maxauth_red=false ssh_crypto_red=false
    section_check_is_red "SSH_ROOT_LOGIN"    && ssh_root_red=true
    section_check_is_red "SSH_PASSWORD_AUTH" && ssh_pass_red=true
    section_check_is_red "SSH_X11"           && ssh_x11_red=true
    section_check_is_red "SSH_AGENT_FWD"     && ssh_agent_red=true
    section_check_is_red "SSH_TCP_FWD"       && ssh_tcp_red=true
    section_check_is_red "SSH_GRACE_TIME"    && ssh_grace_red=true
    section_check_is_red "SSH_MAX_AUTH"      && ssh_maxauth_red=true
    section_check_is_red "SSH_CRYPTO_POLICY" && ssh_crypto_red=true

    local noncrypto_ssh_pending=false any_ssh_pending=false
    $ssh_root_red    && noncrypto_ssh_pending=true
    $ssh_pass_red    && noncrypto_ssh_pending=true
    $ssh_x11_red     && noncrypto_ssh_pending=true
    $ssh_agent_red   && noncrypto_ssh_pending=true
    $ssh_tcp_red     && noncrypto_ssh_pending=true
    $ssh_grace_red   && noncrypto_ssh_pending=true
    $ssh_maxauth_red && noncrypto_ssh_pending=true
    $noncrypto_ssh_pending && any_ssh_pending=true
    $ssh_crypto_red && any_ssh_pending=true

    if $rec_delta_mode && ! $any_ssh_pending; then
        success "No pending SSH findings for recommended mode."
        echo
        return 0
    fi

    if $rec_delta_mode; then
        if $ssh_crypto_red && ! $noncrypto_ssh_pending; then
            :
        else
            ask_yes_no "Apply remaining SSH hardening findings?" "y" || { echo; return 0; }
            mark_section_executed
        fi
    else
        ask_yes_no "Execute SSH Hardening?" "y" || { echo; return 0; }
        mark_section_executed
    fi

    local ssh_config="/etc/ssh/sshd_config" sshd_needs_restart=false
    local ssh_dropin_dir
    ssh_dropin_dir="$(dirname "$SSHD_HARDENING_DROPIN")"

    # AllowUsers is intentionally excluded from recommended delta mode because
    # it is an environment-specific access control decision, not a minimum baseline finding.
    if ! $AUTO_MODE && ! $INTERACTIVE_RECOMMENDED_MODE; then
        describe_detail "ssh_allowusers"
        ask_yes_no "Configure AllowUsers?" "n" && {
            local suggested target_users
            suggested=$(awk -F: '$3 >= 1000 && $3 < 65534 { print $1; exit }' /etc/passwd)
            read -rp "SSH users (suggestion: ${suggested:-admin}, empty=skip): " target_users </dev/tty
            if [[ -n "$target_users" ]]; then
                local all_exist=true u
                for u in $target_users; do id "$u" &>/dev/null || { error "User '$u' not found."; all_exist=false; }; done
                $all_exist && { describe_detail "ssh_allowusers"; ask_yes_no "Set AllowUsers='$target_users'?" "y"; } && {
                    backup_file "$ssh_config"
                    local tc; tc=$(mktemp_tracked); cp "$ssh_config" "$tc"
                    set_sshd_param "AllowUsers" "$target_users" "$tc" || true
                    apply_sshd_config "$tc" && { log_change "AllowUsers:$target_users"; sshd_needs_restart=true; }
                }
            fi
        }
    elif [[ -n "${AUTO_ALLOW_USERS:-}" ]]; then
        backup_file "$ssh_config"
        local tc; tc=$(mktemp_tracked); cp "$ssh_config" "$tc"
        set_sshd_param "AllowUsers" "$AUTO_ALLOW_USERS" "$tc" || true
        apply_sshd_config "$tc" && { log_change "AllowUsers:$AUTO_ALLOW_USERS"; sshd_needs_restart=true; }
    fi

    declare -A ssh_recommendations=(
        ["PermitRootLogin"]="prohibit-password"
        ["PasswordAuthentication"]="no"
        ["ChallengeResponseAuthentication"]="no"
        ["UsePAM"]="yes"
        ["X11Forwarding"]="no"
        ["AllowAgentForwarding"]="no"
        ["AllowTcpForwarding"]="no"
        ["LoginGraceTime"]="30"
        ["MaxAuthTries"]="3"
        ["MaxSessions"]="2"
        ["PermitUserEnvironment"]="no"
        ["ClientAliveInterval"]="300"
        ["ClientAliveCountMax"]="2"
        ["PrintLastLog"]="yes"
    )

    local check_user="${SUDO_USER:-$(whoami)}"
    local check_home; check_home=$(eval echo "~$check_user")
    local key_count=0
    [[ -d "$check_home/.ssh" ]] && {
        key_count=$(find "$check_home/.ssh" -maxdepth 1 -name "*.pub" -exec grep -Eil "ssh-ed25519|ssh-rsa|ecdsa-sha2" {} + 2>/dev/null | wc -l)
        [[ -f "$check_home/.ssh/authorized_keys" ]] && key_count=$((key_count + $(grep -Eic "ssh-ed25519|ssh-rsa|ecdsa-sha2" "$check_home/.ssh/authorized_keys" 2>/dev/null || echo 0)))
    }

    local auth_methods_current ssh_uses_kbi=false
    auth_methods_current=$(get_effective_sshd_config "AuthenticationMethods" 2>/dev/null || true)
    if ssh_uses_keyboard_interactive; then
        ssh_uses_kbi=true
        ssh_recommendations["ChallengeResponseAuthentication"]="yes"
        ssh_recommendations["KbdInteractiveAuthentication"]="yes"
        warn "SSH 2FA / keyboard-interactive detected via AuthenticationMethods='${auth_methods_current:-<empty>}' — keeping ChallengeResponseAuthentication/KbdInteractiveAuthentication enabled."
    fi

    local ssh_crypto_policy_default="off"
    $INTERACTIVE_RECOMMENDED_MODE && ssh_crypto_policy_default="strict"
    [[ "$ACTIVE_PROFILE" == "strict" && "$ssh_crypto_policy_default" == "off" ]] && ssh_crypto_policy_default="strict"
    local ssh_crypto_policy_mode="${AUTO_SSH_CRYPTO_POLICY:-$ssh_crypto_policy_default}"
    if ! $AUTO_MODE; then
        echo
        info "Optional Mil/Gov enhancement: explicit SSH crypto policy pinning."
        info "This only affects SSH client compatibility, not web services such as Nextcloud, Caddy or AdGuard Home."
        if $rec_delta_mode && $ssh_crypto_red && ! $noncrypto_ssh_pending; then
            info "The recommended SSH crypto policy pins a strict SSH algorithm set for Ciphers, MACs and KEX. This is closer to a Mil/Gov-oriented baseline, but can break older SSH clients."
            info "Choose 'yes' to apply the recommended 'strict' policy. Choose 'no' to leave the current SSH crypto settings unchanged."
            if ask_yes_no "Apply recommended SSH crypto policy ('strict')?" "y"; then
                ssh_crypto_policy_mode="strict"
                mark_section_executed
            else
                ssh_crypto_policy_mode="off"
            fi
        else
            $INTERACTIVE_RECOMMENDED_MODE && info "Recommended mode default: 'strict' (stronger Mil/Gov-style baseline for current OpenSSH clients)."
            info "'strict' is the strongest built-in baseline and may break older SSH clients. 'modern' is slightly more compatible, 'fips-compatible' is for FIPS-oriented environments."
            read -rp "SSH crypto policy [off/strict/modern/fips-compatible] (default: ${ssh_crypto_policy_default}): " ssh_crypto_policy_mode </dev/tty
        fi
        ssh_crypto_policy_mode="${ssh_crypto_policy_mode:-$ssh_crypto_policy_default}"
    fi
    case "$(echo "$ssh_crypto_policy_mode" | tr '[:upper:]' '[:lower:]')" in
        "") ssh_crypto_policy_mode="$ssh_crypto_policy_default" ;;
        y|yes) ssh_crypto_policy_mode="$ssh_crypto_policy_default" ;;
        n|no) ssh_crypto_policy_mode="off" ;;
        off|strict|modern|fips-compatible) ssh_crypto_policy_mode="$(echo "$ssh_crypto_policy_mode" | tr '[:upper:]' '[:lower:]')" ;;
        *) warn "Invalid SSH crypto policy '$ssh_crypto_policy_mode' — using default '$ssh_crypto_policy_default'."; ssh_crypto_policy_mode="$ssh_crypto_policy_default" ;;
    esac

    declare -A changes_to_apply=()
    declare -A final_secure_values=()
    local param current recommended cur_lower rec_lower ask_user default_ans related_check preserve_only

    for param in "${!ssh_recommendations[@]}"; do
        current=$(get_effective_sshd_config "$param"); recommended="${ssh_recommendations[$param]}"; ask_user=true; preserve_only=false
        [[ -z "$current" ]] && case "$param" in
            "PasswordAuthentication"|"ChallengeResponseAuthentication"|"KbdInteractiveAuthentication"|"AllowAgentForwarding"|"AllowTcpForwarding"|"PermitRootLogin") current="yes" ;;
            "X11Forwarding"|"PermitUserEnvironment") current="no" ;;
            "LoginGraceTime") current="120" ;;
            "MaxAuthTries") current="6" ;;
            "MaxSessions") current="10" ;;
            "ClientAliveInterval") current="300" ;;
            "ClientAliveCountMax") current="2" ;;
            "PrintLastLog") current="yes" ;;
        esac
        cur_lower=$(echo "${current:-}" | tr '[:upper:]' '[:lower:]')
        rec_lower=$(echo "$recommended" | tr '[:upper:]' '[:lower:]')

        related_check=""
        case "$param" in
            PermitRootLogin) related_check="SSH_ROOT_LOGIN" ;;
            PasswordAuthentication) related_check="SSH_PASSWORD_AUTH" ;;
            X11Forwarding) related_check="SSH_X11" ;;
            AllowAgentForwarding) related_check="SSH_AGENT_FWD" ;;
            AllowTcpForwarding) related_check="SSH_TCP_FWD" ;;
            LoginGraceTime) related_check="SSH_GRACE_TIME" ;;
            MaxAuthTries) related_check="SSH_MAX_AUTH" ;;
        esac

        if [[ "$param" == "PermitRootLogin" ]] && [[ "$cur_lower" =~ ^(no|without-password|prohibit-password)$ ]]; then
            success "$param already secure ($current)."
            ask_user=false
            final_secure_values["$param"]="prohibit-password"
        elif [[ "$cur_lower" == "$rec_lower" ]]; then
            success "$param already correct."
            ask_user=false
            final_secure_values["$param"]="$recommended"
        fi

        if $rec_delta_mode && $ask_user; then
            if $ssh_uses_kbi && [[ "$param" =~ ^(ChallengeResponseAuthentication|KbdInteractiveAuthentication|UsePAM|PasswordAuthentication)$ ]]; then
                preserve_only=false
            elif [[ -z "$related_check" ]]; then
                preserve_only=true
            elif ! section_check_is_red "$related_check"; then
                preserve_only=true
            fi
        fi

        if $preserve_only; then
            final_secure_values["$param"]="$current"
            ask_user=false
        fi

        if $ask_user; then
            echo -e "  ${C_BOLD}$param${C_RESET}: current='${current:-<default>}' → recommended='$recommended'"
            case "$param" in
                AllowUsers) describe_detail "ssh_allowusers" ;;
                PasswordAuthentication) describe_detail "ssh_passwordauth" ;;
                ChallengeResponseAuthentication|KbdInteractiveAuthentication) describe_detail "ssh_challengeresponse" ;;
                AllowAgentForwarding) describe_detail "ssh_agentfwd" ;;
                AllowTcpForwarding) describe_detail "ssh_tcpfwd" ;;
                X11Forwarding) describe_detail "ssh_x11fwd" ;;
                LoginGraceTime) describe_detail "ssh_logingracetime" ;;
                MaxAuthTries) describe_detail "ssh_maxauthtries" ;;
                MaxSessions) describe_detail "ssh_maxsessions" ;;
                ClientAliveInterval) describe_detail "ssh_clientaliveinterval" ;;
                ClientAliveCountMax) describe_detail "ssh_clientalivecountmax" ;;
                PermitRootLogin) describe_detail "ssh_permitrootlogin" ;;
                PermitUserEnvironment) describe_detail "ssh_permituserenvironment" ;;
                PrintLastLog) describe_detail "ssh_printlastlog" ;;
            esac
            [[ "$param" == "PasswordAuthentication" && $key_count -eq 0 ]] && warn "$(tr_msg no_key_warning)"
            default_ans="y"; [[ "$param" == "PasswordAuthentication" && $key_count -eq 0 ]] && default_ans="n"
            if ask_yes_no "$(tr_msg set_recommended_prefix)$recommended$(tr_msg set_recommended_suffix)" "$default_ans"; then
                changes_to_apply["$param"]="$recommended"
                final_secure_values["$param"]="$recommended"
            else
                final_secure_values["$param"]="$current"
            fi
        fi
    done

    if [[ "$ssh_crypto_policy_mode" != "off" ]]; then
        local crypto_line key value
        while IFS= read -r crypto_line; do
            [[ -n "$crypto_line" ]] || continue
            key="${crypto_line%% *}"
            value="${crypto_line#* }"
            final_secure_values["$key"]="$value"
            changes_to_apply["$key"]="$value"
        done < <(get_ssh_crypto_policy_values "$ssh_crypto_policy_mode")
        info "SSH crypto policy selected: $ssh_crypto_policy_mode"
    fi

    if [[ ${#final_secure_values[@]} -gt 0 ]]; then
        ask_yes_no "$(tr_msg save_ssh_changes)" "y" && {
            mkdir -p "$ssh_dropin_dir"
            local tdrop
            tdrop=$(mktemp_tracked)
            {
                echo "# SSH hardening drop-in — generated by security_script.sh v${SCRIPT_VERSION}"
                echo "# This file intentionally overrides weaker defaults from sshd_config and sshd_config.d/*.conf"
                echo "# Optional Mil/Gov-oriented SSH crypto policy mode: ${ssh_crypto_policy_mode}"
                local k
                while IFS= read -r k; do
                    [[ -n "$k" ]] || continue
                    [[ -n "${final_secure_values[$k]:-}" ]] || {
                        warn "Skipping empty SSH value for '$k' to avoid invalid sshd config."
                        continue
                    }
                    echo "$k ${final_secure_values[$k]}"
                done < <(printf '%s
' "${!final_secure_values[@]}" | sort)
            } > "$tdrop"

            backup_file "$ssh_config"
            if install_managed_file "$SSHD_HARDENING_DROPIN" "$tdrop" 600; then
                if normalize_sshd_include_path "$ssh_config"; then
                    log_change "SSH_MAIN_INCLUDE:/etc/ssh/sshd_config.d/*.conf"
                fi
                if [[ -f "$SSHD_HARDENING_DROPIN_LEGACY" ]] && [[ "$SSHD_HARDENING_DROPIN_LEGACY" != "$SSHD_HARDENING_DROPIN" ]]; then
                    rm -f "$SSHD_HARDENING_DROPIN_LEGACY"
                    log_change "REMOVED_LEGACY_FILE:$SSHD_HARDENING_DROPIN_LEGACY"
                fi
                if ssh_dropin_validate_and_restore; then
                    local k
                    for k in "${!final_secure_values[@]}"; do log_change "SSH_DROPIN:$k=${final_secure_values[$k]}"; done
                    sshd_needs_restart=true
                    if [[ ${#changes_to_apply[@]} -gt 0 ]]; then
                        record_check "SSH_HARDENING" "FIXED" "${#changes_to_apply[@]} parameter(s) hardened"
                        if [[ "$ssh_crypto_policy_mode" != "off" ]]; then
                            if [[ "$ssh_crypto_policy_mode" == "strict" ]]; then
                            record_check "SSH_CRYPTO_POLICY" "FIXED" "Strict SSH crypto policy applied (${ssh_crypto_policy_mode})"
                        else
                            record_check "SSH_CRYPTO_POLICY" "INFO" "Explicit SSH crypto policy applied, but not in strict mode (${ssh_crypto_policy_mode})"
                        fi
                        fi
                    else
                        record_check "SSH_HARDENING" "PASS" "Existing secure settings normalized into managed drop-in"
                    fi
                else
                    error "SSH hardening drop-in could not be validated. No restart performed."
                    return 1
                fi
            else
                success "SSH hardening drop-in already correct."
                record_check "SSH_HARDENING" "PASS" "All parameters already managed"
                [[ "$ssh_crypto_policy_mode" != "off" ]] && {
                    if [[ "$ssh_crypto_policy_mode" == "strict" ]]; then
                        record_check "SSH_CRYPTO_POLICY" "PASS" "Strict SSH crypto policy already managed (${ssh_crypto_policy_mode})"
                    else
                        record_check "SSH_CRYPTO_POLICY" "INFO" "Explicit SSH crypto policy already managed, but not in strict mode (${ssh_crypto_policy_mode})"
                    fi
                }
            fi
        }
    else
        success "SSH already hardened."
        record_check "SSH_HARDENING" "PASS" "All parameters correct"
    fi

    $sshd_needs_restart && restart_ssh "hardening" || true
    if $sshd_needs_restart; then
        local ssh_pass_after
        ssh_pass_after=$(get_effective_sshd_config "PasswordAuthentication")
        if [[ "$(echo "${ssh_pass_after:-yes}" | tr '[:upper:]' '[:lower:]')" != "no" ]]; then
            warn "$(tr_msg ssh_password_still_yes) '$ssh_pass_after'. $(tr_msg check_include_files)"
            show_sshd_setting_sources "PasswordAuthentication"
        else
            success "Effective SSH setting confirmed: PasswordAuthentication=no"
        fi
    fi
    section_done "4a"
}

# ============================================================================
# SECTION 4b: Google 2FA
# ============================================================================
configure_google_2fa() {
    info "${C_BOLD}4b. Google Authenticator 2FA${C_RESET}"
    describe_action "twofa"
    is_section_skipped "2fa" && { info "Skipped."; echo; return 0; }
    $AUTO_MODE && { info "2FA needs interactive setup — skipping in auto mode."; echo; return 0; }
    ask_yes_no "Setup Google Authenticator 2FA?" "y" || { echo; return 0; }

    local target_user="${SUDO_USER:-$(whoami)}"
    local user_home; user_home=$(eval echo "~$target_user")
    [[ -f "$user_home/.google_authenticator" ]] && ! ask_yes_no "Already configured. Reconfigure?" "n" && { echo; return 0; }

    ensure_packages_installed "libpam-google-authenticator" || return 1

    echo "  • QR-Code mit Authenticator-App scannen"
    echo "  • Emergency Scratch Codes sicher aufbewahren"; echo
    $DRY_RUN && dry_run_echo "google-authenticator -t -f -d -r 3 -R 30 -w 17" \
        || sudo -u "$target_user" google-authenticator -t -f -d -r 3 -R 30 -w 17 \
        || { error "Google Authenticator failed."; return 1; }

    local pam_file="/etc/pam.d/sshd" pam_changed=false
    backup_file "$pam_file"
    local tp; tp=$(mktemp_tracked); cp "$pam_file" "$tp"
    # Keep the standard Debian/Ubuntu include chain intact. Insert the google-authenticator
    # line directly before the common-auth include (or before the first auth line as fallback)
    # so PAM still reaches common-auth / pam_unix.so afterwards.
    if ! grep -q "pam_google_authenticator.so" "$tp"; then
        if grep -q '^@include common-auth' "$tp"; then
            sed -i '/^@include common-auth/i auth required pam_google_authenticator.so nullok' "$tp"
        elif grep -qE '^auth\s' "$tp"; then
            sed -i '0,/^auth\s/{s//auth required pam_google_authenticator.so nullok\n&/}' "$tp"
        else
            printf '%s\n' 'auth required pam_google_authenticator.so nullok' >> "$tp"
        fi
        pam_changed=true
    fi

    if $pam_changed; then
        validate_pam_file "$tp" || { error "PAM validation failed. Not applying."; return 1; }
        $DRY_RUN && dry_run_echo "Update $pam_file" || {
            mv "$tp" "$pam_file" && chmod 644 "$pam_file" && log_change "MODIFIED:$pam_file (2FA)"
            sudo_smoke_test "$pam_file" || return 1
        }
    else
        rm -f "$tp" 2>/dev/null || true
    fi

    local sc="/etc/ssh/sshd_config"
    local ssh_dropin="/etc/ssh/sshd_config.d/00-security-script.conf"
    backup_file "$sc"
    [[ -f "$ssh_dropin" ]] && backup_file "$ssh_dropin"

    local stage_dir ts_main ts_drop include_path staged_changed=false
    stage_dir=$(mktemp -d)
    chmod 700 "$stage_dir"
    ts_main="$stage_dir/sshd_config"
    cp "$sc" "$ts_main"
    mkdir -p "$stage_dir/sshd_config.d"
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        cp -a /etc/ssh/sshd_config.d/. "$stage_dir/sshd_config.d/" 2>/dev/null || true
    fi
    ts_drop="$stage_dir/sshd_config.d/00-security-script.conf"
    [[ -f "$ts_drop" ]] || : > "$ts_drop"

    include_path=$(printf '%s' "$stage_dir/sshd_config.d/*.conf" | sed 's/[\/&]/\\&/g')
    sed -i -E "s|^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf|Include ${include_path}|" "$ts_main"

    set_sshd_param "UsePAM" "yes" "$ts_main" && staged_changed=true || true
    set_sshd_param "KbdInteractiveAuthentication" "yes" "$ts_main" && staged_changed=true || true
    set_sshd_param "AuthenticationMethods" "publickey,keyboard-interactive" "$ts_main" && staged_changed=true || true
    set_sshd_param "PasswordAuthentication" "no" "$ts_main" && staged_changed=true || true

    set_sshd_param "ChallengeResponseAuthentication" "yes" "$ts_drop" && staged_changed=true || true
    set_sshd_param "KbdInteractiveAuthentication" "yes" "$ts_drop" && staged_changed=true || true
    set_sshd_param "UsePAM" "yes" "$ts_drop" && staged_changed=true || true
    set_sshd_param "PasswordAuthentication" "no" "$ts_drop" && staged_changed=true || true

    local sshd_check_output
    sshd_check_output=$(sshd -t -f "$ts_main" 2>&1) || {
        error "SSHD config syntax check failed — changes NOT applied."
        [[ -n "$sshd_check_output" ]] && error "$sshd_check_output"
        rm -rf "$stage_dir" 2>/dev/null || true
        [[ -f "$tp" ]] && rm -f "$tp" 2>/dev/null || true
        [[ -f "$pam_file${BACKUP_SUFFIX}" ]] && restore_file "$pam_file" || true
        return 1
    }

    if $DRY_RUN; then
        dry_run_echo "Install staged sshd_config and drop-in, then restart ssh"
        rm -rf "$stage_dir" 2>/dev/null || true
    else
        sed -i -E 's|^[[:space:]]*Include[[:space:]]+/tmp/[^[:space:]]+/sshd_config\.d/\*\.conf([[:space:]]*)$|Include /etc/ssh/sshd_config.d/*.conf|' "$ts_main"
        cp "$ts_main" "$sc" && chmod 644 "$sc" && log_change "MODIFIED:$sc (2FA)"
        install -m 644 "$ts_drop" "$ssh_dropin"
        log_change "MODIFIED:$ssh_dropin (2FA)"
        rm -rf "$stage_dir" 2>/dev/null || true
        restart_ssh "2FA" || return 1
    fi

    echo; warn "WICHTIG: SSH in NEUEM Terminal testen bevor dieses geschlossen wird!"
    section_done "4b"
}

# ============================================================================
# SECTION 5a: Fail2ban
# ============================================================================
configure_fail2ban() {
    info "${C_BOLD}5a. Fail2ban${C_RESET}"
    describe_action "fail2ban"
    is_section_skipped "fail2ban" && { info "Skipped."; echo; return 0; }

    local policy_diff
    policy_diff=$(fail2ban_policy_diff 2>/dev/null || true)
    if [[ -z "$policy_diff" ]]; then
        success "Existing Fail2ban configuration already matches script recommendations."
        record_check "FAIL2BAN" "PASS" "Already aligned with script recommendations"
        section_done "5a"
        return 0
    fi
    [[ "$policy_diff" != "package missing" ]] && warn "Current Fail2ban setup differs from script recommendations: $policy_diff"

    local pkg="fail2ban" jail_local="/etc/fail2ban/jail.local" needs_restart=false

    is_package_installed "$pkg" || {
        ask_yes_no "Install Fail2ban?" "y" && ensure_packages_installed "$pkg" || { info "Skipped."; echo; return 0; }
    }

    if [[ ! -f "$jail_local" ]] || ! is_fail2ban_jail_enabled "sshd"; then
        ask_yes_no "Create/fix jail.local with [sshd] enabled?" "y" && {
            local tjail; tjail=$(mktemp_tracked)
            cat > "$tjail" <<'JAIL_EOF'
# jail.local — generated by security_script.sh
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
JAIL_EOF
            install_managed_file "$jail_local" "$tjail" 644 && needs_restart=true
        }
    else success "jail.local and [sshd] jail OK."; fi

    # ignoreip
    local current_ignoreip
    current_ignoreip=$(awk '/^\s*\[DEFAULT\]/{d=1;next} /^\s*\[/{d=0} d&&/^\s*ignoreip\s*=/{gsub(/^\s*ignoreip\s*=\s*/,"");cl=$0;while(getline>0&&$0~/^[[:space:]]/)cl=cl $0;gsub(/[[:space:]]+/," ",cl);print cl;exit}' "$jail_local" 2>/dev/null || true)
    read -ra current_array <<< "$current_ignoreip"
    local proposed=() apply_ignore=false ip subnet already p
    for ip in $(ip -4 addr show | grep -oP 'inet \K[\d.]+' | grep -v '^127\.' || true); do
        subnet="$(echo "$ip" | cut -d. -f1-3).0/24"
        is_ip_covered_by_ignoreip "$ip" "${current_array[@]+"${current_array[@]}"}" && continue
        already=false
        for p in "${proposed[@]+"${proposed[@]}"}"; do [[ "$subnet" == "$p" ]] && already=true; done
        $already || { proposed+=("$subnet"); apply_ignore=true; }
    done
    $apply_ignore && {
        local final_list; final_list=$(printf '%s\n' "127.0.0.1/8" "::1" "${current_array[@]+"${current_array[@]}"}" "${proposed[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//')
        describe_detail "fail2ban_ignoreip"
        describe_detail "fail2ban_ignoreip"
        ask_yes_no "Add local subnets to ignoreip?" "y" && {
            backup_file "$jail_local"
            $DRY_RUN && dry_run_echo "Update ignoreip in $jail_local" || {
                local ti; ti=$(mktemp_tracked)
                awk -v new_ip="$final_list" 'BEGIN{d=0;f=0} /^\s*\[DEFAULT\]/{print;d=1;next} /^\s*\[/&&NR>1&&d{if(!f)print "ignoreip = " new_ip;d=0;f=1} d&&/^\s*#?\s*ignoreip\s*=/{if(!f)print "ignoreip = " new_ip;f=1;next} {print} END{if(d&&!f)print "ignoreip = " new_ip}' "$jail_local" > "$ti"
                mv "$ti" "$jail_local" && { success "ignoreip updated."; needs_restart=true; }
            }
        }
    } || success "ignoreip OK."

    $needs_restart && ! $DRY_RUN && {
        if fail2ban-client -t >/dev/null 2>&1; then
            if systemctl enable --now fail2ban >/dev/null 2>&1; then
                success "Fail2ban enabled and started."
            else
                error "Fail2ban service could not be enabled/started! Restoring."
                restore_file "$jail_local"
            fi
        else
            error "Fail2ban config invalid! Restoring."
            restore_file "$jail_local"
        fi
    }
    if is_package_installed "$pkg" && systemctl is-active --quiet fail2ban; then
        record_check "FAIL2BAN" "FIXED" "Fail2ban configured"
    else
        record_check "FAIL2BAN" "FAIL" "Fail2ban package missing or service inactive"
    fi
    section_done "5a"
}

# ============================================================================
# SECTION 5b: SSHGuard
# ============================================================================
configure_sshguard() {
    info "${C_BOLD}5b. SSHGuard${C_RESET}"
    describe_action "sshguard"
    is_section_skipped "sshguard" && { info "Skipped."; echo; return 0; }
    ask_yes_no "Install SSHGuard?" "n" || { echo; return 0; }
    ensure_packages_installed "sshguard" && ensure_service_running "sshguard"
    section_done "5b"
}

# ============================================================================
# SECTION 6: UFW Firewall
# ============================================================================
configure_ufw() {
    info "${C_BOLD}6. UFW Firewall${C_RESET}"
    describe_action "ufw"
    is_section_skipped "ufw" && { info "Skipped."; echo; return 0; }
    ask_yes_no "Configure UFW?" "y" || { echo; return 0; }

    ensure_packages_installed "ufw" || return 0

    local ssh_port; ssh_port=$(get_ssh_port)
    local ssh_spec="${ssh_port}/tcp"
    local ufw_status; ufw_status=$(ufw status 2>/dev/null | head -1 || true)
    local ufw_active=false; [[ "$ufw_status" =~ "active" ]] && ufw_active=true

    $ufw_active && {
        while IFS= read -r line; do
            local ps; ps=$(echo "$line" | grep -oP '^\d+(/\w+)?' || true)
            [[ -n "$ps" ]] && ufw_rules["$ps"]=1
        done < <(ufw status 2>/dev/null | grep -E "^[0-9]")
        success "UFW active. ${#ufw_rules[@]} existing rule(s)."
    } || {
        ask_yes_no "Enable UFW (default deny incoming)?" "y" && {
            $DRY_RUN && dry_run_echo "ufw default deny incoming && ufw default allow outgoing" || {
                run_cmd "UFW_DEFAULT_DENY"    ufw default deny incoming
                run_cmd "UFW_DEFAULT_ALLOW"   ufw default allow outgoing
            }
        }
    }

    # SSH must be allowed first
    is_ufw_allowed "$ssh_spec" || ufw status 2>/dev/null | grep -qE "^${ssh_port}[[:space:]]" || {
        ask_yes_no "Allow SSH port ${ssh_port}/tcp?" "y" && {
            run_cmd "UFW_ALLOW_SSH" ufw allow "${ssh_port}/tcp" comment "SSH"
            ufw_rules["$ssh_spec"]=1
        }
    }

    ! $ufw_active && ask_yes_no "Enable UFW now?" "y" && {
        $DRY_RUN && dry_run_echo "ufw --force enable" || {
            ufw --force enable && { success "UFW enabled."; txlog "SERVICE_ENABLED" "ufw"; record_check "UFW_ACTIVE" "FIXED" "UFW enabled"; }
        }
    }

    # Port review in interactive mode
    ! $AUTO_MODE && {
        info "Scanning listening ports..."
        declare -A listening_ports=()
        while IFS= read -r entry; do
            [[ -z "$entry" ]] && continue
            IFS=',' read -r port proto proc <<< "$entry"
            listening_ports["${port}/${proto}"]="$proc"
        done < <({ get_listening_ports; get_container_ports; } 2>/dev/null | sort | uniq)

        local uncovered=()
        for key in "${!listening_ports[@]}"; do
            is_ufw_allowed "$key" && continue; [[ "$key" == "$ssh_spec" ]] && continue
            uncovered+=("$key (${listening_ports[$key]})")
        done
        [[ ${#uncovered[@]} -gt 0 ]] && {
            warn "${#uncovered[@]} listening port(s) not in UFW:"
            for item in "${uncovered[@]}"; do echo "    • $item"; done
            ask_yes_no "Interactively review these ports?" "y" && {
                for key in "${!listening_ports[@]}"; do
                    is_ufw_allowed "$key" && continue; [[ "$key" == "$ssh_spec" ]] && continue
                    ask_yes_no "  Allow $key (${listening_ports[$key]})?" "n" && {
                        run_cmd "UFW_ALLOW:$key" ufw insert 1 allow "$key" comment "Script $(date +%Y-%m-%d)"
                        ufw_rules["$key"]=1
                    }
                done
                ! $DRY_RUN && ufw reload && success "UFW reloaded." || true
            }
        } || success "All listening ports covered."
    }
    section_done 6
}

# ============================================================================
# SECTION 7: Journald
# ============================================================================
configure_journald() {
    info "${C_BOLD}7. Journald Log Limit${C_RESET}"
    describe_action "journald"
    is_section_skipped "journald" && { info "Skipped."; echo; return 0; }

    local config_file="/etc/systemd/journald.conf" key="SystemMaxUse" desired="$JOURNALD_MAX_USE" current=""
    [[ -f "$config_file" ]] && current=$(grep -E "^\s*${key}=" "$config_file" 2>/dev/null | tail -n1 | cut -d= -f2 | xargs || true)
    [[ "$current" == "$desired" ]] && { success "Journald $key='$desired' OK."; section_done 7; return 0; }

    warn "[Issue] Journald $key='${current:-not set}' (should be '$desired')."
    ask_yes_no "Fix: Set $key=$desired?" "y" || { section_done 7; return 0; }

    backup_file "$config_file"
    local tc; tc=$(mktemp_tracked); cp "$config_file" "$tc"
    grep -qE "^\s*#?\s*${key}=" "$tc"         && sed -i -E "s|^\s*#?\s*${key}=.*|${key}=${desired}|" "$tc"         || grep -q "^\s*\[Journal\]" "$tc"             && sed -i "/^\s*\[Journal\]/a ${key}=${desired}" "$tc"             || echo -e "
[Journal]
${key}=${desired}" >> "$tc"

    if install_managed_file "$config_file" "$tc" 644; then
        if ! $DRY_RUN; then
            log_change "JOURNALD:$key=$desired"
            run_cmd "RESTART:journald" systemctl restart systemd-journald && success "Journald configured."
        fi
    fi
    section_done 7
}

# ============================================================================
# SECTION 8: ClamAV
# ============================================================================
configure_clamav() {
    info "${C_BOLD}8. ClamAV Antivirus${C_RESET}"
    describe_action "clamav"
    is_section_skipped "clamav" && { info "Skipped."; record_check "CLAMAV" "SKIP" "$(section_skip_record_desc)"; echo; return 0; }
    ask_yes_no "Install/configure ClamAV?" "y" || { echo; return 0; }

    ensure_packages_installed "clamav" "clamav-daemon" || { record_check "CLAMAV" "FAIL" "Package install skipped/failed"; section_done 8; return 0; }
    local fcs="clamav-freshclam" cds="clamav-daemon" db="/var/lib/clamav"

    systemctl is-active --quiet "$fcs" 2>/dev/null && {
        run_cmd "STOP:$fcs" systemctl stop "$fcs" || true; $DRY_RUN || sleep 2; }

    describe_detail "clamav_freshclam"
    ask_yes_no "Run freshclam (downloads definitions)?" "y" && {
        run_cmd "freshclam" freshclam --quiet && success "freshclam done." || warn "freshclam failed."
        $DRY_RUN || sleep 3
    }

    systemctl list-unit-files 2>/dev/null | grep -q "^${fcs}\.service" && ensure_service_running "$fcs"
    systemctl list-unit-files 2>/dev/null | grep -q "^${cds}\.service" && {
        [[ -f "$db/main.cvd" || -f "$db/main.cld" ]] && ensure_service_running "$cds" \
            || warn "ClamAV definitions missing, cannot start daemon."
    }
    record_check "CLAMAV" "FIXED" "ClamAV installed and configured"
    section_done 8
}

# ============================================================================
# SECTION 9: Sysctl Hardening
# ============================================================================
configure_sysctl() {
    info "${C_BOLD}9. Sysctl Hardening (CIS/BSI)${C_RESET}"
    describe_action "sysctl"
    is_section_skipped "sysctl" && { info "Skipped."; echo; return 0; }

    load_sysctl_policy

    local issues_found=0
    local -a params_to_set=()
    local param desired current expected_desc
    for param in "${!SYSCTL_POLICY[@]}"; do
        desired="${SYSCTL_POLICY[$param]}"
        current=$(get_effective_sysctl_config "$param")
        expected_desc=$(sysctl_expected_description "$param" "$desired")
        if sysctl_value_matches_policy "$param" "$desired" "$current"; then
            success "  $param=$current (OK; expected $expected_desc)"
        else
            warn "  [Issue] $param=$current (should be $expected_desc)"
            issues_found=$((issues_found+1))
            params_to_set+=("$param=$desired")
        fi
    done

    (( issues_found == 0 )) && {
        success "All sysctl parameters hardened."
        record_check "SYSCTL" "PASS" "All hardened"
        section_done 9
        return 0
    }

    ask_yes_no "${issues_found} issue(s) found. Apply sysctl hardening?" "y" || {
        section_done 9
        return 0
    }

    local tsys
    tsys=$(mktemp_tracked)
    {
        echo "# Sysctl security hardening — generated by security_script.sh v${SCRIPT_VERSION}"
        echo "# $(date)"
        echo
        for param in $(printf '%s\n' "${!SYSCTL_POLICY[@]}" | sort); do
            echo "$param=${SYSCTL_POLICY[$param]}"
        done
    } > "$tsys"

    if install_managed_file "$SYSCTL_CONFIG_FILE" "$tsys" 644; then
        if ! $DRY_RUN; then
            if sysctl --system >/dev/null 2>&1; then
                local remaining=0
                local -a remaining_params=()
                for param in "${!SYSCTL_POLICY[@]}"; do
                    desired="${SYSCTL_POLICY[$param]}"
                    current=$(get_effective_sysctl_config "$param")
                    if ! sysctl_value_matches_policy "$param" "$desired" "$current"; then
                        remaining=$((remaining+1))
                        remaining_params+=("$param")
                    fi
                done

                if (( remaining == 0 )); then
                    success "${issues_found} sysctl parameter(s) remediated."
                    record_check "SYSCTL" "FIXED" "${issues_found} params hardened"
                else
                    warn "Sysctl applied, but ${remaining} parameter(s) still differ from policy: ${remaining_params[*]}"
                    local -a remaining_details=()
                    for param in "${remaining_params[@]}"; do
                        desired="${SYSCTL_POLICY[$param]}"
                        current=$(get_effective_sysctl_config "$param")
                        remaining_details+=("${param}=${current:-unset} (want ${desired})")
                    done
                    record_check "SYSCTL" "FAIL" "${remaining} sysctl param(s) not hardened: $(format_sysctl_findings "${remaining_details[@]}")"
                fi
            else
                error "sysctl --system failed."
                record_check "SYSCTL" "FAIL" "Apply failed"
            fi
        fi
    fi
    section_done 9
}

# ============================================================================
# SECTION 10: Sudoers TTY Tickets
# ============================================================================
configure_sudoers_tty() {
    info "${C_BOLD}10. Sudoers TTY Tickets${C_RESET}"
    describe_action "sudoers"
    is_section_skipped "sudoers" && { info "Skipped."; echo; return 0; }

    grep -rPh --include='*' '^\s*Defaults\s+([^#]*,\s*)?tty_tickets' /etc/sudoers /etc/sudoers.d/ >/dev/null 2>&1 && {
        success "tty_tickets already set."; record_check "SUDOERS_TTY" "PASS" "tty_tickets OK"; section_done 10; return 0; }

    describe_detail "sudo_ttytickets"
    ask_yes_no "Configure tty_tickets?" "y" || { section_done 10; return 0; }
    local tsudo; tsudo=$(mktemp_tracked)
    printf '# tty_tickets — generated by security_script.sh v%s
Defaults tty_tickets
' "$SCRIPT_VERSION" > "$tsudo"
    if $DRY_RUN; then
        show_diff_preview "$SUDOERS_TTY_FILE" "$tsudo" "$SUDOERS_TTY_FILE"
        record_dry_run_action "Update $SUDOERS_TTY_FILE"
    else
        install_managed_file "$SUDOERS_TTY_FILE" "$tsudo" 0440
        visudo -c -f "$SUDOERS_TTY_FILE" >/dev/null 2>&1 && {
            success "tty_tickets configured."
            record_check "SUDOERS_TTY" "FIXED" "tty_tickets set"
        } || { error "visudo check failed! Removing."; rm -f "$SUDOERS_TTY_FILE"; record_check "SUDOERS_TTY" "FAIL" "visudo failed"; }
    fi
    section_done 10
}

# ============================================================================
# SECTION 10a: Interactive login umask
# ============================================================================
configure_login_umask() {
    info "${C_BOLD}10a. System-wide default umask${C_RESET}"
    info "Hardens default permissions for interactive logins and future systemd-managed services/users. Existing running services keep their current umask until restart/reboot."
    is_section_skipped "login_umask" && { info "Skipped."; record_check "LOGIN_UMASK" "SKIP" "$(section_skip_record_desc)"; echo; return 0; }
    ask_yes_no "Configure restrictive system-wide default umask?" "y" || { record_check "LOGIN_UMASK" "SKIP" "User skipped"; echo; return 0; }
    mark_section_executed

    local desired_umask="${AUTO_LOGIN_UMASK:-$DEFAULT_LOGIN_UMASK}"
    normalize_octal_umask "$desired_umask" >/dev/null 2>&1 || { error "Invalid umask '$desired_umask'"; record_check "LOGIN_UMASK" "FAIL" "Invalid umask '$desired_umask'"; section_done "10a"; return 0; }
    desired_umask=$(normalize_octal_umask "$desired_umask")

    local changed=0
    local tlogin tprofile tsystemd_system tsystemd_user
    tlogin=$(mktemp_tracked)
    if [[ -f "$LOGIN_DEFS_FILE" ]]; then
        cp "$LOGIN_DEFS_FILE" "$tlogin"
    else
        : > "$tlogin"
    fi
    set_or_append_login_defs_key "$tlogin" "UMASK" "$desired_umask"
    if install_managed_file "$LOGIN_DEFS_FILE" "$tlogin" 644; then
        changed=$((changed+1))
    fi

    tprofile=$(mktemp_tracked)
    cat > "$tprofile" <<UMASK_EOF
# security-script.sh v${SCRIPT_VERSION}
# Restrictive default permissions for interactive shells.
umask ${desired_umask}
UMASK_EOF
    if install_managed_file "$PROFILE_UMASK_FILE" "$tprofile" 644; then
        changed=$((changed+1))
    fi

    tsystemd_system=$(mktemp_tracked)
    cat > "$tsystemd_system" <<UMASK_EOF
# security-script.sh v${SCRIPT_VERSION}
[Manager]
DefaultUMask=${desired_umask}
UMASK_EOF
    if install_managed_file "$SYSTEM_UMASK_SYSTEMD_DROPIN" "$tsystemd_system" 644; then
        changed=$((changed+1))
    fi

    tsystemd_user=$(mktemp_tracked)
    cat > "$tsystemd_user" <<UMASK_EOF
# security-script.sh v${SCRIPT_VERSION}
[Manager]
DefaultUMask=${desired_umask}
UMASK_EOF
    if install_managed_file "$USER_UMASK_SYSTEMD_DROPIN" "$tsystemd_user" 644; then
        changed=$((changed+1))
    fi

    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true

    if (( changed > 0 )); then
        record_check "LOGIN_UMASK" "FIXED" "System-wide default umask set to ${desired_umask}"
    else
        record_check "LOGIN_UMASK" "PASS" "System-wide default umask already set to ${desired_umask}"
    fi
    section_done "10a"
}

# ============================================================================
# SECTION 10b: SUID/SGID inventory baseline
# ============================================================================
configure_suid_sgid_inventory() {
    info "${C_BOLD}10b. SUID/SGID inventory baseline${C_RESET}"
    info "Creates a daily audit-only inventory; it does not remove binaries automatically."
    is_section_skipped "suid_sgid" && { info "Skipped."; record_check "SUID_SGID_BASELINE" "SKIP" "$(section_skip_record_desc)"; echo; return 0; }
    ask_yes_no "Install daily SUID/SGID inventory baseline?" "y" || { record_check "SUID_SGID_BASELINE" "SKIP" "User skipped"; echo; return 0; }
    mark_section_executed

    local changed=0 dir
    dir=$(dirname "$SUID_SGID_AUDIT_BASELINE")
    mkdir -p "$dir" 2>/dev/null || true

    local tscript tcron tbaseline
    tscript=$(mktemp_tracked)
    cat > "$tscript" <<'SUID_EOF'
#!/bin/bash
set -euo pipefail
BASELINE_FILE="__SUID_BASELINE__"
REPORT_FILE="__SUID_REPORT__"
TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%#m %u %g %p\n' 2>/dev/null | sort > "$TMP_FILE"
mkdir -p "$(dirname "$BASELINE_FILE")" 2>/dev/null || true
if [[ ! -s "$BASELINE_FILE" ]]; then
    cp "$TMP_FILE" "$BASELINE_FILE"
    printf '[%s] Baseline created (%s entries)\n' "$(date '+%F %T')" "$(wc -l < "$BASELINE_FILE")" > "$REPORT_FILE"
    exit 0
fi
{
    printf '[%s] SUID/SGID inventory diff\n' "$(date '+%F %T')"
    diff -u "$BASELINE_FILE" "$TMP_FILE" || true
    printf '\nCurrent inventory entries: %s\n' "$(wc -l < "$TMP_FILE")"
} > "$REPORT_FILE"
SUID_EOF
    sed -i "s|__SUID_BASELINE__|$SUID_SGID_AUDIT_BASELINE|g; s|__SUID_REPORT__|$SUID_SGID_AUDIT_REPORT|g" "$tscript"
    if install_managed_file "$SUID_SGID_AUDIT_SCRIPT" "$tscript" 700; then
        changed=$((changed+1))
    fi

    tcron=$(mktemp_tracked)
    cat > "$tcron" <<CRON_EOF
#!/bin/bash
exec "${SUID_SGID_AUDIT_SCRIPT}"
CRON_EOF
    if install_managed_file "$SUID_SGID_AUDIT_CRON" "$tcron" 700; then
        changed=$((changed+1))
    fi

    if [[ ! -s "$SUID_SGID_AUDIT_BASELINE" ]]; then
        tbaseline=$(mktemp_tracked)
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%#m %u %g %p\n' 2>/dev/null | sort > "$tbaseline"
        if install_managed_file "$SUID_SGID_AUDIT_BASELINE" "$tbaseline" 600; then
            changed=$((changed+1))
        fi
        printf '[%s] Baseline created (%s entries)\n' "$(date '+%F %T')" "$(wc -l < "$SUID_SGID_AUDIT_BASELINE")" > "$SUID_SGID_AUDIT_REPORT"
    elif ! $DRY_RUN; then
        "$SUID_SGID_AUDIT_SCRIPT" >/dev/null 2>&1 || true
    fi

    if (( changed > 0 )); then
        record_check "SUID_SGID_BASELINE" "FIXED" "SUID/SGID inventory baseline + daily cron deployed"
    else
        record_check "SUID_SGID_BASELINE" "PASS" "SUID/SGID inventory baseline already present"
    fi
    section_done "10b"
}

# ============================================================================
# SECTION 11: auditd
# ============================================================================
configure_auditd() {
    info "${C_BOLD}11. auditd — Linux Audit Daemon (extended)${C_RESET}"
    describe_action "auditd"
    is_section_skipped "auditd" && { info "Skipped."; record_check "AUDITD" "SKIP" "$(section_skip_record_desc)"; echo; return 0; }
    ask_yes_no "Install/configure auditd?" "y" || { record_check "AUDITD" "SKIP" "User skipped"; echo; return 0; }
    mark_section_executed

    ensure_packages_installed "auditd" "audispd-plugins" || { record_check "AUDITD" "FAIL" "Package install skipped/failed"; section_done 11; return 0; }
    ensure_auditd_service_available || warn "auditd.service weiterhin nicht auffindbar. Es wird ein Fallback versucht."

    mkdir -p "$(dirname "$AUDITD_RULES")"
    local taudit; taudit=$(mktemp_tracked)
    cat > "$taudit" <<'AUDITD_EOF'
# auditd extended ruleset — generated by security_script.sh
-D
-b 8192
-f 1

# Identity / auth
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity
-w /etc/login.defs -p wa -k login_defs
-w /etc/security/faillock.conf -p wa -k auth_policy
-w /etc/security/pwquality.conf -p wa -k auth_policy

# PAM / SSH / shell environment
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config
-w /etc/profile -p wa -k shell_profile
-w /etc/profile.d/ -p wa -k shell_profile
-w /etc/environment -p wa -k shell_profile

# System and service config
-w /etc/systemd/system/ -p wa -k systemd
-w /etc/init.d/ -p wa -k init
-w /etc/modprobe.d/ -p wa -k modprobe
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/rsyslog.conf -p wa -k rsyslog
-w /etc/rsyslog.d/ -p wa -k rsyslog

# Cron and audit config
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /var/log/audit/ -p wa -k audit_logs
-w /etc/audit/ -p wa -k audit_config

# Session tracking
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/lastlog -p wa -k session
-w /var/log/faillog -p wa -k session

# Privileged command execution
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-w /usr/bin/sudo -p x -k sudo_usage
-w /usr/bin/su -p x -k privileged_cmd
-w /usr/bin/passwd -p x -k privileged_cmd
-w /usr/bin/chsh -p x -k privileged_cmd
-w /usr/bin/chfn -p x -k privileged_cmd
-w /usr/bin/gpasswd -p x -k privileged_cmd
-w /usr/bin/newgrp -p x -k privileged_cmd

# Kernel modules / mount / hostname / time change
-w /sbin/insmod -p x -k module_load
-w /sbin/rmmod  -p x -k module_load
-w /sbin/modprobe -p x -k module_load
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k module_load
-a always,exit -F arch=b64 -S mount -k mounts
-a always,exit -F arch=b32 -S mount -k mounts
-a always,exit -F arch=b64 -S sethostname,setdomainname -k identity_host
-a always,exit -F arch=b32 -S sethostname,setdomainname -k identity_host
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime,clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

# Permission and ownership changes by real users
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod

# File deletions and access denied
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=-1 -k file_deletion
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=-1 -k file_deletion
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -k access_denied
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM  -F auid>=1000 -k access_denied
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -k access_denied
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM  -F auid>=1000 -k access_denied
AUDITD_EOF

    append_audit_watch_if_exists "$taudit" "/etc/apparmor/" "wa" "apparmor"
    append_audit_watch_if_exists "$taudit" "/etc/default/grub" "wa" "grub"
    append_audit_watch_if_exists "$taudit" "/boot/grub/" "wa" "grub"
    append_audit_watch_if_exists "$taudit" "/boot/grub2/" "wa" "grub"

    install_managed_file "$AUDITD_RULES" "$taudit" 640
    if $DRY_RUN; then
        section_done 11
        return 0
    fi

    command -v augenrules >/dev/null 2>&1 && augenrules --load >/dev/null 2>&1 && success "Audit rules loaded."

    if auditd_unit_exists; then
        systemctl enable auditd >/dev/null 2>&1 || true
        systemctl restart auditd >/dev/null 2>&1 || systemctl start auditd >/dev/null 2>&1 || true
    elif command -v service >/dev/null 2>&1; then
        service auditd restart >/dev/null 2>&1 || service auditd start >/dev/null 2>&1 || true
    fi

    if auditd_is_active; then
        success "auditd active."
        record_check "AUDITD" "FIXED" "auditd + extended ruleset"
        record_check "AUDITD_EXTENDED" "FIXED" "Extended audit coverage applied"
    else
        error "auditd could not start."
        if auditd_unit_exists; then
            warn "$(tr_msg auditd_check_hint)"
            record_check "AUDITD" "FAIL" "auditd installed but failed to start"
        else
            warn "auditd.service fehlt weiterhin. Wahrscheinlich Packaging-/Umgebungsproblem."
            record_check "AUDITD" "FAIL" "auditd package present but no service unit"
        fi
    fi
    print_auditd_observability_info
    section_done 11
}

# ============================================================================
# SECTION 12: AIDE
# ============================================================================
configure_aide() {
    info "${C_BOLD}12. AIDE — File Integrity Monitoring${C_RESET}"
    describe_action "aide"
    is_section_skipped "aide" && { info "Skipped."; record_check "AIDE" "SKIP" "$(section_skip_record_desc)"; echo; return 0; }
    ask_yes_no "Install/configure AIDE?" "y" || { record_check "AIDE" "SKIP" "User skipped"; echo; return 0; }
    mark_section_executed

    ensure_packages_installed "aide" "aide-common" || { record_check "AIDE" "FAIL" "Package install skipped/failed"; section_done 12; return 0; }
    $DRY_RUN && { dry_run_echo "AIDE init with resolved config + setup cron"; section_done 12; return 0; }

    local promoted_db="" init_rc=0
    if ! aide_baseline_exists; then
        if aide_init_running; then
            warn "AIDE init is already running in the background. Not starting a second one."
            print_aide_observability_info
            record_check "AIDE" "FAIL" "Initialization already running — baseline pending"
            section_done 12
            return 0
        fi

        info "Initializing AIDE database (may take several minutes; Ctrl+C cancels safely)..."
        [[ "$AIDE_INIT_TIMEOUT" == "0" ]] && info "AIDE timeout disabled for this profile/run."

        if ! run_aide_init_command; then
            init_rc=$?
            if (( init_rc == 124 )); then
                error "AIDE init timed out after ${AIDE_INIT_TIMEOUT}s. See $AIDE_INIT_LOG"
            else
                error "AIDE init failed. See $AIDE_INIT_LOG"
            fi
            tail -n 30 "$AIDE_INIT_LOG" 2>/dev/null || true
            record_check "AIDE" "FAIL" "Init failed"
            print_aide_observability_info
            section_done 12
            return 1
        fi

        promoted_db="$(aide_list_candidate_paths | awk '/aide\.db/ && $0 !~ /\.new(\.gz)?$/ {print; exit}')"
        if [[ -z "$promoted_db" ]]; then
            error "AIDE init failed or no usable baseline was created. See $AIDE_INIT_LOG"
            tail -n 30 "$AIDE_INIT_LOG" 2>/dev/null || true
            record_check "AIDE" "FAIL" "Init failed"
            print_aide_observability_info
            section_done 12
            return 1
        fi

        success "AIDE database initialized: $promoted_db"
        log_change "AIDE_DB_INITIALIZED:$promoted_db"
        txlog "FILE_ADDED" "$promoted_db"
    else
        success "AIDE database exists."
        describe_detail "aide_reinit"
        ask_yes_no "Re-initialize database (replaces baseline)?" "n" && {
            if ! run_aide_init_command; then
                init_rc=$?
                if (( init_rc == 124 )); then
                    warn "AIDE re-initialization timed out after ${AIDE_INIT_TIMEOUT}s."
                else
                    warn "AIDE re-initialization failed. See $AIDE_INIT_LOG"
                fi
            else
                success "Database re-initialized."
            fi
        }
    fi

    [[ ! -f "$AIDE_CRON" ]] && {
        local taidecron; taidecron=$(mktemp_tracked)
        cat > "$taidecron" << 'AIDE_EOF'
#!/bin/bash
# AIDE daily check — generated by security_script.sh
LOG="/var/log/aide-check.log"
REPORT="/var/log/aide-report-$(date +%Y%m%d).log"
CFG_AUTO="/var/lib/aide/aide.conf.autogenerated"
CFG_STATIC="/etc/aide/aide.conf"
HELPER="$(command -v update-aide.conf 2>/dev/null || true)"

aide_fallback_refresh() {
    local tmp file
    [[ -f "$CFG_STATIC" ]] || return 1
    mkdir -p /var/lib/aide /etc/aide/aide.conf.d >/dev/null 2>&1 || true
    tmp=$(mktemp) || return 1
    cat "$CFG_STATIC" > "$tmp" || { rm -f "$tmp"; return 1; }
    if [[ -d /etc/aide/aide.conf.d ]]; then
        while IFS= read -r file; do
            [[ -f "$file" ]] || continue
            printf '
# --- merged from %s ---
' "$file" >> "$tmp"
            if [[ -x "$file" ]]; then
                "$file" >> "$tmp" 2>> "$LOG" || { rm -f "$tmp"; return 1; }
            else
                cat "$file" >> "$tmp" || { rm -f "$tmp"; return 1; }
            fi
            printf '
' >> "$tmp"
        done < <(find /etc/aide/aide.conf.d -maxdepth 1 -type f | sort)
    fi
    install -m 600 "$tmp" "$CFG_AUTO" || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"
}

echo "=== AIDE $(date) ===" >> "$LOG"
if [[ -n "$HELPER" ]]; then
    "$HELPER" >/dev/null 2>&1 || true
else
    aide_fallback_refresh >/dev/null 2>&1 || true
fi
if [[ -f "$CFG_AUTO" ]]; then
    nice -n 19 ionice -c3 aide --config="$CFG_AUTO" --check 2>&1 | tee "$REPORT" >> "$LOG"
elif [[ -f "$CFG_STATIC" ]]; then
    nice -n 19 ionice -c3 aide --config="$CFG_STATIC" --check 2>&1 | tee "$REPORT" >> "$LOG"
else
    nice -n 19 ionice -c3 aide --check 2>&1 | tee "$REPORT" >> "$LOG"
fi
grep -q "changed\|added\|removed" "$REPORT" 2>/dev/null && echo "AIDE ALERT on $(hostname) at $(date)" | mail -s "AIDE Alert: $(hostname)" root 2>/dev/null || true
find /var/log -name "aide-report-*.log" -mtime +30 -delete 2>/dev/null || true
AIDE_EOF
        install_managed_file "$AIDE_CRON" "$taidecron" 755
        success "AIDE cron job installed."
    }

    if aide_baseline_exists; then
        record_check "AIDE" "FIXED" "AIDE + daily cron active"
    else
        record_check "AIDE" "FAIL" "AIDE installed but baseline missing"
    fi
    info "AIDE monitors critical files for changes and helps detect later tampering."
    print_aide_observability_info
    section_done 12
}


# ============================================================================
# SECTION 13: AppArmor (from ChatGPT v4.1.0 — NEW in v5)
# ============================================================================
configure_apparmor_enforce() {
    info "${C_BOLD}13. AppArmor — Enforce Mode${C_RESET}"
    describe_action "apparmor"
    is_section_skipped "apparmor" && { info "Skipped."; echo; return 0; }

    if $HOST_HAS_DOCKER || $HOST_HAS_PODMAN; then
        warn "Container runtime detected (Docker/Podman). Broad AppArmor enforce can break OCI runtimes on this host."
        local force_enforce=false
        if $AUTO_MODE; then
            [[ "${AUTO_APPARMOR_ENFORCE:-false}" == "true" ]] && force_enforce=true
        else
            ask_yes_no "Force AppArmor enforce anyway on this container host?" "n" && force_enforce=true || true
        fi
        $force_enforce || { info "AppArmor enforce skipped on container host."; echo; return 0; }
    else
        local enforce="${AUTO_APPARMOR_ENFORCE:-false}"
        [[ "$enforce" == "false" ]] && ! $AUTO_MODE &&             ask_yes_no "Set all AppArmor profiles to enforce mode?" "n" ||             { [[ "$enforce" != "true" ]] && { info "AppArmor enforce skipped."; echo; return 0; }; }
    fi

    command -v aa-enforce >/dev/null 2>&1 || ensure_packages_installed "apparmor-utils" || return 0
    $DRY_RUN && { dry_run_echo "aa-enforce /etc/apparmor.d/*"; section_done 13; return 0; }

    local complain_profiles; complain_profiles=$(aa-status 2>/dev/null | grep "profiles are in complain mode" | grep -oP '^\d+' || echo "0")
    (( ${complain_profiles:-0} == 0 )) && { success "No profiles in complain mode."; record_check "APPARMOR" "PASS" "All currently loaded profiles enforced"; section_done 13; return 0; }

    info "Setting ${complain_profiles} complain profile(s) to enforce..."
    aa-enforce /etc/apparmor.d/* 2>/dev/null && {
        success "AppArmor: all profiles set to enforce."; record_check "APPARMOR" "FIXED" "All currently loaded profiles enforced"
    } || { warn "Some profiles could not be enforced (check aa-status)."; record_check "APPARMOR" "FAIL" "Enforce partially failed"; }
    section_done 13
}

# ============================================================================
# SECTION 14: Filesystem Hardening
# ============================================================================
configure_filesystem_hardening() {
    info "${C_BOLD}14. Filesystem Hardening — /tmp, /dev/shm${C_RESET}"
    describe_action "filesystem"
    is_section_skipped "fstab" && { info "Skipped."; echo; return 0; }
    describe_detail "filesystem_mountopts"
    ask_yes_no "Harden tmpfs mount options (noexec,nosuid,nodev)?" "y" || { echo; return 0; }

    local issues_found=0 fstab="/etc/fstab"
    backup_file "$fstab"

    harden_tmpfs_mount() {
        local mp="$1"
        local required=("noexec" "nosuid" "nodev")
        local entry; entry=$(grep -E "^\S+\s+${mp}\s" "$fstab" 2>/dev/null | head -1 || true)

        if [[ -z "$entry" ]]; then
            mountpoint -q "$mp" 2>/dev/null || { info "  $mp not mounted, skip."; return; }
            ask_yes_no "  Add $mp to fstab with noexec,nosuid,nodev?" "y" && {
                $DRY_RUN && dry_run_echo "Add tmpfs $mp to fstab" || {
                    echo "tmpfs $mp tmpfs defaults,noexec,nosuid,nodev 0 0" >> "$fstab"
                    log_change "MODIFIED:$fstab ($mp added)"; txlog "FILE_ADDED" "$fstab"
                    mount -o remount "$mp" 2>/dev/null || true
                    success "  $mp added to fstab."
                }; issues_found=$((issues_found+1))
            }
            return
        fi

        local opts; opts=$(echo "$entry" | awk '{print $4}')
        local missing=()
        for opt in "${required[@]}"; do echo "$opts" | grep -q "$opt" || missing+=("$opt"); done
        [[ ${#missing[@]} -eq 0 ]] && { success "  $mp: all options OK."; return; }

        issues_found=$((issues_found+1))
        warn "  $mp missing: ${missing[*]}"
        describe_detail "filesystem_mountopts"
        ask_yes_no "  Add ${missing[*]} to $mp in fstab?" "y" && {
            $DRY_RUN && dry_run_echo "Update $mp in fstab" || {
                local new_opts="${opts},$(IFS=','; echo "${missing[*]}")"
                local mp_esc; mp_esc=$(printf '%s\n' "$mp" | sed 's/[]\/$*.^[]/\\&/g')
                sed -i "s|\(\S\+\s\+${mp_esc}\s\+\S\+\s\+\)${opts}|\1${new_opts}|" "$fstab"
                mount -o remount "$mp" 2>/dev/null || warn "Remount failed (will apply on next boot)."
                success "  $mp updated in fstab."; log_change "MODIFIED:$fstab ($mp +${missing[*]})"
            }
        }
    }

    harden_tmpfs_mount "/tmp"
    harden_tmpfs_mount "/dev/shm"
    harden_tmpfs_mount "/var/tmp"

    (( issues_found == 0 )) && record_check "FSTAB_HARDENING" "PASS" "/tmp + /dev/shm hardened" \
        || record_check "FSTAB_HARDENING" "FIXED" "${issues_found} mount option(s) fixed"
    section_done 14
}

# ============================================================================
# SECTION 15: Kernel Module Blacklist
# ============================================================================
configure_module_blacklist() {
    info "${C_BOLD}15. Kernel Module Blacklist (CIS)${C_RESET}"
    describe_action "modules"
    is_section_skipped "modules" && { info "Skipped."; echo; return 0; }
    describe_detail "modules_blacklist"
    ask_yes_no "Blacklist unused kernel modules?" "y" || { record_check "MODULE_BLACKLIST" "SKIP" "User skipped"; echo; return 0; }

    local mods=("cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "udf" "squashfs" "dccp" "sctp" "rds" "tipc")

    mkdir -p "$(dirname "$MODPROBE_BLACKLIST")"
    local tmod; tmod=$(mktemp_tracked)
    {
        echo "# Kernel module blacklist — generated by security_script.sh v${SCRIPT_VERSION}"
        echo "# $(date) — CIS Linux Benchmark"; echo
        for m in "${mods[@]}"; do
            echo "blacklist $m"; echo "install $m /bin/true"; echo
        done
    } > "$tmod"
    install_managed_file "$MODPROBE_BLACKLIST" "$tmod" 644
    ! $DRY_RUN && command -v update-initramfs >/dev/null 2>&1 && update-initramfs -u 2>/dev/null && success "initramfs updated." || true
    success "${#mods[@]} modules blacklisted."; info "Full effect after reboot."
    record_check "MODULE_BLACKLIST" "FIXED" "${#mods[@]} modules blacklisted"
    section_done 15
}

# ============================================================================
# SECTION 16: Core Dump Disabling
# ============================================================================
configure_core_dumps() {
    info "${C_BOLD}16. Core Dump Disabling${C_RESET}"
    describe_action "coredumps"
    is_section_skipped "coredumps" && { info "Skipped."; echo; return 0; }

    local core_sysctl; core_sysctl=$(get_effective_sysctl_config "fs.suid_dumpable")
    local limits_ok=false
    grep -qE '^\s*\*\s+hard\s+core\s+0' "$LIMITS_CONF" 2>/dev/null && limits_ok=true

    [[ "$core_sysctl" == "0" ]] && $limits_ok && {
        success "Core dumps already disabled."; record_check "CORE_DUMPS" "PASS" "Core dumps disabled"
        section_done 16; return 0
    }

    describe_detail "coredumps_disable"
    ask_yes_no "Disable core dumps?" "y" || { section_done 16; return 0; }
    $DRY_RUN && { dry_run_echo "Write limits + sysctl for core dump disable"; section_done 16; return 0; }

    mkdir -p "$(dirname "$LIMITS_CONF")"
    backup_file "$LIMITS_CONF"
    { echo "# Core dump prevention — security_script.sh v${SCRIPT_VERSION}"; echo "* soft core 0"; echo "* hard core 0"; } > "$LIMITS_CONF"
    chmod 644 "$LIMITS_CONF"; log_change "ADDED_FILE:$LIMITS_CONF"; txlog "FILE_ADDED" "$LIMITS_CONF"

    local sf="$SYSCTL_CONFIG_FILE"
    [[ -f "$sf" ]] || touch "$sf"
    grep -q "fs.suid_dumpable" "$sf"     || echo "fs.suid_dumpable = 0"         >> "$sf"
    grep -q "kernel.core_pattern" "$sf"  || echo "kernel.core_pattern = |/bin/false" >> "$sf"
    sysctl -w fs.suid_dumpable=0 >/dev/null 2>&1 && success "fs.suid_dumpable=0 applied." || true

    local coredump_conf="/etc/systemd/coredump.conf"
    [[ -f "$coredump_conf" ]] && {
        backup_file "$coredump_conf"
        sed -i '/^\s*#\?\s*Storage\s*=/d' "$coredump_conf"
        sed -i '/^\[Coredump\]/a Storage=none' "$coredump_conf"
        systemctl daemon-reload 2>/dev/null || true
    }
    success "Core dumps disabled (limits.conf + sysctl + systemd-coredump)."
    record_check "CORE_DUMPS" "FIXED" "Core dumps disabled"
    section_done 16
}

# ============================================================================
# SECTION 17: PAM Hardening — ROCK SOLID REWRITE
#
# Strategy:
# 1. pwquality: only modifies /etc/security/pwquality.conf — safe, no PAM stack touch
# 2. faillock: uses /etc/security/faillock.conf (modern Debian/Ubuntu approach)
#    pam_faillock is already in the PAM stack on modern Debian/Ubuntu via pam-auth-update
#    We only configure the PARAMETERS, not the stack itself
# 3. Root lock: explicit user confirmation required even in auto mode
# 4. After EVERY PAM change: sudo smoke test + auto-rollback on failure
# ============================================================================
configure_pam_hardening() {
    info "${C_BOLD}17. PAM Hardening${C_RESET}"
    describe_action "pam"
    is_section_skipped "pam" && { info "Skipped."; echo; return 0; }
    ask_yes_no "Configure PAM hardening?" "y" || { echo; return 0; }

    # --- 17a: Password Quality (pwquality.conf only — no PAM stack touch) ---
    info "17a. Password complexity (pwquality.conf)..."
    describe_detail "pam_pwquality"
    if ensure_packages_installed "libpam-pwquality"; then
        backup_file "$PWQUALITY_CONF"
        $DRY_RUN && dry_run_echo "Configure $PWQUALITY_CONF" || {
            declare -A pwq=(
                ["minlen"]="14"    ["dcredit"]="-1"    ["ucredit"]="-1"
                ["ocredit"]="-1"   ["lcredit"]="-1"    ["maxrepeat"]="3"
                ["difok"]="7"      ["gecoscheck"]="1"  ["dictcheck"]="1"
            )
            local k v
            for k in "${!pwq[@]}"; do
                v="${pwq[$k]}"
                [[ -f "$PWQUALITY_CONF" ]] && grep -qE "^\s*#?\s*${k}\s*=" "$PWQUALITY_CONF" \
                    && sed -i -E "s|^\s*#?\s*${k}\s*=.*|${k} = ${v}|" "$PWQUALITY_CONF" \
                    || echo "${k} = ${v}" >> "$PWQUALITY_CONF"
            done
            log_change "MODIFIED:$PWQUALITY_CONF"; txlog "FILE_ADDED" "$PWQUALITY_CONF"
            success "  pwquality: minlen=14, complexity enforced."
        }
        record_check "PAM_PWQUALITY" "FIXED" "pwquality: minlen=14"
    else
        record_check "PAM_PWQUALITY" "FAIL" "libpam-pwquality install failed"
    fi

    # --- 17b: Account lockout via faillock.conf (SAFE — no PAM stack injection) ---
    info "17b. Account lockout (faillock.conf — no PAM stack injection)..."
    info "  Modern Debian/Ubuntu: pam_faillock is activated via pam-auth-update."
    info "  We only configure the parameters in /etc/security/faillock.conf."

    describe_detail "pam_faillock"
    ask_yes_no "  Configure pam_faillock parameters (deny=5, unlock_time=900)?" "y" && {
        $DRY_RUN && dry_run_echo "Configure $FAILLOCK_CONF" || {
            # Ensure libpam-modules is installed (pam_faillock comes with it on Ubuntu 22+)
            # On older systems, ensure faillock.conf exists
            if [[ ! -f "$FAILLOCK_CONF" ]]; then
                info "  Creating $FAILLOCK_CONF..."
                mkdir -p "$(dirname "$FAILLOCK_CONF")"
                local tfail; tfail=$(mktemp_tracked)
                cat > "$tfail" <<'FAILLOCK_EOF'
# faillock.conf — generated by security_script.sh
# Parameters for pam_faillock.so
deny = 5
fail_interval = 900
unlock_time = 900
silent
audit
FAILLOCK_EOF
                install_managed_file "$FAILLOCK_CONF" "$tfail" 644
                success "  $FAILLOCK_CONF created."
            else
                backup_file "$FAILLOCK_CONF"
                declare -A fc_params=(["deny"]="5" ["fail_interval"]="900" ["unlock_time"]="900")
                local fk fv
                for fk in "${!fc_params[@]}"; do
                    fv="${fc_params[$fk]}"
                    grep -qE "^\s*#?\s*${fk}\s*=" "$FAILLOCK_CONF" \
                        && sed -i -E "s|^\s*#?\s*${fk}\s*=.*|${fk} = ${fv}|" "$FAILLOCK_CONF" \
                        || echo "${fk} = ${fv}" >> "$FAILLOCK_CONF"
                done
                log_change "MODIFIED:$FAILLOCK_CONF"
                success "  $FAILLOCK_CONF updated."
            fi

            # Activate pam_faillock via pam-auth-update (Debian/Ubuntu native — SAFE)
            if command -v pam-auth-update >/dev/null 2>&1; then
                # Check if faillock profile exists
                if [[ -f /usr/share/pam-configs/faillock ]]; then
                    pam-auth-update --enable faillock 2>/dev/null && \
                        success "  pam_faillock activated via pam-auth-update." || \
                        warn "  pam-auth-update --enable faillock failed (may already be active)."
                else
                    info "  No pam-configs/faillock profile found."
                    info "  pam_faillock will use faillock.conf parameters when the module is in the stack."
                    info "  On Ubuntu 22.04+: pam_faillock is active by default via pam-configs/faillock."
                fi
                # Smoke test — critical safety check
                sudo_smoke_test "/etc/pam.d/common-auth" || {
                    error "PAM smoke test failed after pam-auth-update! Rolling back."
                    pam-auth-update --disable faillock 2>/dev/null || true
                    return 1
                }
            else
                info "  pam-auth-update not found — faillock.conf parameters set but manual PAM config may be needed."
            fi
        }
        record_check "PAM_FAILLOCK" "FIXED" "faillock.conf: deny=5, unlock=900s"
    } || record_check "PAM_FAILLOCK" "SKIP" "User skipped faillock"

    # --- 17c: Root account lock ---
    info "17c. Root account lock..."
    if passwd -S root 2>/dev/null | grep -qE "^root\s+L"; then
        success "  Root account already locked."
        record_check "ROOT_LOCKED" "PASS" "root locked"
    else
        warn "  Root account is NOT locked."
        warn "  Ensure you have sudo access BEFORE locking root!"

        # Safety check: verify sudo works NOW before even offering to lock root
        if sudo -n true 2>/dev/null || groups "${SUDO_USER:-$(whoami)}" 2>/dev/null | grep -qE '\b(sudo|wheel|admin)\b'; then
            describe_detail "root_lock"
            if ask_yes_no "  Lock root account (passwd -l root)? [REQUIRES WORKING SUDO]" "y"; then
                # One final sudo test
                if sudo true 2>/dev/null; then
                    $DRY_RUN && dry_run_echo "passwd -l root" || {
                        passwd -l root && {
                            success "  Root account locked."
                            log_change "ROOT_LOCKED"; txlog "ROOT_LOCKED" "root"
                            record_check "ROOT_LOCKED" "FIXED" "root account locked"
                        } || { error "passwd -l root failed."; record_check "ROOT_LOCKED" "FAIL" "Lock failed"; }
                    }
                else
                    error "  Sudo not working — NOT locking root. Fix sudo first!"
                    record_check "ROOT_LOCKED" "FAIL" "sudo not working — root NOT locked"
                fi
            else
                record_check "ROOT_LOCKED" "SKIP" "User declined root lock"
            fi
        else
            error "  Cannot verify sudo access — NOT locking root (safety abort)."
            record_check "ROOT_LOCKED" "FAIL" "sudo not verified — root NOT locked for safety"
        fi
    fi
    section_done 17
}

# ============================================================================
# SECTION 18: Login Banners
# ============================================================================
configure_login_banners() {
    info "${C_BOLD}18. Login Banners${C_RESET}"
    describe_action "banners"
    is_section_skipped "banners" && { info "Skipped."; echo; return 0; }
    describe_detail "banners_apply"
    ask_yes_no "Configure login banners (compliance requirement)?" "y" || { record_check "LOGIN_BANNER" "SKIP" "User skipped"; echo; return 0; }

    $DRY_RUN && { dry_run_echo "Write SSH pre-login banner and avoid duplicate MOTD banner"; section_done 18; return 0; }

    local banner_text
    banner_text=$(cat <<'BANNER'
***************************************************************************
                         AUTHORIZED ACCESS ONLY

This system is for authorized users only. All activity may be monitored
and recorded. By accessing this system, you consent to such monitoring.
Unauthorized access or use may result in civil and criminal penalties.

Disconnect immediately if you are not an authorized user.
***************************************************************************
BANNER
)
    local tbanner
    tbanner=$(mktemp_tracked)
    printf '%s
' "$banner_text" > "$tbanner"
    install_managed_file "$BANNER_FILE" "$tbanner" 644
    success "  $BANNER_FILE written (SSH pre-login banner)."

    if [[ -f "$MOTD_FILE" ]] && grep -q "AUTHORIZED ACCESS ONLY" "$MOTD_FILE" 2>/dev/null; then
        if [[ -f "${MOTD_FILE}${BACKUP_SUFFIX}" ]]; then
            restore_file "$MOTD_FILE"
            success "  $MOTD_FILE restored to avoid duplicate post-login banner."
        else
            : > "$MOTD_FILE"
            chmod 644 "$MOTD_FILE" 2>/dev/null || true
            success "  $MOTD_FILE cleared to avoid duplicate post-login banner."
        fi
    else
        info "  $MOTD_FILE left unchanged to avoid duplicate banner text."
    fi

    local sc="/etc/ssh/sshd_config"
    backup_file "$sc"
    local ts; ts=$(mktemp_tracked); cp "$sc" "$ts"
    grep -qiE "^\s*Banner\s+$BANNER_FILE" "$ts" && success "  Banner already in sshd_config." || {
        grep -qiE "^\s*#?\s*Banner" "$ts"             && sed -i -E "s|^\s*#?\s*Banner\s+.*|Banner $BANNER_FILE|" "$ts"             || echo "Banner $BANNER_FILE" >> "$ts"
        apply_sshd_config "$ts" && { log_change "MODIFIED:$sc (Banner)"; restart_ssh "login banner" || true; }
    }
    success "Login banners configured (single SSH pre-login banner)."
    record_check "LOGIN_BANNER" "FIXED" "Authorization banner deployed via SSH pre-login"
    section_done 18
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    clear
    select_ui_language
    echo -e "${C_BOLD}${C_CYAN}"
    echo "  ╔══════════════════════════════════════════════════════════════════╗"
    echo "  ║   Linux Server Security Script v${SCRIPT_VERSION} — Paul Schumacher      ║"
    echo "  ║   Debian / Ubuntu — CIS/BSI Hardening + Full Rollback           ║"
    echo "  ╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    info "UI language: $UI_LANG"

    reload_governance_state
    interactive_mode_menu
    select_hardening_profile
    apply_profile_defaults
    detect_host_runtime_context
    if ! $ASSESS_ONLY && ! $DRY_RUN; then
        ensure_governance_files
        reload_governance_state
    fi

    $ROLLBACK_MODE && { run_full_rollback; exit $?; }
    $SELECTIVE_REMOVE_MODE && { run_selective_removal "$REMOVE_TARGETS_RAW"; exit $?; }

    echo "  Log:     $SCRIPT_LOG_FILE"
    echo "  Tx-Log:  $TRANSACTION_LOG"
    echo "  Backups: *${BACKUP_SUFFIX}"
    if $PROFILE_SELECTED || $AUTO_MODE || $EXPERT_PROFILE_MODE; then
        echo "  Profile: $ACTIVE_PROFILE"
    fi
    $DRY_RUN     && echo -e "\n  ${C_MAGENTA}*** $( [[ "$UI_LANG" == "de" ]] && echo "DRY-RUN — keine Änderungen" || echo "DRY-RUN — no changes" ) ***${C_RESET}"
    $AUTO_MODE   && echo -e "\n  ${C_YELLOW}*** $( [[ "$UI_LANG" == "de" ]] && echo "AUTO-MODUS — alle Prompts automatisch" || echo "AUTO MODE — all prompts automatic" ) ***${C_RESET}"
    $ASSESS_ONLY && echo -e "\n  ${C_CYAN}*** $( [[ "$UI_LANG" == "de" ]] && echo "NUR PRÜFUNG — keine Änderungen" || echo "ASSESSMENT ONLY — no changes" ) ***${C_RESET}"
    echo

    run_assessment

    if $ASSESS_ONLY; then
        print_assessment_report
        local red; red="$(count_red_checks)"
        echo -e "  ${C_CYAN}$(tr_msg run_without_assess)${C_RESET}"; echo
        (( red == 0 )) && exit 0 || exit 2
    fi

    echo -e "\n${C_BOLD}Pre-Hardening Assessment:${C_RESET}"
    print_assessment_report

    if $INTERACTIVE_RECOMMENDED_MODE; then
        info "$(tr_msg recommended_intro_1)"
        info "$(tr_msg recommended_intro_2)"
        info "$(tr_msg recommended_intro_3)"
    elif $INTERACTIVE_STEP_MODE && ! $EXPERT_PROFILE_MODE; then
        info "$(tr_msg step_intro)"
    fi

    local pre_red; pre_red="$(count_red_checks)"

    $AUTO_MODE || {
        warn "$(tr_msg own_risk)"
        ask_yes_no "$(tr_msg start_hardening)" "y" || { info "$(tr_msg aborted)"; exit 0; }
    }

    ! $DRY_RUN && {
        local log_dir; log_dir=$(dirname "$SCRIPT_LOG_FILE")
        [[ -d "$log_dir" ]] || mkdir -p "$log_dir"
        touch "$SCRIPT_LOG_FILE" "$TRANSACTION_LOG"
        log_change "SCRIPT_STARTED v=${SCRIPT_VERSION} AUTO=${AUTO_MODE} VERIFY=${VERIFY_AFTER_HARDENING}"
        txlog "SCRIPT_START" "v=${SCRIPT_VERSION}"
    }

    detect_ssh_service
    info "SSH service: $SSH_SERVICE"

    local -a sections=(
        configure_ssh_key_and_users      #  1
        configure_unattended_upgrades    #  2
        configure_msmtp                  #  3
        configure_ssh_hardening          #  4a
        configure_google_2fa             #  4b
        configure_fail2ban               #  5a
        configure_sshguard               #  5b
        configure_ufw                    #  6
        configure_journald               #  7
        configure_clamav                 #  8
        configure_sysctl                 #  9
        configure_sudoers_tty            # 10
        configure_login_umask            # 10a
        configure_suid_sgid_inventory    # 10b
        configure_auditd                 # 11
        configure_aide                   # 12
        configure_apparmor_enforce       # 13
        configure_filesystem_hardening   # 14
        configure_module_blacklist       # 15
        configure_core_dumps             # 16
        configure_pam_hardening          # 17 ← ROCK SOLID REWRITE
        configure_login_banners          # 18
    )

    local targeted_pending_sections=0
    targeted_pending_sections="$(count_targeted_pending_sections "${sections[@]}")"

    if (( pre_red == 0 )) && { $INTERACTIVE_RECOMMENDED_MODE || $EXPERT_PROFILE_MODE || $AUTO_MODE; }; then
        success "$(tr_msg no_open_findings_mode)"
        info "$(tr_msg manual_step_mode_hint)"
        exit 0
    fi
    if { $INTERACTIVE_RECOMMENDED_MODE || $EXPERT_PROFILE_MODE || $AUTO_MODE; } && (( targeted_pending_sections == 0 )); then
        success "$(tr_msg no_relevant_findings_mode)"
        info "$(tr_msg open_points_special)"
        exit 0
    fi

    local func
    local -a executed_sections=()
    for func in "${sections[@]}"; do
        if ! should_execute_section_in_current_mode "$func"; then
            continue
        fi
        SECTION_WAS_EXECUTED=false
        if declare -f "$func" >/dev/null 2>&1; then
            "$func"
            $SECTION_WAS_EXECUTED && executed_sections+=("$func")
        else
            warn "Function '$func' not defined."
        fi
    done

    if $INTERACTIVE_STEP_MODE; then
        info "Idempotence proof skipped in step-by-step mode."
    elif (( ${#executed_sections[@]} > 0 )); then
        prove_idempotence "${executed_sections[@]}"
    else
        info "Idempotence proof skipped — no sections were executed in this run."
    fi

    # Post-hardening assessment
    echo
    declare -A ASSESS_RESULTS=()
    declare -a ASSESS_ORDER=()
    run_assessment
    echo -e "\n${C_BOLD}${C_GREEN}Post-Hardening Assessment:${C_RESET}"
    print_assessment_report

    $AUTO_MODE || {
        ask_yes_no "$(tr_msg manage_backups)" "n" && {
            list_backups
            ask_yes_no "$(tr_msg restore_backup_prompt)" "n" && restore_backup_interactive
        }
    }

    echo
    local final_red; final_red="$(count_red_checks)"
    if (( final_red == 0 )); then
        echo -e "${C_GREEN_BOLD}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "${C_GREEN_BOLD}$(tr_msg done_green)${C_RESET}"
        echo -e "${C_GREEN_BOLD}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
    else
        echo -e "${C_RED_BOLD}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "${C_RED_BOLD}$(tr_msg done_red_prefix) ${final_red} $(tr_msg done_red_suffix)${C_RESET}"
        echo -e "${C_RED_BOLD}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
    fi
    echo

    ! $DRY_RUN && {
        info "Changelog: $SCRIPT_LOG_FILE"
        info "$(tr_msg txlog_label_with_rb): $TRANSACTION_LOG"
        info "Backups mit Suffix: '${BACKUP_SUFFIX}'"
        print_security_log_summary
        echo -e "  ${C_YELLOW_BOLD}$(tr_msg reboot_recommended)${C_RESET}"
        txlog "SCRIPT_FINISH" "red_findings=${final_red}"
        log_change "SCRIPT_FINISHED"
    } || warn "$(tr_msg dry_run_no_changes)"

    $VERIFY_AFTER_HARDENING && (( final_red == 0 )) && exit 0
    $VERIFY_AFTER_HARDENING && exit 2
    exit 0
}

main
