#!/bin/bash

# === Interactive Linux Server Security Script ===
# Version: 2.0.6
# Original Author: Paul Schumacher
# Purpose: Check and harden Debian/Ubuntu servers
# License: MIT – Free to use, but at your own risk. NO WARRANTY.
#
# Improvements in v2.0.0:
# - Eliminated eval() usage for security (uses arrays for command execution)
# - Added missing get_container_ports() function
# - Added missing configure_sysctl() function
# - Added missing configure_sudoers_tty() function
# - Fixed syntax error in process_parameter_line()
# - Improved backup/restore with list and selective restore commands
# - Reduced code duplication with shared helper functions
# - ShellCheck-compatible improvements
# - Streamlined origins processing in unattended-upgrades
# - Added GPG/secret-tool hint for MSMTP password storage
#
# Fixes in v2.0.1:
# - Removed set -e (caused premature exit on grep/diff non-zero returns)
# - Fixed UFW detection for already-installed packages
# - Added || true to all grep pipelines to prevent pipefail breakage
# - Improved UFW status display when inactive
#
# Fixes in v2.0.2:
# - Fail2ban/SSHGuard/UFW: Auto-audit when already installed (no redundant questions)
# - Only prompts when issues are found, with [Issue] + Recommendation + Fix pattern
# - Shows audit summary with issue count per section
#
# Fixes in v2.0.3:
# - Journald/Sysctl/Sudoers: Auto-audit, skip if already configured correctly
# - Fixed ANSI escape codes not rendering in ask_yes_no prompts (read -p bug)
# - All sections now follow consistent audit pattern: check → report → fix
#
# Fixes in v2.0.4:
# - Fixed ufw_rules array crash with set -u (unbound variable on empty array)
# - Added is_ufw_allowed() helper for safe associative array access
# - Fail2ban: validates config before restart, offers restore on failure
# - listening_ports array properly initialized
#
# Fixes in v2.0.5 (release candidate):
# - SSH port detection: fallback to sshd_config file when sshd binary missing
# - get_ssh_port() helper always returns a valid port number (default 22)
# - get_listening_ports: replaced gawk-only match() with bash regex (mawk compat)
# - list_backups: fixed ANSI escape rendering (echo -e)
# - Fail2ban: creates minimal jail.local instead of copying huge jail.conf
# - Fail2ban: sshd jail enable handles missing section, appends if needed
# - Fail2ban: ignoreip handles missing [DEFAULT] section
#
# Fixes in v2.0.6:
# - Fixed ask_yes_no stdin conflict: reads from /dev/tty to prevent
#   infinite loop when called inside while-read pipelines (UFW port review)

set -uo pipefail

# --- Configuration ---
readonly SCRIPT_VERSION="2.0.6"
readonly JOURNALD_MAX_USE="${JOURNALD_MAX_USE:-1G}"
readonly SCRIPT_LOG_FILE="/var/log/security_script_changes.log"
readonly BACKUP_SUFFIX=".security_script_backup"
readonly MSMTP_CONFIG_CHOICE="user"  # 'user' (~/.msmtprc) or 'system' (/etc/msmtprc)
readonly SYSCTL_CONFIG_FILE="/etc/sysctl.d/99-security-script.conf"
readonly SUDOERS_TTY_FILE="/etc/sudoers.d/tty_tickets"
readonly SCRIPT_DEBUG="${SCRIPT_DEBUG:-false}"

# --- Global Variables ---
DRY_RUN=false
SCRIPT_APT_UPDATED=false
SSH_SERVICE=""

# --- Argument Parsing ---
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=true; shift ;;
            --help|-h)
                echo "Usage: $0 [--dry-run] [--help]"
                echo "  --dry-run  Simulate changes without applying them"
                echo "  --help     Show this help message"
                exit 0 ;;
            *) echo "Unknown option: $1" >&2; exit 1 ;;
        esac
    done
}

parse_args "$@"

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root!" >&2
    exit 1
fi

# Check Bash version
if (( BASH_VERSINFO[0] < 4 )); then
    echo "ERROR: Bash version 4+ required (found ${BASH_VERSION})." >&2
    exit 1
fi

# Announce Dry-Run mode
if $DRY_RUN; then
    echo -e "\n\e[1;35m*** DRY-RUN MODE ACTIVE: No changes will be made. ***\e[0m\n"
fi

# --- Determine SSH service name ---
detect_ssh_service() {
    if systemctl list-unit-files 2>/dev/null | grep -q "^ssh\.service"; then
        SSH_SERVICE="ssh"
    elif systemctl list-unit-files 2>/dev/null | grep -q "^sshd\.service"; then
        SSH_SERVICE="sshd"
    else
        SSH_SERVICE="sshd"
        warn "Could not detect SSH service name, assuming 'sshd'."
    fi
}

# --- Colors ---
readonly C_RESET='\e[0m'
readonly C_RED='\e[0;31m'
readonly C_GREEN='\e[0;32m'
readonly C_YELLOW='\e[0;33m'
readonly C_BLUE='\e[0;34m'
readonly C_MAGENTA='\e[0;35m'
readonly C_BOLD='\e[1m'

# --- Output Helpers ---
debug()       { [[ "$SCRIPT_DEBUG" == "true" ]] && echo -e "${C_YELLOW}DEBUG [${FUNCNAME[1]}]:${C_RESET} $1"; return 0; }
info()        { echo -e "${C_BLUE}INFO:${C_RESET} $1"; }
success()     { echo -e "${C_GREEN}SUCCESS:${C_RESET} $1"; }
warn()        { echo -e "${C_YELLOW}WARNING:${C_RESET} $1"; }
error()       { echo -e "${C_RED}ERROR:${C_RESET} $1" >&2; }
dry_run_echo() { echo -e "${C_MAGENTA}DRY-RUN:${C_RESET} Would execute: $1"; }

# --- Core Helper Functions ---

ask_yes_no() {
    local question="$1" default="${2:-}" answer
    while true; do
        if [[ "$default" == "y" ]]; then
            echo -en "$question [Y/n]: "
            read -r answer < /dev/tty
            answer=${answer:-y}
        elif [[ "$default" == "n" ]]; then
            echo -en "$question [y/N]: "
            read -r answer < /dev/tty
            answer=${answer:-n}
        else
            echo -en "$question [y/n]: "
            read -r answer < /dev/tty
        fi
        case "$answer" in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) warn "Invalid input. Please enter 'y' or 'n'." ;;
        esac
    done
}

is_package_installed() { dpkg -s "$1" &>/dev/null; }

validate_email() { [[ "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; }
validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

log_change() {
    $DRY_RUN && return 0
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $1" >> "$SCRIPT_LOG_FILE"
}

# --- Safe Command Execution (no eval!) ---
# Usage: run_cmd "log description" command arg1 arg2 ...
run_cmd() {
    local log_description="$1"
    shift
    local cmd_display="$*"

    if $DRY_RUN; then
        dry_run_echo "$cmd_display"
        return 0
    fi

    debug "Executing: $cmd_display"
    if "$@"; then
        log_change "$log_description"
        return 0
    else
        local exit_code=$?
        error "Command failed (exit $exit_code): $cmd_display"
        return $exit_code
    fi
}

# For commands that need shell features (pipes, redirects) - use sparingly
run_shell() {
    local log_description="$1"
    local shell_cmd="$2"

    if $DRY_RUN; then
        dry_run_echo "$shell_cmd"
        return 0
    fi

    debug "Executing shell: $shell_cmd"
    if bash -c "$shell_cmd"; then
        log_change "$log_description"
        return 0
    else
        local exit_code=$?
        error "Shell command failed (exit $exit_code): $shell_cmd"
        return $exit_code
    fi
}

# --- Ensure apt is updated (once per session) ---
ensure_apt_updated() {
    if ! $SCRIPT_APT_UPDATED; then
        info "Running 'apt update'..."
        if run_cmd "APT_UPDATE" apt-get update -qq; then
            SCRIPT_APT_UPDATED=true
        else
            error "'apt update' failed."
            return 1
        fi
    fi
}

# --- Install packages if missing ---
# Usage: ensure_packages_installed pkg1 pkg2 ...
ensure_packages_installed() {
    local missing=()
    for pkg in "$@"; do
        is_package_installed "$pkg" || missing+=("$pkg")
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        success "Required packages already installed: $*"
        return 0
    fi

    warn "Missing packages: ${missing[*]}"
    if ask_yes_no "Install missing packages (${missing[*]})?" "y"; then
        ensure_apt_updated || return 1
        if run_cmd "INSTALLED:${missing[*]}" apt-get install -y "${missing[@]}"; then
            success "Packages installed: ${missing[*]}"
            return 0
        else
            error "Package installation failed."
            return 1
        fi
    else
        info "Package installation declined."
        return 1
    fi
}

# --- Backup & Restore ---
backup_file() {
    local file="$1"
    local backup_path="${file}${BACKUP_SUFFIX}"

    [[ ! -f "$file" ]] && return 0  # Nothing to back up

    if [[ -f "$backup_path" ]]; then
        info "Backup already exists: '$backup_path'"
        return 0
    fi

    if $DRY_RUN; then
        dry_run_echo "cp -a '$file' '$backup_path'"
        return 0
    fi

    if cp -a "$file" "$backup_path"; then
        info "Backup created: '$backup_path'"
        log_change "BACKUP_CREATED:$file:$backup_path"
        return 0
    else
        error "Could not create backup of '$file'."
        return 1
    fi
}

restore_file() {
    local file="$1"
    local backup_path="${file}${BACKUP_SUFFIX}"

    if [[ -f "$backup_path" ]]; then
        if $DRY_RUN; then
            dry_run_echo "mv '$backup_path' '$file'"
            return 0
        fi
        if mv "$backup_path" "$file"; then
            success "Restored '$file' from backup."
            log_change "FILE_RESTORED:$file"
            return 0
        else
            error "Failed to restore '$file' from '$backup_path'."
            return 1
        fi
    fi

    # Check if file was added by this script
    if ! $DRY_RUN && [[ -f "$SCRIPT_LOG_FILE" ]] && grep -q "ADDED_FILE:$file" "$SCRIPT_LOG_FILE"; then
        if [[ -f "$file" ]]; then
            info "No backup found, but '$file' was added by this script. Removing..."
            if rm -f "$file"; then
                success "Removed '$file'."
                log_change "REMOVED_ADDED_FILE:$file"
                return 0
            fi
        fi
    fi

    warn "No backup found for '$file'."
    return 0
}

# --- List all backups created by this script ---
list_backups() {
    info "${C_BOLD}Listing all backups created by this script:${C_RESET}"
    local found=false
    while IFS= read -r -d '' backup; do
        local original="${backup%"$BACKUP_SUFFIX"}"
        local backup_date
        backup_date=$(stat -c '%y' "$backup" 2>/dev/null | cut -d. -f1)
        echo -e "  ${C_GREEN}→${C_RESET} $original (backed up: $backup_date)"
        found=true
    done < <(find /etc /home -name "*${BACKUP_SUFFIX}" -print0 2>/dev/null)

    if ! $found; then
        info "No backups found."
    fi
}

# --- Restore a specific backup interactively ---
restore_backup_interactive() {
    info "${C_BOLD}Interactive Backup Restore${C_RESET}"
    local backups=()
    while IFS= read -r -d '' backup; do
        backups+=("$backup")
    done < <(find /etc /home -name "*${BACKUP_SUFFIX}" -print0 2>/dev/null)

    if [[ ${#backups[@]} -eq 0 ]]; then
        info "No backups found to restore."
        return 0
    fi

    echo "Available backups:"
    local i
    for i in "${!backups[@]}"; do
        local original="${backups[$i]%"$BACKUP_SUFFIX"}"
        local backup_date
        backup_date=$(stat -c '%y' "${backups[$i]}" 2>/dev/null | cut -d. -f1)
        echo "  [$((i+1))] $original (backed up: $backup_date)"
    done
    echo "  [0] Cancel"

    local choice
    read -rp "Select backup to restore [0]: " choice
    choice=${choice:-0}

    if [[ "$choice" == "0" ]]; then
        info "Restore cancelled."
        return 0
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#backups[@]} )); then
        local selected="${backups[$((choice-1))]}"
        local original="${selected%"$BACKUP_SUFFIX"}"
        if ask_yes_no "Restore '$original' from backup?" "y"; then
            restore_file "$original"
        fi
    else
        warn "Invalid selection."
    fi
}

# --- SSH Config Helpers ---
# Returns the effective value of an sshd parameter, or empty string if unavailable.
get_effective_sshd_config() {
    local parameter="$1"
    local result=""

    # Method 1: sshd -T (most reliable, but needs sshd binary)
    if command -v sshd >/dev/null 2>&1; then
        result=$(sshd -T -C user=root -C host=localhost -C addr=127.0.0.1 2>/dev/null | \
            grep -i "^${parameter}[[:space:]]" | head -n 1 | awk '{print $2}' || true)
    fi

    # Method 2: Fallback to config file parsing
    if [[ -z "$result" ]] && [[ -f /etc/ssh/sshd_config ]]; then
        result=$(grep -iE "^\s*${parameter}\s+" /etc/ssh/sshd_config 2>/dev/null | \
            tail -n 1 | awk '{print $2}' || true)
    fi

    echo "$result"
}

# Get the SSH port with robust fallback
get_ssh_port() {
    local port
    port=$(get_effective_sshd_config "port")
    # Validate it's actually a number
    if [[ -n "$port" ]] && validate_port "$port"; then
        echo "$port"
    else
        echo "22"  # SSH default
    fi
}

get_config_file_sshd_setting() {
    local parameter="$1"
    local config_file="/etc/ssh/sshd_config"
    [[ ! -f "$config_file" ]] && return 0
    grep -iE "^\s*${parameter}\s+" "$config_file" 2>/dev/null | tail -n 1 | awk '{print $2}' || true
}

get_effective_sysctl_config() {
    local parameter="$1"
    if sysctl "$parameter" >/dev/null 2>&1; then
        sysctl -n "$parameter"
    else
        echo "not_set"
    fi
}

# --- Modify or add a parameter in sshd_config temp file ---
# Returns 0 if changed, 1 if already correct
set_sshd_param() {
    local key="$1" value="$2" file="$3"
    local current_val
    current_val=$(grep -iE "^\s*${key}\s+" "$file" 2>/dev/null | tail -n 1 | awk '{print $2}' || true)

    # Case-insensitive comparison
    if [[ -n "$current_val" ]] && \
       [[ "$(echo "$current_val" | tr '[:upper:]' '[:lower:]')" == "$(echo "$value" | tr '[:upper:]' '[:lower:]')" ]]; then
        return 1  # Already correct
    fi

    if grep -qE "^\s*#?\s*${key}" "$file"; then
        sed -i -E "s|^\s*#?\s*(${key})\s+.*|${key} ${value}|" "$file"
    else
        echo "${key} ${value}" >> "$file"
    fi
    info "Set '${key} ${value}' in temp SSH config."
    return 0
}

# --- Apply a temp sshd_config with validation ---
apply_sshd_config() {
    local temp_file="$1"
    local target="/etc/ssh/sshd_config"

    if $DRY_RUN; then
        dry_run_echo "sshd -t -f '$temp_file' && mv '$temp_file' '$target'"
        rm -f "$temp_file" 2>/dev/null
        return 0
    fi

    if sshd -t -f "$temp_file" 2>/dev/null; then
        if mv "$temp_file" "$target"; then
            chmod 644 "$target"
            success "Applied changes to $target."
            return 0
        else
            error "Failed to move temp config to $target."
        fi
    else
        error "SSHD config validation failed. Changes NOT applied."
    fi

    rm -f "$temp_file" 2>/dev/null
    restore_file "$target"
    return 1
}

# --- Restart SSH service safely ---
restart_ssh() {
    local reason="${1:-configuration change}"
    info "Restarting SSH service ($SSH_SERVICE) due to $reason..."

    if run_cmd "SERVICE_RESTARTED:$SSH_SERVICE ($reason)" systemctl restart "$SSH_SERVICE"; then
        success "SSH service restarted."
        if ! $DRY_RUN; then
            sleep 1
            if ! systemctl is-active --quiet "$SSH_SERVICE"; then
                error "SSH service is not active after restart! Check config."
                return 1
            fi
        fi
        return 0
    else
        error "SSH service restart failed!"
        return 1
    fi
}

# --- Service management helper ---
ensure_service_running() {
    local service="$1"
    local needs_start=false needs_enable=false

    if ! systemctl is-active --quiet "$service" 2>/dev/null; then
        needs_start=true
    fi
    if ! systemctl is-enabled --quiet "$service" 2>/dev/null; then
        needs_enable=true
    fi

    if $needs_start; then
        if ask_yes_no "Start '$service' service?" "y"; then
            run_cmd "SERVICE_STARTED:$service" systemctl start "$service" && \
                success "'$service' started." || error "Failed to start '$service'."
        fi
    else
        success "'$service' is already active."
    fi

    if $needs_enable; then
        if ask_yes_no "Enable '$service' on boot?" "y"; then
            run_cmd "SERVICE_ENABLED:$service" systemctl enable "$service" && \
                success "'$service' enabled." || error "Failed to enable '$service'."
        fi
    else
        success "'$service' is already enabled."
    fi
}

# --- Fail2ban jail check ---
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

# --- Container port detection ---
get_container_ports() {
    # Docker
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        docker ps --format '{{.Ports}}' 2>/dev/null | \
            grep -oP '0\.0\.0\.0:(\d+)->(\d+)/(tcp|udp)' | \
            while IFS= read -r mapping; do
                local host_port proto
                host_port=$(echo "$mapping" | grep -oP '0\.0\.0\.0:\K\d+')
                proto=$(echo "$mapping" | grep -oP '(tcp|udp)$')
                echo "${host_port},${proto},docker-container"
            done
    fi

    # Podman
    if command -v podman >/dev/null 2>&1; then
        podman ps --format '{{.Ports}}' 2>/dev/null | \
            grep -oP '0\.0\.0\.0:(\d+)->(\d+)/(tcp|udp)' | \
            while IFS= read -r mapping; do
                local host_port proto
                host_port=$(echo "$mapping" | grep -oP '0\.0\.0\.0:\K\d+')
                proto=$(echo "$mapping" | grep -oP '(tcp|udp)$')
                echo "${host_port},${proto},podman-container"
            done
    fi
}

# --- Get listening ports from ss ---
get_listening_ports() {
    # TCP - parse ss output, extract port and process name
    ss -ltnp 2>/dev/null | while IFS= read -r line; do
        # Skip header
        [[ "$line" =~ ^State ]] && continue
        [[ "$line" =~ ^LISTEN ]] || continue

        # Extract local address:port (4th field)
        local addr_field
        addr_field=$(echo "$line" | awk '{print $4}')
        # Port is everything after the last ':'
        local port="${addr_field##*:}"

        # Validate port
        [[ "$port" =~ ^[0-9]+$ ]] && (( port > 0 && port < 65536 )) || continue

        # Extract process name from users:(("name",...))
        local proc="unknown"
        if [[ "$line" =~ users:\(\(\"([^\"]+)\" ]]; then
            proc="${BASH_REMATCH[1]}"
        fi

        echo "${port},tcp,${proc}"
    done

    # UDP
    ss -lunp 2>/dev/null | while IFS= read -r line; do
        [[ "$line" =~ ^State ]] && continue
        [[ "$line" =~ ^UNCONN ]] || continue

        local addr_field
        addr_field=$(echo "$line" | awk '{print $4}')
        local port="${addr_field##*:}"

        [[ "$port" =~ ^[0-9]+$ ]] && (( port > 0 && port < 65536 )) || continue

        local proc="unknown"
        if [[ "$line" =~ users:\(\(\"([^\"]+)\" ]]; then
            proc="${BASH_REMATCH[1]}"
        fi

        echo "${port},udp,${proc}"
    done
}

# --- Fail2ban ignoreip helper ---
is_ip_covered_by_ignoreip() {
    local check_item="$1"
    shift
    local ignore_list=("$@")
    local ip="" subnet=""

    if [[ "$check_item" =~ / ]]; then
        subnet="$check_item"
    else
        ip="$check_item"
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && \
            subnet="$(echo "$ip" | cut -d. -f1-3).0/24"
    fi

    for entry in "${ignore_list[@]}"; do
        [[ "$ip" == "$entry" || "$subnet" == "$entry" ]] && return 0
        if [[ -n "$ip" ]]; then
            { [[ "$entry" == "192.168.0.0/16" ]] && [[ "$ip" =~ ^192\.168\. ]]; } && return 0
            { [[ "$entry" == "172.16.0.0/12" ]] && [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; } && return 0
            { [[ "$entry" == "10.0.0.0/8" ]] && [[ "$ip" =~ ^10\. ]]; } && return 0
        fi
    done
    return 1
}


# ============================================================================
# SECTION 1: SSH Key Generation
# ============================================================================
configure_ssh_key_and_users() {
    info "${C_BOLD}1. Create SSH Key Pair (Ed25519)${C_RESET}"
    if ! ask_yes_no "Execute this step (SSH Key)?" "y"; then
        info "Step skipped."; echo; return 0
    fi

    local current_user="${SUDO_USER:-$(whoami)}"
    local user_home
    user_home=$(eval echo "~$current_user")

    # Check existing keys
    local existing_count=0
    if [[ -d "$user_home/.ssh" ]]; then
        existing_count=$(find "$user_home/.ssh" -maxdepth 1 -type f -name "*.pub" \
            -exec grep -Eil "ssh-ed25519" {} + 2>/dev/null | wc -l)
        if [[ -f "$user_home/.ssh/authorized_keys" ]]; then
            existing_count=$((existing_count + $(grep -Eic "ssh-ed25519" "$user_home/.ssh/authorized_keys" 2>/dev/null || echo 0)))
        fi
    fi

    if (( existing_count > 0 )); then
        success "Found $existing_count Ed25519 key(s) in '$user_home/.ssh'."
    else
        warn "No Ed25519 key found in '$user_home/.ssh'."
    fi

    if ! ask_yes_no "Create new Ed25519 SSH key pair for '$current_user'?" "y"; then
        echo "--- Section 1 completed ---"; echo; return 0
    fi

    local new_key_name
    read -rp "Filename for new key [id_ed25519_$(date +%Y%m%d)]: " new_key_name
    new_key_name=${new_key_name:-"id_ed25519_$(date +%Y%m%d)"}
    local key_path="$user_home/.ssh/$new_key_name"
    local pub_key_path="${key_path}.pub"
    local authorized_keys_path="$user_home/.ssh/authorized_keys"

    if [[ -f "$key_path" || -f "$pub_key_path" ]]; then
        warn "Key file '$key_path' already exists."
        if ! ask_yes_no "Overwrite?" "n"; then
            echo "--- Section 1 completed ---"; echo; return 0
        fi
    fi

    local passphrase passphrase_confirm
    while true; do
        read -rsp "Passphrase (empty = none): " passphrase; echo
        read -rsp "Confirm passphrase: " passphrase_confirm; echo
        [[ "$passphrase" == "$passphrase_confirm" ]] && break
        warn "Passphrases do not match."
    done

    # Prepare .ssh directory
    run_cmd "MKDIR_SSH" mkdir -p "$user_home/.ssh"
    run_cmd "CHMOD_SSH" chmod 700 "$user_home/.ssh"
    run_cmd "CHOWN_SSH" chown "$current_user":"$current_user" "$user_home/.ssh"

    if $DRY_RUN; then
        dry_run_echo "ssh-keygen -q -t ed25519 -f '$key_path' -N '***'"
        success "DRY-RUN: Would generate SSH key at '$key_path'."
        echo "--- Section 1 completed ---"; echo; return 0
    fi

    # Generate key
    info "Generating SSH key pair..."
    if sudo -u "$current_user" ssh-keygen -q -t ed25519 -f "$key_path" -N "$passphrase"; then
        chmod 600 "$key_path"
        chmod 644 "$pub_key_path"
        chown "$current_user":"$current_user" "$key_path" "$pub_key_path"
        success "SSH key pair created at '$key_path'."
        log_change "SSH_KEY_GENERATED:${key_path}"

        # Display private key
        echo
        warn "--- Private Key ($(basename "$key_path")) --- SENSITIVE! ---"
        cat "$key_path"
        warn "--- End Private Key --- Copy to a secure location! ---"
        echo

        # Add to authorized_keys
        info "Adding public key to authorized_keys..."
        if ! sudo -u "$current_user" test -f "$authorized_keys_path"; then
            sudo -u "$current_user" touch "$authorized_keys_path"
            sudo -u "$current_user" chmod 600 "$authorized_keys_path"
            log_change "ADDED_FILE:$authorized_keys_path"
        fi

        local pub_key_content
        pub_key_content=$(cat "$pub_key_path")
        if sudo -u "$current_user" grep -Fq -- "$pub_key_content" "$authorized_keys_path" 2>/dev/null; then
            success "Public key already in authorized_keys."
        elif echo "$pub_key_content" | sudo -u "$current_user" tee -a "$authorized_keys_path" > /dev/null; then
            success "Public key added to authorized_keys."
            log_change "AUTHORIZED_KEY_ADDED:${pub_key_path}"
        else
            warn "Could not add public key to authorized_keys."
        fi

        [[ -n "$passphrase" ]] && warn "Remember to store the passphrase securely!"
    else
        error "Key generation failed."
    fi

    echo "--- Section 1 completed ---"; echo
}


# ============================================================================
# SECTION 2: Unattended Upgrades
# ============================================================================
configure_unattended_upgrades() {
    info "${C_BOLD}2. Configure Unattended Upgrades${C_RESET}"
    if ! ask_yes_no "Execute this step (Unattended Upgrades)?" "y"; then
        info "Step skipped."; echo; return 0
    fi

    local pkg="unattended-upgrades"
    local config_file="/etc/apt/apt.conf.d/50unattended-upgrades"
    local periodic_file="/etc/apt/apt.conf.d/20auto-upgrades"

    # Get distro info
    local distro_id distro_codename
    if command -v lsb_release &>/dev/null; then
        distro_id=$(lsb_release -is)
        distro_codename=$(lsb_release -cs)
    elif [[ -f /etc/os-release ]]; then
        distro_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
        distro_id="${distro_id^}"
        distro_codename=$(grep '^VERSION_CODENAME=' /etc/os-release | cut -d= -f2 | tr -d '"')
    else
        error "Cannot determine distribution."; return 1
    fi

    if [[ -z "$distro_id" || -z "$distro_codename" ]]; then
        error "Could not determine distro ID or codename."; return 1
    fi
    info "Detected: $distro_id $distro_codename"

    # Install package
    ensure_packages_installed "$pkg" || return 0

    # --- Periodic configuration ---
    info "Checking periodic configuration ($periodic_file)..."
    local periodic_ok=true
    if [[ ! -f "$periodic_file" ]] || \
       ! grep -qE '^\s*APT::Periodic::Update-Package-Lists\s*"1"\s*;' "$periodic_file" || \
       ! grep -qE '^\s*APT::Periodic::Unattended-Upgrade\s*"1"\s*;' "$periodic_file"; then
        periodic_ok=false
    fi

    if ! $periodic_ok; then
        if ask_yes_no "Apply recommended periodic settings to '$periodic_file'?" "y"; then
            backup_file "$periodic_file"
            local content='APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";'
            if run_shell "WRITE_FILE:$periodic_file" "echo -e '$content' > '$periodic_file'"; then
                success "'$periodic_file' configured."
            else
                error "Failed to write '$periodic_file'."; restore_file "$periodic_file"
            fi
        fi
    else
        success "'$periodic_file' already correct."
    fi

    # --- Main configuration ---
    if [[ ! -f "$config_file" ]]; then
        error "Config file '$config_file' not found!"; return 1
    fi

    local temp_file
    temp_file=$(mktemp)
    cp "$config_file" "$temp_file"
    local changes_made=false

    # Define desired parameters
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
        ["Unattended-Upgrade::Allow-downgrade"]="true"
        ["Unattended-Upgrade::Allow-APT-Mark-Fallback"]="true"
    )

    # Process each parameter
    for key in "${!desired_params[@]}"; do
        local value="${desired_params[$key]}"
        local current_line current_value

        current_line=$(grep -E "^\s*(//\s*)?${key}\s+" "$temp_file" || true)

        if [[ -n "$current_line" ]]; then
            current_value=$(echo "$current_line" | sed -E 's/^\s*(\/\/\s*)?.*'"${key}"'\s*"?([^";]*)"?\s*;?.*/\2/')
            local is_commented=false
            [[ "$current_line" =~ ^\s*// ]] && is_commented=true

            if ! $is_commented && [[ "$current_value" == "$value" ]]; then
                success "  $key = \"$value\" (already correct)"
                continue
            fi

            # Replace the line
            sed -i -E "s|^\s*(//\s*)?${key}\s+.*|${key} \"${value}\";|" "$temp_file"
            success "  $key -> \"$value\" (updated)"
            changes_made=true
        else
            # Add missing parameter
            echo "${key} \"${value}\";" >> "$temp_file"
            success "  $key -> \"$value\" (added)"
            changes_made=true
        fi
    done

    # Process Allowed-Origins
    info "Checking Allowed-Origins..."
    local desired_origins=(
        "\"${distro_id}:${distro_codename}-security\";"
        "\"${distro_id}:${distro_codename}-updates\";"
        "\"${distro_id}ESMApps:${distro_codename}-apps-security\";"
        "\"${distro_id}ESM:${distro_codename}-infra-security\";"
    )

    local block_start block_end
    block_start=$(grep -nE "^\s*(//\s*)?Unattended-Upgrade::Allowed-Origins\s*\{" "$temp_file" 2>/dev/null | head -n1 | cut -d: -f1 || true)

    if [[ -n "$block_start" ]]; then
        block_end=$(tail -n +"$block_start" "$temp_file" | grep -nm1 -E "^\s*(//\s*)?\};" | cut -d: -f1 || true)
        if [[ -n "$block_end" ]]; then
            block_end=$((block_start + block_end - 1))

            # Uncomment block start if needed
            if sed -n "${block_start}p" "$temp_file" | grep -q "^\s*//"; then
                sed -i "${block_start}s|^\s*//\s*||" "$temp_file"
                changes_made=true
            fi
            # Uncomment block end if needed
            if sed -n "${block_end}p" "$temp_file" | grep -q "^\s*//"; then
                sed -i "${block_end}s|^\s*//\s*||" "$temp_file"
                changes_made=true
            fi

            for origin in "${desired_origins[@]}"; do
                # Check if active
                if sed -n "${block_start},${block_end}p" "$temp_file" | grep -qF "$origin"; then
                    # Check if it's commented
                    local origin_line
                    origin_line=$(sed -n "${block_start},${block_end}p" "$temp_file" | grep -n "//.*${origin}" | head -n1 | cut -d: -f1)
                    if [[ -n "$origin_line" ]]; then
                        local abs_line=$((block_start + origin_line - 1))
                        sed -i "${abs_line}s|^\s*//\s*||" "$temp_file"
                        success "  Uncommented origin: $origin"
                        changes_made=true
                    else
                        success "  Origin already active: $origin"
                    fi
                else
                    # Insert before closing brace
                    sed -i "${block_end}i\\\\t${origin}" "$temp_file"
                    block_end=$((block_end + 1))
                    success "  Added origin: $origin"
                    changes_made=true
                fi
            done
        fi
    else
        warn "Allowed-Origins block not found in config."
    fi

    # Email configuration
    info "Checking mail configuration..."
    local mail_key="Unattended-Upgrade::Mail"
    local mail_report_val
    mail_report_val=$(grep -E "^\s*Unattended-Upgrade::MailReport\s+" "$temp_file" | sed -E 's/.*"(.*)".*/\1/' || true)

    if [[ "$mail_report_val" == "on-change" || "$mail_report_val" == "always" ]]; then
        local current_mail
        current_mail=$(grep -E "^\s*${mail_key}\s+" "$temp_file" | sed -E 's/.*"(.*)".*/\1/' || true)

        if [[ -z "$current_mail" ]] || ! validate_email "$current_mail"; then
            warn "No valid email address configured for mail reports."
            if ask_yes_no "Set email address for upgrade reports?" "y"; then
                local new_mail=""
                while true; do
                    read -rp "Email address: " new_mail
                    validate_email "$new_mail" && break
                    warn "Invalid email format."
                done

                if grep -qE "^\s*(//\s*)?${mail_key}\s+" "$temp_file"; then
                    sed -i -E "s|^\s*(//\s*)?${mail_key}\s+.*|${mail_key} \"${new_mail}\";|" "$temp_file"
                else
                    echo "${mail_key} \"${new_mail}\";" >> "$temp_file"
                fi
                success "Mail address set to: $new_mail"
                changes_made=true
            fi
        else
            success "Mail address configured: $current_mail"
        fi
    fi

    # Apply changes
    if $changes_made; then
        backup_file "$config_file" || { rm -f "$temp_file"; return 1; }

        if ! $DRY_RUN && command -v diff &>/dev/null; then
            info "--- Changes ---"
            diff -u "$config_file" "$temp_file" || true
            info "--- End ---"
            if ! ask_yes_no "Apply these changes?" "y"; then
                rm -f "$temp_file"; return 0
            fi
        fi

        if $DRY_RUN; then
            dry_run_echo "mv '$temp_file' '$config_file'"
            rm -f "$temp_file"
        elif mv "$temp_file" "$config_file" && chmod 644 "$config_file"; then
            success "Changes applied to $config_file."
            log_change "APPLY_CONFIG:$config_file"
        else
            error "Failed to apply changes!"; restore_file "$config_file"
        fi
    else
        success "No changes needed for $config_file."
    fi

    rm -f "$temp_file" 2>/dev/null
    echo "--- Section 2 completed ---"; echo
}


# ============================================================================
# SECTION 3: MSMTP Setup
# ============================================================================
configure_msmtp() {
    info "${C_BOLD}3. MSMTP Setup for System Notifications${C_RESET}"
    if ! ask_yes_no "Execute this step (MSMTP)?" "y"; then
        info "Step skipped."; echo; return 0
    fi

    # Determine config scope
    local config_owner config_file_path user_home
    if [[ "$MSMTP_CONFIG_CHOICE" == "user" ]]; then
        local target_user="${SUDO_USER:-$USER}"
        read -rp "Configure MSMTP for which user? [$target_user]: " config_owner
        config_owner=${config_owner:-$target_user}
        user_home=$(eval echo "~$config_owner")
        [[ -d "$user_home" ]] || { error "Home dir for '$config_owner' not found."; return 1; }
        config_file_path="$user_home/.msmtprc"
    else
        config_file_path="/etc/msmtprc"; config_owner="root"; user_home="/root"
    fi
    info "MSMTP config: '$config_file_path' (owner: $config_owner)"

    # Install packages
    local base_pkgs=("msmtp" "msmtp-mta")
    ensure_packages_installed "${base_pkgs[@]}" || return 0

    # Optional mailutils
    if ! is_package_installed "mailutils"; then
        if ask_yes_no "Install 'mailutils' (for test emails)?" "y"; then
            ensure_packages_installed "mailutils" || true
        fi
    fi

    # Check existing config
    local do_configure=false
    if [[ -f "$config_file_path" ]]; then
        warn "MSMTP config exists: '$config_file_path'."
        ask_yes_no "Recreate configuration (will overwrite)?" "n" && do_configure=true
    else
        ask_yes_no "Set up MSMTP now?" "y" && do_configure=true
    fi

    if ! $do_configure; then
        echo "--- Section 3 completed ---"; echo; return 0
    fi

    # Gather SMTP details
    info "Enter SMTP details:"
    local smtp_host smtp_port smtp_tls smtp_trust_file smtp_from smtp_user smtp_password

    while true; do read -rp "SMTP Host: " smtp_host; [[ -n "$smtp_host" ]] && break; warn "Cannot be empty."; done
    while true; do read -rp "SMTP Port [587]: " smtp_port; smtp_port=${smtp_port:-587}; validate_port "$smtp_port" && break; warn "Invalid port."; done
    while true; do read -rp "TLS (on/off) [on]: " smtp_tls; smtp_tls=${smtp_tls:-on}; [[ "$smtp_tls" =~ ^(on|off)$ ]] && break; warn "Enter 'on' or 'off'."; done
    read -rp "CA cert file [/etc/ssl/certs/ca-certificates.crt]: " smtp_trust_file
    smtp_trust_file=${smtp_trust_file:-/etc/ssl/certs/ca-certificates.crt}
    while true; do read -rp "Sender (From): " smtp_from; validate_email "$smtp_from" && break; warn "Invalid email."; done
    while true; do read -rp "SMTP Username [$smtp_from]: " smtp_user; smtp_user=${smtp_user:-$smtp_from}; [[ -n "$smtp_user" ]] && break; done
    while true; do read -rsp "SMTP Password: " smtp_password; echo; [[ -n "$smtp_password" ]] && break; warn "Cannot be empty."; done

    local logfile_path="${user_home}/.msmtp.log"
    local aliases_file="/etc/aliases"

    # Show config preview (password hidden)
    echo
    info "--- Configuration Preview ---"
    cat <<EOF
defaults
port $smtp_port
tls $smtp_tls
tls_trust_file $smtp_trust_file
logfile ${logfile_path}

account default
host $smtp_host
from $smtp_from
auth on
user $smtp_user
password ********

aliases $aliases_file
EOF
    echo "---"
    echo
    warn "Security Note: Password is stored in plaintext in '$config_file_path'."
    info "For better security, consider using 'secret-tool' or 'gpg' for password storage."
    info "See: https://marlam.de/msmtp/msmtp.html#Authentication"
    echo

    if ! ask_yes_no "Save this configuration?" "y"; then
        echo "--- Section 3 completed ---"; echo; return 0
    fi

    backup_file "$config_file_path"

    if $DRY_RUN; then
        dry_run_echo "Write MSMTP config to '$config_file_path'"
        dry_run_echo "chmod 600 '$config_file_path'; chown $config_owner:$config_owner '$config_file_path'"
        echo "--- Section 3 completed ---"; echo; return 0
    fi

    # Write config
    cat > "$config_file_path" <<EOF
# MSMTP configuration generated by security_script.sh
defaults
port $smtp_port
tls $smtp_tls
tls_trust_file $smtp_trust_file
logfile ${logfile_path}

account default
host $smtp_host
from $smtp_from
auth on
user $smtp_user
password $smtp_password

aliases $aliases_file
EOF

    chmod 600 "$config_file_path"
    mkdir -p "$(dirname "$logfile_path")"
    touch "$logfile_path"
    chmod 600 "$logfile_path"
    chown "$config_owner":"$config_owner" "$config_file_path" "$logfile_path"
    success "MSMTP configuration saved."
    log_change "ADDED_FILE:$config_file_path"

    # Test email
    if is_package_installed "mailutils" && ask_yes_no "Send test email to '$smtp_from'?" "y"; then
        local mail_cmd=(mail -s "MSMTP Test $(date)" "$smtp_from")
        if echo "Test email from Linux Security Script." | \
           sudo -u "$config_owner" "${mail_cmd[@]}" 2>/dev/null; then
            success "Test email sent."
            log_change "SEND_TEST_MAIL:$smtp_from"
        else
            warn "Test email failed. Check $logfile_path"
        fi
    fi

    echo "--- Section 3 completed ---"; echo
}


# ============================================================================
# SECTION 4a: SSH Hardening
# ============================================================================
configure_ssh_hardening() {
    info "${C_BOLD}4a. Harden SSH Configuration${C_RESET}"
    if ! ask_yes_no "Execute this step (SSH Hardening)?" "y"; then
        info "Step skipped."; echo; return 0
    fi

    local ssh_config="/etc/ssh/sshd_config"
    local sshd_needs_restart=false

    # --- AllowUsers ---
    if ask_yes_no "Configure AllowUsers?" "n"; then
        local effective_allow
        effective_allow=$(get_effective_sshd_config "allowusers")
        local suggested_user
        suggested_user=$(awk -F: '$3 >= 1000 && $3 < 65534 { print $1; exit }' /etc/passwd)
        suggested_user=${suggested_user:-"your_admin_user"}

        warn "Restrict SSH access to specific users (not root)."
        read -rp "SSH users (space-separated, suggestion: $suggested_user, empty=skip): " target_users

        if [[ -n "$target_users" ]]; then
            local all_exist=true
            for user in $target_users; do
                id "$user" &>/dev/null || { error "User '$user' doesn't exist."; all_exist=false; }
            done

            if $all_exist; then
                # Check if already set correctly
                local sorted_current sorted_target
                sorted_current=$(echo "$effective_allow" | tr ' ' '\n' | sort | tr '\n' ' ' | xargs)
                sorted_target=$(echo "$target_users" | tr ' ' '\n' | sort | tr '\n' ' ' | xargs)

                if [[ "$sorted_current" == "$sorted_target" ]]; then
                    success "AllowUsers already set to '$target_users'."
                elif ask_yes_no "Set AllowUsers to '$target_users'?" "y"; then
                    backup_file "$ssh_config" || return 1
                    local temp_conf
                    temp_conf=$(mktemp)
                    cp "$ssh_config" "$temp_conf"
                    set_sshd_param "AllowUsers" "$target_users" "$temp_conf" || true
                    if apply_sshd_config "$temp_conf"; then
                        log_change "MODIFIED_PARAM:AllowUsers:$target_users:$ssh_config"
                        sshd_needs_restart=true
                    fi
                fi
            fi
        fi
    fi

    # --- SSH Hardening Parameters ---
    declare -A ssh_recommendations=(
        ["PermitRootLogin"]="prohibit-password"
        ["ChallengeResponseAuthentication"]="no"
        ["PasswordAuthentication"]="no"
        ["UsePAM"]="yes"
        ["X11Forwarding"]="no"
        ["PrintLastLog"]="yes"
    )

    # Check for existing keys (for PasswordAuthentication warning)
    local check_user="${SUDO_USER:-$(whoami)}"
    local check_home
    check_home=$(eval echo "~$check_user")
    local key_count=0
    if [[ -d "$check_home/.ssh" ]]; then
        key_count=$(find "$check_home/.ssh" -maxdepth 1 -name "*.pub" -exec grep -Eil "ssh-ed25519" {} + 2>/dev/null | wc -l)
        if [[ -f "$check_home/.ssh/authorized_keys" ]]; then
            key_count=$((key_count + $(grep -Eic "ssh-ed25519" "$check_home/.ssh/authorized_keys" 2>/dev/null || echo 0)))
        fi
    fi

    declare -A changes_to_apply

    for param in "${!ssh_recommendations[@]}"; do
        local current recommended ask_user=true
        current=$(get_effective_sshd_config "$param")
        recommended="${ssh_recommendations[$param]}"

        # Handle empty/default values
        if [[ -z "$current" ]]; then
            case "$param" in
                "PasswordAuthentication"|"PermitRootLogin") current="yes" ;;
                "ChallengeResponseAuthentication") current="yes" ;;
                "X11Forwarding") current="no" ;;
                "PrintLastLog"|"UsePAM") current="yes" ;;
            esac
        fi

        local cur_lower rec_lower
        cur_lower=$(echo "$current" | tr '[:upper:]' '[:lower:]')
        rec_lower=$(echo "$recommended" | tr '[:upper:]' '[:lower:]')

        # PermitRootLogin: accept 'no' or 'without-password' as secure
        if [[ "$param" == "PermitRootLogin" ]] && \
           [[ "$cur_lower" =~ ^(no|without-password|prohibit-password)$ ]]; then
            success "$param already secure ($current)."; ask_user=false
        elif [[ "$cur_lower" == "$rec_lower" ]]; then
            success "$param already correct ($current)."; ask_user=false
        else
            # Also check config file directly
            local file_val
            file_val=$(get_config_file_sshd_setting "$param")
            if [[ -n "$file_val" ]] && [[ "$(echo "$file_val" | tr '[:upper:]' '[:lower:]')" == "$rec_lower" ]]; then
                success "$param already set in config file ($file_val)."; ask_user=false
            fi
        fi

        if $ask_user; then
            echo
            echo -e "  Parameter: ${C_BOLD}$param${C_RESET}"
            echo "  Current:     $current"
            echo "  Recommended: $recommended"

            case "$param" in
                "PermitRootLogin")           echo "  → Disables root password login. Key-based root login still allowed." ;;
                "PasswordAuthentication")
                    echo "  → ${C_RED}WARNING:${C_RESET} Disabling without SSH key ${C_BOLD}will lock you out!${C_RESET}"
                    if (( key_count == 0 )); then warn "No Ed25519 keys found for '$check_user'!";
                    else success "Found $key_count Ed25519 key(s) for '$check_user'."; fi ;;
                "UsePAM")                    echo "  → Enables system auth integration (2FA, etc.)." ;;
                "X11Forwarding")             echo "  → Disabling reduces attack surface." ;;
            esac

            local default_ans="y"
            [[ "$param" == "PasswordAuthentication" && $key_count -eq 0 ]] && default_ans="n"

            if ask_yes_no "  Change to '$recommended'?" "$default_ans"; then
                changes_to_apply["$param"]="$recommended"
            fi
        fi
    done

    # Apply parameter changes
    if [[ ${#changes_to_apply[@]} -gt 0 ]]; then
        info "Changes to apply:"
        for k in "${!changes_to_apply[@]}"; do echo "  $k -> ${changes_to_apply[$k]}"; done

        if ask_yes_no "Save these changes?" "y"; then
            backup_file "$ssh_config" || return 1
            local temp_conf
            temp_conf=$(mktemp)
            cp "$ssh_config" "$temp_conf"

            for k in "${!changes_to_apply[@]}"; do
                set_sshd_param "$k" "${changes_to_apply[$k]}" "$temp_conf" || true
            done

            if apply_sshd_config "$temp_conf"; then
                for k in "${!changes_to_apply[@]}"; do
                    log_change "MODIFIED_PARAM:$k:${changes_to_apply[$k]}:$ssh_config"
                done
                sshd_needs_restart=true
            fi
        fi
    fi

    # Restart if needed
    if $sshd_needs_restart; then
        restart_ssh "SSH hardening"
    else
        info "No SSH changes applied, skipping restart."
    fi

    echo "--- Section 4a completed ---"; echo
}


# ============================================================================
# SECTION 4b: Google 2FA
# ============================================================================
configure_google_2fa() {
    info "${C_BOLD}5. Configure Google Authenticator 2FA${C_RESET}"
    if ! ask_yes_no "Execute Google Authenticator setup?" "y"; then
        info "Skipping Google Authenticator."; echo; return 0
    fi

    local target_user="${SUDO_USER:-$(whoami)}"
    local user_home
    user_home=$(eval echo "~$target_user")
    info "Setting up 2FA for user: $target_user"

    if [[ -f "$user_home/.google_authenticator" ]]; then
        if ! ask_yes_no "Already configured for $target_user. Reconfigure?" "n"; then
            echo; return 0
        fi
    fi

    ensure_packages_installed "libpam-google-authenticator" || return 1

    # Interactive configuration
    info "Initializing Google Authenticator for $target_user..."
    echo "  - Scan the QR code with your authenticator app"
    echo "  - Save your emergency scratch codes securely"
    echo

    if $DRY_RUN; then
        dry_run_echo "sudo -u '$target_user' google-authenticator -t -f -d -r 3 -R 30 -w 17"
    else
        if ! sudo -u "$target_user" google-authenticator -t -f -d -r 3 -R 30 -w 17; then
            error "Google Authenticator setup failed."; return 1
        fi
        success "Google Authenticator initialized. Save your emergency codes!"
    fi
    echo

    # PAM configuration
    local pam_file="/etc/pam.d/sshd"
    local pam_changed=false
    [[ ! -f "$pam_file" ]] && { error "PAM file $pam_file not found!"; return 1; }
    backup_file "$pam_file" || return 1

    local temp_pam
    temp_pam=$(mktemp)
    cp "$pam_file" "$temp_pam"

    if grep -q "^@include common-auth" "$temp_pam"; then
        sed -i 's/^@include common-auth/#@include common-auth/' "$temp_pam"
        pam_changed=true
    fi
    if ! grep -q "pam_google_authenticator.so" "$temp_pam"; then
        echo "auth required pam_google_authenticator.so nullok" >> "$temp_pam"
        pam_changed=true
    fi

    if $pam_changed; then
        if $DRY_RUN; then
            dry_run_echo "Update $pam_file for Google Authenticator"
            rm -f "$temp_pam"
        elif mv "$temp_pam" "$pam_file"; then
            chmod 644 "$pam_file"
            log_change "MODIFIED:$pam_file (Google Authenticator)"
            success "PAM configured for 2FA."
        else
            error "Failed to update PAM."; rm -f "$temp_pam"; restore_file "$pam_file"; return 1
        fi
    else
        success "PAM already configured for 2FA."
        rm -f "$temp_pam"
    fi

    # SSHD configuration
    local ssh_conf="/etc/ssh/sshd_config"
    local ssh_changed=false
    backup_file "$ssh_conf" || return 1

    local temp_ssh
    temp_ssh=$(mktemp)
    cp "$ssh_conf" "$temp_ssh"

    for param_pair in \
        "ChallengeResponseAuthentication:yes" \
        "KbdInteractiveAuthentication:yes" \
        "AuthenticationMethods:publickey,keyboard-interactive" \
        "UsePAM:yes"; do
        local p_key="${param_pair%%:*}" p_val="${param_pair##*:}"
        set_sshd_param "$p_key" "$p_val" "$temp_ssh" && ssh_changed=true
    done

    if $ssh_changed; then
        if apply_sshd_config "$temp_ssh"; then
            log_change "MODIFIED:$ssh_conf (Google Authenticator)"
        fi
    else
        success "SSHD already configured for 2FA."
        rm -f "$temp_ssh"
    fi

    # Restart SSH if needed
    if $pam_changed || $ssh_changed; then
        if ! restart_ssh "2FA setup"; then
            warn "SSH restart failed. Restoring configs..."
            $pam_changed && restore_file "$pam_file"
            $ssh_changed && restore_file "$ssh_conf"
            restart_ssh "2FA rollback" || true
        fi
    fi

    echo
    info "${C_BOLD}IMPORTANT:${C_RESET}"
    echo "  1. Test login in a SEPARATE SSH session before closing this one!"
    echo "  2. Verify your authenticator app shows correct codes."
    echo "  3. Keep emergency scratch codes safe."
    echo
}


# ============================================================================
# SECTION 5a: Fail2ban
# ============================================================================
configure_fail2ban() {
    info "${C_BOLD}5a. Fail2ban — Audit & Configuration${C_RESET}"

    local pkg="fail2ban"
    local jail_local="/etc/fail2ban/jail.local"
    local jail_conf="/etc/fail2ban/jail.conf"
    local needs_restart=false
    local issues_found=0

    # --- If not installed, ask whether to install ---
    if ! is_package_installed "$pkg"; then
        if ! ask_yes_no "Fail2ban is not installed. Install it?" "y"; then
            info "Fail2ban skipped."; echo; return 0
        fi
        ensure_packages_installed "$pkg" || return 0
    else
        success "Fail2ban is installed."
    fi

    # --- Automated audit starts here (no "Configure?" question) ---
    info "Auditing Fail2ban configuration..."

    # Check 1: jail.local exists
    if [[ ! -f "$jail_local" ]]; then
        issues_found=$((issues_found + 1))
        warn "[Issue] '$jail_local' does not exist."
        info "  Recommendation: Create a minimal '$jail_local' with [sshd] jail enabled."
        if ask_yes_no "  Fix: Create '$jail_local'?" "y"; then
            # Create a clean minimal jail.local instead of copying the huge jail.conf
            if $DRY_RUN; then
                dry_run_echo "Create minimal $jail_local with [sshd] enabled"
            else
                cat > "$jail_local" <<'JAIL_EOF'
# jail.local - Generated by security_script.sh
# This file overrides settings from jail.conf.
# Only add settings that differ from the defaults.

[DEFAULT]
# Ban duration (10 minutes)
bantime  = 10m
# Time window for counting failures
findtime = 10m
# Number of failures before ban
maxretry = 5

[sshd]
enabled = true
JAIL_EOF
                log_change "ADDED_FILE:$jail_local"
            fi
            needs_restart=true
            success "  Fixed: '$jail_local' created with [sshd] jail enabled."
        else
            error "  Cannot proceed without '$jail_local'."; return 1
        fi
    else
        success "jail.local exists."
    fi

    # Check 2: [sshd] jail enabled
    if [[ -f "$jail_local" ]]; then
        if ! is_fail2ban_jail_enabled "sshd"; then
            issues_found=$((issues_found + 1))
            warn "[Issue] Jail [sshd] is not enabled."
            info "  Recommendation: Enable [sshd] jail to protect SSH against brute-force."
            if ask_yes_no "  Fix: Enable [sshd] jail?" "y"; then
                backup_file "$jail_local" || return 1

                if $DRY_RUN; then
                    dry_run_echo "Enable [sshd] jail in $jail_local"
                else
                    # Check if [sshd] section exists at all
                    if grep -q '^\s*\[sshd\]' "$jail_local"; then
                        # Section exists: replace or add enabled line within it
                        local temp_jail
                        temp_jail=$(mktemp)
                        awk '
                            /^\s*\[sshd\]/ { in_sshd=1; print; next }
                            in_sshd && /^\s*\[/ { if (!done) { print "enabled = true"; done=1 }; in_sshd=0 }
                            in_sshd && /^\s*#?\s*enabled\s*=/ { print "enabled = true"; done=1; next }
                            { print }
                            END { if (in_sshd && !done) print "enabled = true" }
                        ' "$jail_local" > "$temp_jail"

                        if mv "$temp_jail" "$jail_local"; then
                            success "  Fixed: [sshd] jail enabled."
                            log_change "MODIFIED:$jail_local (sshd jail enabled)"
                        else
                            rm -f "$temp_jail"
                            restore_file "$jail_local"
                            return 1
                        fi
                    else
                        # No [sshd] section at all — append it
                        echo -e "\n[sshd]\nenabled = true" >> "$jail_local"
                        success "  Fixed: Added [sshd] jail section with enabled = true."
                        log_change "MODIFIED:$jail_local (sshd section added)"
                    fi
                    needs_restart=true
                fi
            fi
        else
            success "Jail [sshd] is enabled."
        fi

        # Check 3: Local IPs in ignoreip
        info "Checking ignoreip whitelist..."
        local current_ignoreip
        current_ignoreip=$(awk '/^\s*\[DEFAULT\]/{d=1;next} /^\s*\[/{d=0} d&&/^\s*ignoreip\s*=/{
            gsub(/^\s*ignoreip\s*=\s*/,""); cl=$0
            while(getline>0 && $0~/^[[:space:]]/) cl=cl $0
            gsub(/[[:space:]]+/," ",cl); print cl; exit
        }' "$jail_local" 2>/dev/null || true)

        read -ra current_array <<< "$current_ignoreip"
        local proposed=() apply_ignore=false
        local local_ips
        local_ips=$(ip -4 addr show | grep -oP 'inet \K[\d.]+' | grep -v '^127\.' || true)

        for ip in $local_ips; do
            local subnet
            subnet="$(echo "$ip" | cut -d. -f1-3).0/24"
            if ! is_ip_covered_by_ignoreip "$ip" "${current_array[@]}"; then
                local already=false
                for p in "${proposed[@]+"${proposed[@]}"}"; do [[ "$subnet" == "$p" ]] && already=true; done
                if ! $already; then
                    proposed+=("$subnet")
                    apply_ignore=true
                fi
            fi
        done

        if $apply_ignore; then
            issues_found=$((issues_found + 1))
            local final_list
            final_list=$(printf '%s\n' "127.0.0.1/8" "::1" "${current_array[@]}" "${proposed[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//')
            warn "[Issue] Local subnets not in ignoreip: ${proposed[*]}"
            info "  Recommendation: Add local subnets to prevent self-lockout."
            info "  Proposed ignoreip: $final_list"

            if ask_yes_no "  Fix: Update ignoreip?" "y"; then
                backup_file "$jail_local" || return 1

                if $DRY_RUN; then
                    dry_run_echo "Update ignoreip in $jail_local"
                else
                    # Check if [DEFAULT] section exists
                    if grep -q '^\s*\[DEFAULT\]' "$jail_local"; then
                        local temp_ignore
                        temp_ignore=$(mktemp)

                        awk -v new_ip="$final_list" '
                            BEGIN {d=0; f=0}
                            /^\s*\[DEFAULT\]/ {print; d=1; next}
                            /^\s*\[/ && NR>1 && d { if(!f) print "ignoreip = " new_ip; d=0; f=1 }
                            d && /^\s*#?\s*ignoreip\s*=/ { if(!f) print "ignoreip = " new_ip; f=1; next }
                            {print}
                            END { if(d && !f) print "ignoreip = " new_ip }
                        ' "$jail_local" > "$temp_ignore"

                        if mv "$temp_ignore" "$jail_local"; then
                            success "  Fixed: ignoreip updated."
                            log_change "MODIFIED:$jail_local (ignoreip)"
                            needs_restart=true
                        else
                            rm -f "$temp_ignore"; restore_file "$jail_local"
                        fi
                    else
                        # No [DEFAULT] section — prepend it
                        local tmp_prepend
                        tmp_prepend=$(mktemp)
                        {
                            echo "[DEFAULT]"
                            echo "ignoreip = $final_list"
                            echo
                            cat "$jail_local"
                        } > "$tmp_prepend"
                        if mv "$tmp_prepend" "$jail_local"; then
                            success "  Fixed: Added [DEFAULT] with ignoreip."
                            log_change "MODIFIED:$jail_local (DEFAULT+ignoreip added)"
                            needs_restart=true
                        else
                            rm -f "$tmp_prepend"; restore_file "$jail_local"
                        fi
                    fi
                fi
            fi
        else
            success "Local subnets covered by ignoreip."
        fi
    fi

    # Check 4: Service running and enabled
    info "Checking Fail2ban service..."
    local svc_issues=false
    if ! systemctl is-active --quiet "$pkg" 2>/dev/null; then
        svc_issues=true
        issues_found=$((issues_found + 1))
        warn "[Issue] Fail2ban service is not running."
    else
        success "Fail2ban service is active."
    fi
    if ! systemctl is-enabled --quiet "$pkg" 2>/dev/null; then
        svc_issues=true
        issues_found=$((issues_found + 1))
        warn "[Issue] Fail2ban service is not enabled on boot."
    else
        success "Fail2ban service is enabled."
    fi

    if $needs_restart; then
        info "Restarting Fail2ban after configuration changes..."
        # Validate config first
        if ! $DRY_RUN && command -v fail2ban-client >/dev/null; then
            if ! fail2ban-client -t 2>/dev/null; then
                error "Fail2ban config validation failed!"
                warn "  Check with: sudo fail2ban-client -t"
                warn "  View log: sudo journalctl -xeu fail2ban.service"
                if ask_yes_no "  Restore jail.local from backup?" "y"; then
                    restore_file "$jail_local"
                    run_cmd "SERVICE_RESTARTED:$pkg (after restore)" systemctl restart "$pkg" || true
                fi
                echo "--- Section 5a completed (with errors) ---"; echo; return 1
            fi
        fi
        if run_cmd "SERVICE_RELOADED:$pkg" systemctl reload-or-restart "$pkg"; then
            success "Fail2ban restarted."
        else
            error "Fail2ban restart failed!"
            warn "  Check with: sudo systemctl status fail2ban"
            warn "  View log: sudo journalctl -xeu fail2ban.service"
            if ask_yes_no "  Restore jail.local from backup?" "y"; then
                restore_file "$jail_local"
                run_cmd "SERVICE_RESTARTED:$pkg (after restore)" systemctl restart "$pkg" || true
            fi
        fi
    elif $svc_issues; then
        ensure_service_running "$pkg"
    fi

    # Summary
    echo
    if (( issues_found == 0 )); then
        success "Fail2ban audit: ${C_GREEN}All checks passed.${C_RESET}"
    else
        info "Fail2ban audit: $issues_found issue(s) found and addressed."
    fi

    echo "--- Section 5a completed ---"; echo
}


# ============================================================================
# SECTION 5b: SSHGuard
# ============================================================================
configure_sshguard() {
    info "${C_BOLD}5b. SSHGuard — Audit & Configuration${C_RESET}"

    local pkg="sshguard"
    local whitelist_file="/etc/sshguard/whitelist"
    local needs_restart=false
    local issues_found=0

    # --- If not installed, ask whether to install ---
    if ! is_package_installed "$pkg"; then
        if ! ask_yes_no "SSHGuard is not installed. Install it?" "y"; then
            info "SSHGuard skipped."; echo; return 0
        fi
        ensure_packages_installed "$pkg" || return 0
    else
        success "SSHGuard is installed."
    fi

    # --- Automated audit ---
    info "Auditing SSHGuard configuration..."

    # Ensure directory and whitelist exist
    run_cmd "MKDIR_SSHGUARD" mkdir -p "$(dirname "$whitelist_file")" || true
    if [[ ! -f "$whitelist_file" ]]; then
        run_cmd "ADDED_FILE:$whitelist_file" touch "$whitelist_file" || true
    fi

    # Check 1: Whitelist completeness
    local proposed=("127.0.0.1" "::1")
    local local_ips4 local_ips6
    local_ips4=$(ip -4 addr show | grep -oP 'inet \K[\d.]+' | grep -v '^127\.' || true)
    local_ips6=$(ip -6 addr show scope global | grep -oP 'inet6 \K[0-9a-fA-F:]+' 2>/dev/null || true)

    for ip in $local_ips4; do
        local subnet="$(echo "$ip" | cut -d. -f1-3).0/24"
        printf '%s\n' "${proposed[@]}" | grep -qxF "$subnet" || proposed+=("$subnet")
    done
    for ip in $local_ips6; do
        IFS=':' read -ra parts <<< "$ip"
        local cidr6
        printf -v cidr6 "%s:%s:%s:%s::/64" "${parts[0]:-0}" "${parts[1]:-0}" "${parts[2]:-0}" "${parts[3]:-0}"
        printf '%s\n' "${proposed[@]}" | grep -qxF "$cidr6" || proposed+=("$cidr6")
    done

    local missing=()
    declare -A existing_map
    if [[ -f "$whitelist_file" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            existing_map["$line"]=1
        done < "$whitelist_file"
    fi

    for item in "${proposed[@]}"; do
        [[ -n "${existing_map[$item]+x}" ]] || missing+=("$item")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        issues_found=$((issues_found + 1))
        warn "[Issue] Missing from whitelist: ${missing[*]}"
        info "  Recommendation: Add local IPs/subnets to prevent self-lockout."
        if ask_yes_no "  Fix: Add missing entries to '$whitelist_file'?" "y"; then
            backup_file "$whitelist_file" || return 1
            if $DRY_RUN; then
                dry_run_echo "Add ${missing[*]} to $whitelist_file"
            else
                printf '%s\n' "${missing[@]}" >> "$whitelist_file"
                sort -u "$whitelist_file" -o "$whitelist_file"
                success "  Fixed: SSHGuard whitelist updated."
                log_change "MODIFIED:$whitelist_file"
                needs_restart=true
            fi
        fi
    else
        success "Whitelist contains all local IPs/subnets."
    fi

    # Check 2: Service running and enabled
    info "Checking SSHGuard service..."
    local svc_issues=false
    if ! systemctl is-active --quiet "$pkg" 2>/dev/null; then
        svc_issues=true
        issues_found=$((issues_found + 1))
        warn "[Issue] SSHGuard service is not running."
    else
        success "SSHGuard service is active."
    fi
    if ! systemctl is-enabled --quiet "$pkg" 2>/dev/null; then
        svc_issues=true
        issues_found=$((issues_found + 1))
        warn "[Issue] SSHGuard service is not enabled on boot."
    else
        success "SSHGuard service is enabled."
    fi

    if $needs_restart; then
        run_cmd "SERVICE_RESTARTED:$pkg" systemctl restart "$pkg" && \
            success "SSHGuard restarted." || error "Failed to restart SSHGuard."
    elif $svc_issues; then
        ensure_service_running "$pkg"
    fi

    # Summary
    echo
    if (( issues_found == 0 )); then
        success "SSHGuard audit: ${C_GREEN}All checks passed.${C_RESET}"
    else
        info "SSHGuard audit: $issues_found issue(s) found and addressed."
    fi

    echo "--- Section 5b completed ---"; echo
}


# ============================================================================
# SECTION 6: UFW Firewall
# ============================================================================
configure_ufw() {
    info "${C_BOLD}6. UFW (Firewall) — Audit & Configuration${C_RESET}"

    local issues_found=0

    # --- If not installed, ask whether to install ---
    if ! is_package_installed "ufw"; then
        if ! ask_yes_no "UFW is not installed. Install it?" "y"; then
            info "UFW skipped."; echo; return 0
        fi
        ensure_packages_installed "ufw" || return 0
    else
        success "UFW is installed."
    fi

    # --- Automated audit ---
    info "Auditing UFW configuration..."

    # Check 1: UFW active?
    local ufw_active=false
    ufw status 2>/dev/null | grep -q "Status: active" && ufw_active=true

    if $ufw_active; then
        success "UFW is active."
        info "Current rules:"
        ufw status verbose 2>/dev/null || true
    else
        issues_found=$((issues_found + 1))
        warn "[Issue] UFW is installed but not active."
        info "  Recommendation: Enable UFW to filter incoming connections."
        if ask_yes_no "  Fix: Enable UFW? ${C_RED}WARNING: May disconnect SSH if rule missing!${C_RESET}" "n"; then
            local ssh_port
            ssh_port=$(get_ssh_port)
            if validate_port "$ssh_port"; then
                info "  Pre-allowing SSH port $ssh_port/tcp..."
                run_cmd "UFW_PRE_ALLOW_SSH" ufw allow "$ssh_port/tcp" comment "SSH pre-enable"
            fi
            if run_cmd "UFW_ENABLED" ufw --force enable; then
                success "  Fixed: UFW enabled."
                ufw_active=true
            else
                error "Failed to enable UFW."; return 1
            fi
        else
            info "UFW remains inactive."
            echo "--- Section 6 completed ---"; echo; return 0
        fi
    fi

    # Check 2: Parse current allowed rules
    declare -A ufw_rules=()
    local ufw_numbered_output
    ufw_numbered_output=$(ufw status numbered 2>/dev/null || true)
    while IFS= read -r line; do
        if [[ "$line" =~ \[[[:space:]]*([0-9]+)\][[:space:]]+([^[:space:]]+)[[:space:]]+(ALLOW[[:space:]]+IN) ]]; then
            local spec="${BASH_REMATCH[2]}"
            spec=${spec%% \(v6\)}
            ufw_rules["$spec"]=1
        fi
    done <<< "$ufw_numbered_output"
    local ufw_rule_count=${#ufw_rules[@]}
    info "Found $ufw_rule_count ALLOW IN rules."

    # Helper: check if a port/spec is allowed in ufw_rules
    is_ufw_allowed() {
        local check_spec="$1"
        local check_port="${check_spec%%/*}"
        [[ ${ufw_rule_count} -gt 0 ]] || return 1
        [[ -n "${ufw_rules[$check_spec]+x}" ]] && return 0
        [[ -n "${ufw_rules[$check_port]+x}" ]] && return 0
        return 1
    }

    # Check 3: SSH port is allowed
    local ssh_port
    ssh_port=$(get_ssh_port)
    local ssh_spec="${ssh_port}/tcp"

    if is_ufw_allowed "$ssh_spec"; then
        success "SSH port ($ssh_spec) is allowed."
    else
        issues_found=$((issues_found + 1))
        warn "[Issue] SSH port $ssh_spec is NOT explicitly allowed in UFW!"
        info "  Recommendation: Allow SSH to prevent lockout."
        if ask_yes_no "  Fix: Allow $ssh_spec?" "y"; then
            if run_cmd "UFW_ALLOW:$ssh_spec" ufw allow "$ssh_spec" comment "SSH - security script"; then
                ufw_rules["$ssh_spec"]=1
                success "  Fixed: SSH port allowed."
            fi
        fi
    fi

    # Check 4: Detect listening ports not covered by UFW
    declare -A listening_ports=()
    local all_ports
    all_ports="$(get_listening_ports)$(get_container_ports)"

    while IFS="," read -r port proto process; do
        [[ -n "$port" && -n "$proto" ]] || continue
        local key="$port/$proto"
        [[ -n "${listening_ports[$key]+x}" ]] || listening_ports["$key"]="${process:-unknown}"
    done <<< "$all_ports"

    if [[ ${#listening_ports[@]} -eq 0 ]]; then
        info "No listening ports detected."
    else
        info "Detected ${#listening_ports[@]} listening port/protocol pairs."

        local uncovered=() to_allow=()
        local sorted_keys
        sorted_keys=$(printf '%s\n' "${!listening_ports[@]}" | sort -t/ -k1,1n -k2,2)

        while IFS= read -r key; do
            [[ -z "$key" ]] && continue
            local port="${key%%/*}"
            local process="${listening_ports[$key]}"

            # Already allowed?
            is_ufw_allowed "$key" && continue

            # SSH already handled above
            [[ "$key" == "$ssh_spec" ]] && continue

            uncovered+=("$key ($process)")
        done <<< "$sorted_keys"

        if [[ ${#uncovered[@]} -gt 0 ]]; then
            issues_found=$((issues_found + 1))
            echo
            warn "[Issue] ${#uncovered[@]} listening port(s) not explicitly allowed in UFW:"
            for item in "${uncovered[@]}"; do
                echo "    • $item"
            done
            echo
            info "  Recommendation: Review and allow ports that need external access."

            if ask_yes_no "  Interactively review these ports now?" "y"; then
                while IFS= read -r key; do
                    [[ -z "$key" ]] && continue
                    local port="${key%%/*}"
                    local process="${listening_ports[$key]}"

                    is_ufw_allowed "$key" && continue
                    [[ "$key" == "$ssh_spec" ]] && continue

                    echo
                    info "  Port ${C_BOLD}$key${C_RESET} ($process) — ${C_YELLOW}not allowed${C_RESET}"
                    if ask_yes_no "    Allow incoming to $key?" "n"; then
                        to_allow+=("$key")
                    fi
                done <<< "$sorted_keys"

                # Apply chosen rules
                if [[ ${#to_allow[@]} -gt 0 ]]; then
                    local count=0
                    for spec in "${to_allow[@]}"; do
                        if ! is_ufw_allowed "$spec"; then
                            if run_cmd "UFW_ALLOW:$spec" ufw insert 1 allow "$spec" \
                                comment "Allowed by security script $(date +%Y-%m-%d)"; then
                                ufw_rules["$spec"]=1
                                ufw_rule_count=$((ufw_rule_count + 1))
                                count=$((count + 1))
                            fi
                        fi
                    done
                    if (( count > 0 )) && ! $DRY_RUN; then
                        ufw reload && success "UFW reloaded ($count rule(s) added)." || warn "UFW reload failed."
                    fi
                fi
            fi
        else
            success "All listening ports are covered by UFW rules."
        fi
    fi

    # Summary
    echo
    if (( issues_found == 0 )); then
        success "UFW audit: ${C_GREEN}All checks passed.${C_RESET}"
    else
        info "UFW audit: $issues_found issue(s) found and addressed."
    fi
    info "Final UFW status:"
    ufw status verbose 2>/dev/null || true

    echo "--- Section 6 completed ---"; echo
}


# ============================================================================
# SECTION 7: Journald
# ============================================================================
configure_journald() {
    info "${C_BOLD}7. Journald Log Limit — Audit${C_RESET}"

    local config_file="/etc/systemd/journald.conf"
    local key="SystemMaxUse"
    local desired="$JOURNALD_MAX_USE"
    local current=""

    if [[ -f "$config_file" ]]; then
        current=$(grep -E "^\s*${key}=" "$config_file" 2>/dev/null | tail -n1 | cut -d= -f2 | xargs || true)
    fi

    if [[ "$current" == "$desired" ]]; then
        success "Journald $key = '$desired' (OK)"
        echo "--- Section 7 completed ---"; echo; return 0
    fi

    # Issue found
    if [[ -n "$current" ]]; then
        warn "[Issue] Journald $key is '$current' (recommended: '$desired')."
    else
        warn "[Issue] Journald $key not explicitly set (recommended: '$desired')."
    fi
    info "  Recommendation: Limit journal disk usage to prevent log bloat."

    if ! ask_yes_no "  Fix: Set $key to '$desired'?" "y"; then
        echo "--- Section 7 completed ---"; echo; return 0
    fi

    backup_file "$config_file" || return 1
    local temp_conf
    temp_conf=$(mktemp)
    cp "$config_file" "$temp_conf"

    if grep -qE "^\s*#?\s*${key}=" "$temp_conf"; then
        sed -i -E "s|^\s*#?\s*${key}=.*|${key}=${desired}|" "$temp_conf"
    elif grep -q "^\s*\[Journal\]" "$temp_conf"; then
        sed -i "/^\s*\[Journal\]/a ${key}=${desired}" "$temp_conf"
    else
        echo -e "\n[Journal]\n${key}=${desired}" >> "$temp_conf"
    fi

    if $DRY_RUN; then
        dry_run_echo "Apply $key=$desired to $config_file and restart journald"
        rm -f "$temp_conf"
    elif mv "$temp_conf" "$config_file" && chmod 644 "$config_file"; then
        success "  Fixed: $key set to '$desired'."
        log_change "MODIFIED_PARAM:$key:$desired:$config_file"
        run_cmd "SERVICE_RESTARTED:systemd-journald" systemctl restart systemd-journald && \
            success "Journald restarted." || error "Failed to restart journald."
    else
        rm -f "$temp_conf"; restore_file "$config_file"
    fi

    echo "--- Section 7 completed ---"; echo
}


# ============================================================================
# SECTION 8: ClamAV
# ============================================================================
configure_clamav() {
    info "${C_BOLD}8. ClamAV Antivirus Setup${C_RESET}"
    if ! ask_yes_no "Execute this step (ClamAV)?" "y"; then
        info "Step skipped."; echo; return 0
    fi

    local freshclam_svc="clamav-freshclam" clamd_svc="clamav-daemon"
    local db_dir="/var/lib/clamav"
    local initial_ok=false

    ensure_packages_installed "clamav" "clamav-daemon" || return 0

    # Initial freshclam
    info "Checking ClamAV definitions..."
    if systemctl is-active --quiet "$freshclam_svc"; then
        run_cmd "SERVICE_STOPPED:$freshclam_svc (temp)" systemctl stop "$freshclam_svc" || true
        $DRY_RUN || sleep 2
    fi

    if ask_yes_no "Run 'freshclam' now (downloads virus definitions)?" "y"; then
        if run_cmd "COMMAND_RUN:freshclam" freshclam --quiet; then
            success "Freshclam completed."
            initial_ok=true
            $DRY_RUN || sleep 3
        else
            error "Freshclam failed. Check /var/log/clamav/freshclam.log"
        fi
    else
        # Check if definitions exist
        if [[ -f "$db_dir/main.cvd" || -f "$db_dir/main.cld" ]]; then
            info "Definition files already exist."
            initial_ok=true
        fi
    fi

    # Freshclam service
    if systemctl list-unit-files 2>/dev/null | grep -q "^${freshclam_svc}\.service"; then
        ensure_service_running "$freshclam_svc"
    fi

    # Clamd service
    if systemctl list-unit-files 2>/dev/null | grep -q "^${clamd_svc}\.service"; then
        if ! systemctl is-active --quiet "$clamd_svc"; then
            if $initial_ok; then
                local defs_ok=false
                [[ -f "$db_dir/main.cvd" || -f "$db_dir/main.cld" ]] && \
                [[ -f "$db_dir/daily.cvd" || -f "$db_dir/daily.cld" ]] && defs_ok=true

                if $defs_ok; then
                    ensure_service_running "$clamd_svc"
                else
                    warn "Cannot start clamd — definition files missing."
                fi
            else
                warn "Cannot start clamd — freshclam was not successful."
            fi
        else
            success "'$clamd_svc' already active."
            ensure_service_running "$clamd_svc"
        fi
    fi

    echo "--- Section 8 completed ---"; echo
}


# ============================================================================
# SECTION 9: Sysctl Hardening
# ============================================================================
configure_sysctl() {
    info "${C_BOLD}9. Sysctl Security Hardening — Audit${C_RESET}"

    # Define recommended sysctl parameters
    declare -A sysctl_params=(
        # Network security
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.default.rp_filter"]="1"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv6.conf.all.accept_redirects"]="0"
        ["net.ipv6.conf.default.accept_redirects"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.default.send_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.default.accept_source_route"]="0"
        ["net.ipv6.conf.all.accept_source_route"]="0"
        ["net.ipv6.conf.default.accept_source_route"]="0"
        ["net.ipv4.conf.all.log_martians"]="1"
        ["net.ipv4.conf.default.log_martians"]="1"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        ["net.ipv4.tcp_syncookies"]="1"
        # Kernel hardening
        ["kernel.randomize_va_space"]="2"
        ["kernel.sysrq"]="0"
        ["fs.protected_hardlinks"]="1"
        ["fs.protected_symlinks"]="1"
    )

    local issues_found=0
    local params_to_set=()

    info "Checking sysctl parameters against best practices..."
    for param in "${!sysctl_params[@]}"; do
        local desired="${sysctl_params[$param]}"
        local current
        current=$(get_effective_sysctl_config "$param")

        if [[ "$current" == "$desired" ]]; then
            success "  $param = $desired (OK)"
        else
            warn "  [Issue] $param = $current (should be $desired)"
            issues_found=$((issues_found + 1))
            params_to_set+=("$param=$desired")
        fi
    done

    if (( issues_found == 0 )); then
        success "Sysctl audit: ${C_GREEN}All parameters hardened.${C_RESET}"
        echo "--- Section 9 completed ---"; echo; return 0
    fi

    info "$issues_found parameter(s) differ from recommended values."
    info "  Recommendation: Apply hardening to '$SYSCTL_CONFIG_FILE'."

    if ! ask_yes_no "  Fix: Apply sysctl hardening?" "y"; then
        echo "--- Section 9 completed ---"; echo; return 0
    fi

    backup_file "$SYSCTL_CONFIG_FILE"

    if $DRY_RUN; then
        dry_run_echo "Write ${#params_to_set[@]} parameters to $SYSCTL_CONFIG_FILE"
        dry_run_echo "sysctl --system"
    else
        {
            echo "# Sysctl security hardening - generated by security_script.sh v${SCRIPT_VERSION}"
            echo "# $(date)"
            echo
            for entry in "${params_to_set[@]}"; do
                echo "$entry"
            done
        } > "$SYSCTL_CONFIG_FILE"

        chmod 644 "$SYSCTL_CONFIG_FILE"
        log_change "ADDED_FILE:$SYSCTL_CONFIG_FILE"

        if sysctl --system >/dev/null 2>&1; then
            success "  Fixed: ${#params_to_set[@]} sysctl parameter(s) applied."
            log_change "SYSCTL_APPLIED:$SYSCTL_CONFIG_FILE"
        else
            error "Failed to apply sysctl parameters."
        fi
    fi

    echo "--- Section 9 completed ---"; echo
}


# ============================================================================
# SECTION 10: Sudoers TTY Tickets
# ============================================================================
configure_sudoers_tty() {
    info "${C_BOLD}10. Sudoers TTY Ticket Isolation — Audit${C_RESET}"

    # Check current state
    local is_active=false
    if grep -rPh --include='*' '^\s*Defaults\s+([^#]*,\s*)?tty_tickets' /etc/sudoers /etc/sudoers.d/ >/dev/null 2>&1; then
        is_active=true
    fi

    if $is_active; then
        success "Sudoers tty_tickets already active (OK)."
        echo "--- Section 10 completed ---"; echo; return 0
    fi

    # Issue found
    warn "[Issue] tty_tickets not explicitly set."
    info "  TTY tickets ensure sudo credentials are per-terminal, not shared across sessions."
    info "  Recommendation: Add 'Defaults tty_tickets' to '$SUDOERS_TTY_FILE'."

    if ! ask_yes_no "  Fix: Configure tty_tickets?" "y"; then
        echo "--- Section 10 completed ---"; echo; return 0
    fi

    backup_file "$SUDOERS_TTY_FILE"

    local content="# Ensure sudo tickets are per-TTY (generated by security_script.sh)\nDefaults tty_tickets\n"

    if $DRY_RUN; then
        dry_run_echo "Write 'Defaults tty_tickets' to $SUDOERS_TTY_FILE"
        dry_run_echo "visudo -c -f $SUDOERS_TTY_FILE"
    else
        echo -e "$content" > "$SUDOERS_TTY_FILE"
        chmod 0440 "$SUDOERS_TTY_FILE"

        # Validate with visudo
        if visudo -c -f "$SUDOERS_TTY_FILE" >/dev/null 2>&1; then
            success "  Fixed: Sudoers tty_tickets configured."
            log_change "ADDED_FILE:$SUDOERS_TTY_FILE"
        else
            error "Sudoers syntax check failed! Removing file."
            rm -f "$SUDOERS_TTY_FILE"
            restore_file "$SUDOERS_TTY_FILE"
        fi
    fi

    echo "--- Section 10 completed ---"; echo
}


# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    echo "=== Interactive Linux Server Security Script v${SCRIPT_VERSION} ==="
    echo "Checks and configures security settings for Debian/Ubuntu."
    echo "Log file: $SCRIPT_LOG_FILE"
    echo "Backups: Files ending with '$BACKUP_SUFFIX'"
    $DRY_RUN || echo
    warn "Use at your own risk! Create backups beforehand!"
    echo

    if ! ask_yes_no "Proceed?" "y"; then
        info "Exiting."; exit 0
    fi

    # Setup logging
    if ! $DRY_RUN; then
        local log_dir
        log_dir=$(dirname "$SCRIPT_LOG_FILE")
        [[ -d "$log_dir" ]] || mkdir -p "$log_dir" || { error "Cannot create log dir."; exit 1; }
        touch "$SCRIPT_LOG_FILE" || { error "Cannot write log file."; exit 1; }
        log_change "SCRIPT_STARTED Version=$SCRIPT_VERSION"
    else
        info "DRY-RUN: Logging disabled."
    fi

    detect_ssh_service
    info "SSH service: $SSH_SERVICE"

    # Execute all sections in order
    local -a sections=(
        configure_ssh_key_and_users       # 1. SSH Keys
        configure_unattended_upgrades     # 2. Auto Updates
        configure_msmtp                   # 3. Mail Notifications
        configure_ssh_hardening           # 4a. SSH Hardening
        configure_google_2fa              # 4b. Two-Factor Auth
        configure_fail2ban                # 5a. Fail2ban
        configure_sshguard                # 5b. SSHGuard
        configure_ufw                     # 6. Firewall
        configure_journald                # 7. Log Limits
        configure_clamav                  # 8. Antivirus
        configure_sysctl                  # 9. Kernel/Network Hardening
        configure_sudoers_tty             # 10. Sudoers TTY Tickets
    )

    for func in "${sections[@]}"; do
        if declare -f "$func" >/dev/null 2>&1; then
            "$func"
        else
            warn "Function '$func' not defined. Skipping."
        fi
    done

    # Offer backup management
    echo
    if ask_yes_no "View/manage backups created by this script?" "n"; then
        list_backups
        ask_yes_no "Restore a backup?" "n" && restore_backup_interactive
    fi

    echo
    success "=== Script finished ==="
    if ! $DRY_RUN; then
        info "Review: $SCRIPT_LOG_FILE"
        info "Backups have suffix '$BACKUP_SUFFIX'."
        info "A reboot may be recommended."
        log_change "SCRIPT_FINISHED"
    else
        warn "*** DRY-RUN MODE: No changes were made. ***"
    fi
}

main
exit 0
