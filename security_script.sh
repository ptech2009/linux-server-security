#!/bin/bash
# === Interactive Linux Server Security Script (V1.5.1) ===
# Version: 1.5
# Author: Paul Schumacher
# Purpose: Check and harden Debian/Ubuntu servers.
# License: Free to use, but at your own risk. NO WARRANTY.
#
# Backup and Recovery:
# - Before each change, a backup of the affected configuration file is created automatically.
# - In case of errors, an attempt is made to restore the backup.
# - Affected services are automatically restarted as needed.
#
# Whitelisting:
# - Fail2ban: Automatic whitelisting of local network subnets in [DEFAULT] ignoreip.
# - SSHGuard: Automatic whitelisting of local network subnets in /etc/sshguard/whitelist.

# --- Configuration ---
: ${JOURNALD_MAX_USE:="1G"}
SCRIPT_LOG_FILE="/var/log/security_script_changes.log"
BACKUP_SUFFIX=".security_script_backup"
MSMTP_CONFIG_CHOICE="user"  # 'user' (~/.msmtprc) or 'system' (/etc/msmtprc)
SYSCTL_CONFIG_FILE="/etc/sysctl.d/99-security-script.conf"
SUDOERS_TTY_FILE="/etc/sudoers.d/tty_tickets"
# AllowUsers is configured directly in /etc/ssh/sshd_config
SCRIPT_DEBUG=${SCRIPT_DEBUG:-false} # Set SCRIPT_DEBUG=true env var for debug output

# --- Determine the SSH service name ---
if systemctl list-unit-files | grep -q "^ssh\.service"; then
    SSH_SERVICE="ssh"
elif systemctl list-unit-files | grep -q "^sshd\.service"; then
    SSH_SERVICE="sshd"
else
    SSH_SERVICE="sshd" # Default assumption
    # Warning moved to main execution start
fi

# --- Colors for output ---
C_RESET='\e[0m'
C_RED='\e[0;31m'
C_GREEN='\e[0;32m'
C_YELLOW='\e[0;33m'
C_BLUE='\e[0;34m'
C_BOLD='\e[1m'

# --- Global Variables ---
declare -gA ufw_allowed_ports_map # Associative array for UFW allowed ports (Bash 4+)
SCRIPT_APT_UPDATED=false # Track if apt update has run in this script instance

# --- Helper Functions ---
debug() { [[ "$SCRIPT_DEBUG" == "true" ]] && echo -e "${C_YELLOW}DEBUG [${FUNCNAME[1]}]:${C_RESET} $1"; }
info() { echo -e "${C_BLUE}INFO:${C_RESET} $1"; }
success() { echo -e "${C_GREEN}SUCCESS:${C_RESET} $1"; }
warn() { echo -e "${C_YELLOW}WARNING:${C_RESET} $1"; }
error() { echo -e "${C_RED}ERROR:${C_RESET} $1" >&2; }

ask_yes_no() {
    local question="$1" default="$2" answer
    while true; do
        if [[ "$default" == "y" ]]; then
            read -p "$question [Y/n]: " answer
            answer=${answer:-y}
        elif [[ "$default" == "n" ]]; then
            read -p "$question [y/N]: " answer
            answer=${answer:-n}
        else
            read -p "$question [y/n]: " answer
        fi
        case "$answer" in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) warn "Invalid input. Please enter 'y' or 'n'." ;;
        esac
    done
}

is_package_installed() { dpkg -s "$1" &>/dev/null; return $?; }
log_change() { echo "$(date '+%Y-%m-%d %H:%M:%S') | $1" >> "$SCRIPT_LOG_FILE"; }

backup_file() {
    local file="$1" backup_path="${file}${BACKUP_SUFFIX}"
    if [[ -f "$file" ]] && [[ ! -f "$backup_path" ]]; then
        if cp -a "$file" "$backup_path"; then
            info "Backup of '$file' created: '$backup_path'"
            log_change "BACKUP_CREATED:$file:$backup_path"
            return 0
        else
            error "Could not create backup of '$file'."
            return 1
        fi
    elif [[ -f "$backup_path" ]]; then
        info "Backup '$backup_path' already exists."
        return 0
    elif [[ ! -f "$file" ]]; then
        # File doesn't exist, no backup needed, not an error for this function's purpose
        return 0
    fi
    # Should not happen if logic above is correct, but added for safety
    return 1
}

restore_file() {
    local file="$1" backup_path="${file}${BACKUP_SUFFIX}"
    if [[ -f "$backup_path" ]]; then
        if mv "$backup_path" "$file"; then
            success "File '$file' restored from backup '$backup_path'."
            return 0
        else
            error "Restoration of '$file' from backup '$backup_path' failed."
            return 1
        fi
    else
        # Check if the script originally added this file
        if grep -q "ADDED_FILE:$file" "$SCRIPT_LOG_FILE"; then
            if [[ -f "$file" ]]; then
                 info "No backup found for '$file', but logged as ADDED_FILE. Removing file..."
                 if rm "$file"; then
                     success "File '$file' removed."
                     return 0
                 else
                     error "Could not remove file '$file'."
                     return 1
                 fi
            fi
        else
            warn "No backup '$backup_path' found for '$file'. Cannot restore."
        fi
        # It's not an error if there's no backup and the file wasn't added by the script
        return 0
    fi
}

validate_email() { [[ "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && return 0 || return 1; }
validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ] && return 0 || return 1; }

get_effective_sshd_config() {
    local parameter="$1"
    if command -v sshd >/dev/null; then
        # Use sshd -T to get the effective configuration, handling potential case differences
        sshd -T -C user=root -C host=localhost -C addr=127.0.0.1 2>/dev/null | grep -i "^${parameter}[[:space:]]" | head -n 1 | awk '{print $2}'
    else
        echo "sshd_not_found" # Indicate sshd command is missing
    fi
}

get_effective_sysctl_config() {
    local parameter="$1"
    if sysctl "$parameter" >/dev/null 2>&1; then
        sysctl -n "$parameter"
    else
        echo "not_set" # Parameter is not currently set or readable
    fi
}

is_sudo_tty_tickets_active() {
    # Check sudoers and sudoers.d for tty_tickets default, ignoring comments
    if sudo grep -rPh --include=\* '^\s*Defaults\s+([^#]*,\s*)?tty_tickets' /etc/sudoers /etc/sudoers.d/ > /dev/null 2>&1; then
        return 0 # Found active tty_tickets setting
    else
        return 1 # Did not find active tty_tickets setting
    fi
}

is_fail2ban_jail_enabled() {
    local jail_name="$1" jail_local="/etc/fail2ban/jail.local"
    if [[ ! -f "$jail_local" ]]; then return 1; fi # jail.local must exist
    local status
    # Use awk to parse the jail.local file for the specific jail and its 'enabled' status
    status=$(awk -v jail="[$jail_name]" '
        $0 == jail {in_section=1; enabled_status="false"; next} # Found the jail section
        /^\s*\[/ && in_section { exit } # Found the next section, stop parsing
        in_section && /^\s*enabled\s*=\s*true\s*(#.*)?$/ { enabled_status="true"; exit } # Found enabled = true
        in_section && /^\s*enabled\s*=\s*false\s*(#.*)?$/ { enabled_status="false"; next } # Found enabled = false, continue checking section
        END { print enabled_status } # Output the found status (defaults to false)
    ' "$jail_local")
    [[ "$status" == "true" ]] # Return true (0) if status is "true", false (1) otherwise
}


# --- Function definitions for individual sections ---

configure_ssh_key_and_users() {
    info "${C_BOLD}1. Create SSH Key Pair (Ed25519)${C_RESET}"
    if ! ask_yes_no "Execute this step (SSH Key)?" "y"; then
        info "Step skipped."; echo; return 0
    fi

    # Determine the user to check/create the key for (prefer SUDO_USER if set and not root)
    local current_user
    if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
        current_user="$SUDO_USER"
    else
        current_user=$(whoami) # Fallback to current user (likely root if not using sudo)
    fi
    local user_home; user_home=$(eval echo "~$current_user") # Get user's home directory

    # Check for existing Ed25519 keys (both private keys and authorized keys)
    local existing_ed25519_count=0
    if [[ -d "$user_home/.ssh" ]]; then
        # Count public keys matching the type
        existing_ed25519_count=$(find "$user_home/.ssh" -maxdepth 1 -type f -name "*.pub" -exec grep -Eil "ssh-ed25519" {} + 2>/dev/null | wc -l)
        # Count keys of this type within authorized_keys
        if [[ -f "$user_home/.ssh/authorized_keys" ]]; then
            local auth_count
            auth_count=$(grep -Eic "ssh-ed25519" "$user_home/.ssh/authorized_keys")
            existing_ed25519_count=$((existing_ed25519_count + auth_count))
        fi
    fi

    if (( existing_ed25519_count > 0 )); then
        success "At least one Ed25519 key found in '$user_home/.ssh'."
    else
        warn "No Ed25519 key pair found in '$user_home/.ssh'."
    fi

    if ask_yes_no "Create new Ed25519 SSH key pair for '$current_user'?" "n"; then
        local new_key_name; read -p "Filename for new key (e.g., id_ed25519_new): " new_key_name
        new_key_name=${new_key_name:-id_ed25519_new} # Default filename
        local key_path="$user_home/.ssh/$new_key_name"

        # Prompt for passphrase securely
        local passphrase passphrase_confirm
        while true; do
            read -sp "Passphrase (empty = none): " passphrase; echo
            read -sp "Confirm passphrase: " passphrase_confirm; echo
            [[ "$passphrase" == "$passphrase_confirm" ]] && break || warn "Passphrases do not match."
        done

        # Create .ssh directory if it doesn't exist and set correct permissions/ownership
        mkdir -p "$user_home/.ssh"
        chmod 700 "$user_home/.ssh"
        chown "$current_user":"$current_user" "$user_home/.ssh" # Ensure user owns their .ssh dir

        # Generate the key as the target user
        sudo -u "$current_user" ssh-keygen -q -t ed25519 -f "$key_path" -N "$passphrase"
        if [[ $? -eq 0 ]]; then
            success "SSH key pair '${key_path}' created."
            # Set correct permissions for key files
            chmod 600 "$key_path"; chmod 644 "${key_path}.pub"
            chown "$current_user":"$current_user" "$key_path" "${key_path}.pub"
            info "Public key: ${key_path}.pub"
            info "Please add to ~/.ssh/authorized_keys on the target servers."
            [[ -n "$passphrase" ]] && warn "Store passphrase securely!"
            log_change "SSH_KEY_GENERATED:${key_path}"
        else
            error "Error during key creation (as '$current_user')."
        fi
    fi
    echo "--- Section 1 completed ---"
    echo
}

# --- Unattended Upgrades Functions ---

# Check if a specific origin pattern is active (uncommented) in the config file
is_pattern_active() {
    local pattern="$1" config_file="$2"
    debug "Checking for origin '$pattern' in '$config_file'"
    # Pattern should be the string literal including quotes, e.g., "\"${distro_id}:${distro_codename}-security\";"
    # We need to handle potential variable expansion within the pattern if passed directly
    local expanded_pattern; expanded_pattern=$(eval echo "$pattern") # Expand ${distro_id} etc.
    # Escape regex metacharacters in the expanded pattern for use in grep
    local escaped_pattern; escaped_pattern=$(sed 's#[.^$*\[\]()|+?{}\\\/]#\\&#g' <<< "$expanded_pattern") # Use # as delimiter

    # Check if the line exists and is NOT starting with // (allowing for whitespace)
    if grep -qE "^\s*$escaped_pattern" "$config_file"; then
         debug "Result: ACTIVE for '$expanded_pattern'"
         return 0 # Found active pattern
    else
         debug "Result: INACTIVE for '$expanded_pattern'"
         return 1 # Pattern is commented out or missing
    fi
}

# Check if a specific Unattended-Upgrade parameter is set to "true"
is_uu_param_true() {
    local param_key="$1" config_file="$2"
    debug "Checking param '$param_key' in '$config_file'"
    # Extract the value for the parameter, ignoring comments and leading/trailing spaces
    local value
    # Match lines starting with the param key, possibly commented, extract value within quotes
    # Ensure it matches uncommented lines only for the check
    value=$(grep -E "^\s*$param_key\s+\"?" "$config_file" | grep -v '^\s*//' | sed -E 's/^\s*.*\s*"(.*)".*/\1/' | head -n 1)
    debug "Extracted value: '$value'"
    if [[ "$value" == "true" ]]; then
        return 0 # Parameter is true
    else
        return 1 # Parameter is not true or not found uncommented
    fi
}

configure_unattended_upgrades() {
    info "${C_BOLD}2. Configure Unattended Upgrades${C_RESET}"
    if ! ask_yes_no "Execute this step (Unattended Upgrades)?" "y"; then
        info "Step skipped."; echo; return 0
    fi

    local pkg="unattended-upgrades"
    local config_file="/etc/apt/apt.conf.d/50unattended-upgrades"
    local periodic_config_file="/etc/apt/apt.conf.d/20auto-upgrades"

    # Check if package is installed, prompt to install if not
    if ! is_package_installed "$pkg"; then
        warn "'$pkg' not installed."
        if ask_yes_no "Install '$pkg'?" "y"; then
            # Run apt update if not already done by this script run
            if ! $SCRIPT_APT_UPDATED; then
                 info "Running 'apt update'..."
                 apt update && SCRIPT_APT_UPDATED=true || { error "'apt update' failed."; return 1; }
            fi
            apt install -y "$pkg" && log_change "INSTALLED:$pkg" && success "'$pkg' installed." || { error "Installation failed."; return 1; }
        else
            info "Unattended Upgrades skipped."; echo "--- Section 2 completed ---"; echo; return 0
        fi
    else
        success "Package '$pkg' is already installed."
    fi

    info "Checking Unattended Upgrades configuration..."
    local apply_changes=false periodic_correct=true config_correct=true

    # --- Check periodic configuration (20auto-upgrades) ---
    if [[ ! -f "$periodic_config_file" ]]; then
        warn "'$periodic_config_file' does not exist."; periodic_correct=false
    else
        # Check if Update-Package-Lists is "1"
        if ! grep -qE '^\s*APT::Periodic::Update-Package-Lists\s*"1"\s*;' "$periodic_config_file"; then
            warn "APT::Periodic::Update-Package-Lists not set to \"1\" in '$periodic_config_file'."; periodic_correct=false
        fi
        # Check if Unattended-Upgrade is "1"
        if ! grep -qE '^\s*APT::Periodic::Unattended-Upgrade\s*"1"\s*;' "$periodic_config_file"; then
            warn "APT::Periodic::Unattended-Upgrade not set to \"1\" in '$periodic_config_file'."; periodic_correct=false
        fi
    fi
    [[ "$periodic_correct" = false ]] && apply_changes=true || success "'$periodic_config_file' seems correct."

    # --- Check main configuration (50unattended-upgrades) ---
    if [[ ! -f "$config_file" ]]; then
        error "Configuration file '$config_file' not found!"; echo "--- Section 2 completed ---"; echo; return 1
    fi

    # Get distro info needed for patterns
    local distro_id; distro_id=$(lsb_release -is)
    local distro_codename; distro_codename=$(lsb_release -cs)

    # Define patterns for recommended and optional origins
    # These patterns need double quotes for eval expansion in is_pattern_active
    local security_pattern="\"\\${distro_id}:\\${distro_codename}-security\";"
    local updates_pattern="\"\\${distro_id}:\\${distro_codename}-updates\";"
    local esm_infra_pattern="\"\\${distro_id}ESM:\\${distro_codename}-infra-security\";"
    local esm_apps_pattern="\"\\${distro_id}ESMApps:\\${distro_codename}-apps-security\";"
    local proposed_pattern="\"\\${distro_id}:\\${distro_codename}-proposed\";"
    local backports_pattern="\"\\${distro_id}:\\${distro_codename}-backports\";"


    local security_active=false esm_active=false
    if is_pattern_active "$security_pattern" "$config_file"; then security_active=true; fi
    if is_pattern_active "$esm_infra_pattern" "$config_file"; then esm_active=true; fi
    if is_pattern_active "$esm_apps_pattern" "$config_file"; then esm_active=true; fi

    # Security is mandatory (standard or ESM)
    if ! $security_active && ! $esm_active ; then
         warn "Security (\"${distro_id}:${distro_codename}-security\" or ESM) not active."
         config_correct=false
    else
         success "Security origin (Standard or ESM) seems active."
    fi
    # Updates are recommended
    if ! is_pattern_active "$updates_pattern" "$config_file"; then
         warn "Updates (\"${distro_id}:${distro_codename}-updates\") not active."
         config_correct=false
    else
         success "Updates origin seems active."
    fi
    # ESM are optional - report status
    if is_pattern_active "$esm_infra_pattern" "$config_file"; then
         info "ESM Infra (\"${distro_id}ESM:${distro_codename}-infra-security\") is active (optional)."
    else
         info "ESM Infra (\"${distro_id}ESM:${distro_codename}-infra-security\") not active (optional)."
    fi
     if is_pattern_active "$esm_apps_pattern" "$config_file"; then
         info "ESM Apps (\"${distro_id}ESMApps:${distro_codename}-apps-security\") is active (optional)."
    else
         info "ESM Apps (\"${distro_id}ESMApps:${distro_codename}-apps-security\") not active (optional)."
    fi
    # Proposed and backports should be inactive
    if is_pattern_active "$proposed_pattern" "$config_file"; then
        warn "Proposed (\"${distro_id}:${distro_codename}-proposed\") is active (discouraged)."
        config_correct=false
    fi
    if is_pattern_active "$backports_pattern" "$config_file"; then
        warn "Backports (\"${distro_id}:${distro_codename}-backports\") is active (discouraged)."
        config_correct=false
    fi

    # Check boolean parameters
    if ! is_uu_param_true "Unattended-Upgrade::Remove-Unused-Dependencies" "$config_file"; then
        warn "Remove-Unused-Dependencies not set to \"true\"."
        config_correct=false
    else
         success "Remove-Unused-Dependencies is true."
    fi
    if ! is_uu_param_true "Unattended-Upgrade::AutoFixInterruptedDpkg" "$config_file"; then
        warn "AutoFixInterruptedDpkg not set to \"true\"."
        config_correct=false
    else
         success "AutoFixInterruptedDpkg is true."
    fi

    # Check mail notification settings
    local mail_param="Unattended-Upgrade::Mail"
    local mail_only_error_param="Unattended-Upgrade::MailOnlyOnError"
    local mail_value; mail_value=$(grep -E "^\s*$mail_param\s+" "$config_file" | grep -v '^\s*//' | sed -E 's/^\s*.*"(.*)".*/\1/' | head -n 1)
    local mail_only_error_value; mail_only_error_value=$(grep -E "^\s*$mail_only_error_param\s+" "$config_file" | grep -v '^\s*//' | sed -E 's/^\s*.*"(.*)".*/\1/' | head -n 1)

    if [[ -z "$mail_value" ]]; then
        warn "Mail notification address not set or commented out ('$mail_param')."
        # config_correct=false # Don't mark as incorrect just for missing mail address
    else
        success "Mail notification seems configured ($mail_param -> $mail_value)."
    fi
    if [[ "$mail_only_error_value" != "true" ]]; then
        warn "MailOnlyOnError not set to 'true' (will send mail on every upgrade)."
        config_correct=false # Mark config as incorrect if MailOnlyOnError isn't true
    else
         success "MailOnlyOnError set to 'true'."
    fi

    [[ "$config_correct" = false ]] && apply_changes=true || success "Unattended Upgrades configuration meets recommendations."

    # --- Apply changes if needed and confirmed ---
    if [[ "$apply_changes" = true ]]; then
        warn "Settings deviate or are missing from recommendations."
        # --- Apply changes using sed --- ## Modified from V2.8.3 ##
        if ask_yes_no "Apply baseline settings now?" "y"; then
            backup_file "$config_file" || return 1
            backup_file "$periodic_config_file" || return 1 # Backup even if creating new

            # Ask about automatic reboots
            local allow_reboot="false"
            if ask_yes_no "Allow automatic reboots (potentially risky)?" "n"; then
                allow_reboot="true"
                warn "Automatic reboots enabled. Ensure system stability after upgrades."
            fi

            # --- Modify 50unattended-upgrades using sed ---
            info "Applying changes to $config_file..."
            # 1. Ensure required origins are uncommented
            # Need to expand vars for sed patterns
            local sec_patt_exp; sec_patt_exp=$(eval echo "$security_pattern")
            local upd_patt_exp; upd_patt_exp=$(eval echo "$updates_pattern")
            local esm_i_patt_exp; esm_i_patt_exp=$(eval echo "$esm_infra_pattern")
            local esm_a_patt_exp; esm_a_patt_exp=$(eval echo "$esm_apps_pattern")
            # Escape for sed - use # as delimiter, escape /;&*.[^$ etc.
            sec_patt_exp=$(sed 's#[;&/"*./^$\[()|?+{}]#\\&#g' <<< "$sec_patt_exp")
            upd_patt_exp=$(sed 's#[;&/"*./^$\[()|?+{}]#\\&#g' <<< "$upd_patt_exp")
            esm_i_patt_exp=$(sed 's#[;&/"*./^$\[()|?+{}]#\\&#g' <<< "$esm_i_patt_exp")
            esm_a_patt_exp=$(sed 's#[;&/"*./^$\[()|?+{}]#\\&#g' <<< "$esm_a_patt_exp")

            debug "Applying sed for security: s|^\\s*//\\s*(${sec_patt_exp})|\\t\\1|"
            sed -i -E "s|^\\s*//\\s*(${sec_patt_exp})|\t\1|" "$config_file"
            debug "Applying sed for updates: s|^\\s*//\\s*(${upd_patt_exp})|\\t\\1|"
            sed -i -E "s|^\\s*//\\s*(${upd_patt_exp})|\t\1|" "$config_file"
            debug "Applying sed for esm-infra: s|^\\s*//\\s*(${esm_i_patt_exp})|\\t\\1|"
            sed -i -E "s|^\\s*//\\s*(${esm_i_patt_exp})|\t\1|" "$config_file" # Uncomment if present
            debug "Applying sed for esm-apps: s|^\\s*//\\s*(${esm_a_patt_exp})|\\t\\1|"
            sed -i -E "s|^\\s*//\\s*(${esm_a_patt_exp})|\t\1|" "$config_file" # Uncomment if present

            # 2. Ensure discouraged origins are commented
            local prop_patt_exp; prop_patt_exp=$(eval echo "$proposed_pattern")
            local back_patt_exp; back_patt_exp=$(eval echo "$backports_pattern")
            prop_patt_exp=$(sed 's#[;&/"*./^$\[()|?+{}]#\\&#g' <<< "$prop_patt_exp")
            back_patt_exp=$(sed 's#[;&/"*./^$\[()|?+{}]#\\&#g' <<< "$back_patt_exp")

            debug "Applying sed for proposed: s|^(\\s*)(${prop_patt_exp})|//\\1\\2|"
            sed -i -E "s|^([[:space:]]*)(${prop_patt_exp})|//\1\2|" "$config_file" # Add // if not present
            debug "Applying sed for backports: s|^(\\s*)(${back_patt_exp})|//\\1\\2|"
            sed -i -E "s|^([[:space:]]*)(${back_patt_exp})|//\1\2|" "$config_file" # Add // if not present


            # 3. Set boolean parameters
            local params_to_set=(
                "Unattended-Upgrade::Remove-Unused-Dependencies=true"
                "Unattended-Upgrade::AutoFixInterruptedDpkg=true"
                "Unattended-Upgrade::MailOnlyOnError=true"
                "Unattended-Upgrade::Automatic-Reboot=$allow_reboot"
            )
            for item in "${params_to_set[@]}"; do
                local key val
                IFS='=' read -r key val <<< "$item"
                local desired_line="\t${key} \"${val}\";"
                # Check if key exists (commented or not)
                if grep -qE "^\s*//?\s*${key}" "$config_file"; then
                     # Modify existing line, ensure uncommented
                     debug "Modifying parameter $key to $val"
                     sed -i -E "s|^(\s*//?\s*)(${key})\s*.*|${desired_line}|" "$config_file"
                else
                     # Add the line (consider adding under a specific block if possible, otherwise append)
                     warn "Adding missing parameter line: $key = $val"
                     echo -e "$desired_line" >> "$config_file"
                fi
            done
            success "Changes applied to $config_file using sed."
            log_change "MODIFIED:$config_file"


            # --- Modify 20auto-upgrades ---
            mkdir -p "$(dirname "$periodic_config_file")" # Ensure directory exists
            echo "// Generated by security_script.sh" > "$periodic_config_file"
            echo "APT::Periodic::Update-Package-Lists \"1\";" >> "$periodic_config_file"
            echo "APT::Periodic::Unattended-Upgrade \"1\";" >> "$periodic_config_file"
            success "Periodic configuration '$periodic_config_file' created/updated."
            log_change "ADDED_FILE:$periodic_config_file"

            # Re-check Mail notification just for reporting
             local mail_param_recheck="Unattended-Upgrade::Mail"
             local mail_value_recheck; mail_value_recheck=$(grep -E "^\s*$mail_param_recheck\s+" "$config_file" | grep -v '^\s*//' | sed -E 's/^\s*.*"(.*)".*/\1/' | head -n 1)
            if [[ -z "$mail_value_recheck" ]]; then
                 warn "Mail notification address still not set or commented out in '$config_file'."
                 warn "Please edit manually to enable email reports."
            else
                 success "Mail notification seems already configured."
            fi
            # Re-check MailOnlyOnError which should now be true
            local mail_only_error_recheck="Unattended-Upgrade::MailOnlyOnError"
             if ! is_uu_param_true "$mail_only_error_recheck" "$config_file"; then
                 warn "MailOnlyOnError verification failed after applying changes. Please check '$config_file' manually."
             else
                 success "MailOnlyOnError is now set to 'true'."
            fi

        else
             info "No changes applied to Unattended Upgrades configuration."
        fi
    fi ## End apply_changes=true block ##
    echo "--- Section 2 completed ---"
    echo
}


configure_msmtp() {
    info "${C_BOLD}3. MSMTP Setup for System Notifications${C_RESET}"
    if ! ask_yes_no "Execute this step (MSMTP)?" "y"; then
        info "Step skipped."; echo; return 0
    fi

    local msmtp_pkg="msmtp" mta_pkg="msmtp-mta" mailutils_pkg="mailutils"
    local config_file_path config_owner user_home

    # Determine configuration scope (user or system)
    if [[ "$MSMTP_CONFIG_CHOICE" == "user" ]]; then
        local target_user=${SUDO_USER:-$USER} # Suggest current or sudo user
        read -p "For which user should the MSMTP configuration be created? [$target_user]: " config_owner
        config_owner=${config_owner:-$target_user}
        user_home=$(eval echo "~$config_owner") # Get home directory safely
        if [[ -z "$user_home" ]] || [[ ! -d "$user_home" ]]; then
            error "Home directory for '$config_owner' not found."; echo "--- Section 3 completed ---"; echo; return 1
        fi
        config_file_path="$user_home/.msmtprc"
        info "MSMTP will be configured for '$config_owner' in '$config_file_path'."
    else
        config_file_path="/etc/msmtprc"; config_owner="root"; user_home="/root" # System-wide config
        info "MSMTP will be configured system-wide in '$config_file_path'."
    fi

    # Check and prompt for package installation
    local install_pkgs=false
    if ! is_package_installed "$msmtp_pkg" || ! is_package_installed "$mta_pkg"; then
        warn "'$msmtp_pkg' and/or '$mta_pkg' not installed."
        if ask_yes_no "Install packages?" "y"; then install_pkgs=true; else info "MSMTP skipped."; echo "--- Section 3 completed ---"; echo; return 0; fi
    else
        success "Packages '$msmtp_pkg' and '$mta_pkg' are installed."
    fi
    local install_mailutils=false
    if ! is_package_installed "$mailutils_pkg"; then
        warn "Package '$mailutils_pkg' (for 'mail' command) not installed."
        if ask_yes_no "Install '$mailutils_pkg'?" "y"; then install_pkgs=true; install_mailutils=true; fi
    fi

    # Install required packages if confirmed
    if [[ "$install_pkgs" = true ]]; then
        info "Installing required packages..."
        local pkgs_to_install=""
        # Build list of packages actually needing installation
        if ! is_package_installed "$msmtp_pkg"; then pkgs_to_install+="$msmtp_pkg "; fi
        if ! is_package_installed "$mta_pkg"; then pkgs_to_install+="$mta_pkg "; fi
        if [[ "$install_mailutils" = true ]]; then pkgs_to_install+="$mailutils_pkg "; fi


        if [[ -n "$pkgs_to_install" ]]; then
             # Run apt update if not already done by this script run
            if ! $SCRIPT_APT_UPDATED; then
                 info "Running 'apt update'..."
                 apt update && SCRIPT_APT_UPDATED=true || { error "'apt update' failed."; return 1; }
            fi
            apt install -y $pkgs_to_install && success "Packages installed." || { error "Installation failed."; return 1; }
            # Log installations
            [[ "$pkgs_to_install" =~ "$msmtp_pkg" ]] && log_change "INSTALLED:$msmtp_pkg"
            [[ "$pkgs_to_install" =~ "$mta_pkg" ]] && log_change "INSTALLED:$mta_pkg"
            [[ "$pkgs_to_install" =~ "$mailutils_pkg" ]] && log_change "INSTALLED:$mailutils_pkg"
        fi
    fi

    # Check for existing configuration and prompt to overwrite or create
    local configure_msmtp=false
    if [[ -f "$config_file_path" ]]; then
        warn "MSMTP configuration found in '$config_file_path'."
        if ask_yes_no "Recreate the configuration (will overwrite existing file)?" "n"; then configure_msmtp=true; else info "Existing configuration will be kept."; fi
    else
        info "No configuration found in '$config_file_path'."
        if ask_yes_no "Set up MSMTP now?" "y"; then configure_msmtp=true; fi
    fi

    # Configure MSMTP if confirmed
    if [[ "$configure_msmtp" = true ]]; then
        info "Please enter SMTP details:"
        local smtp_host smtp_port smtp_tls smtp_trust_file smtp_from smtp_user smtp_password smtp_aliases

        # Input gathering with validation
        while true; do read -p "SMTP Host: " smtp_host; [[ -n "$smtp_host" ]] && break || warn "Host cannot be empty."; done
        while true; do read -p "SMTP Port [587]: " smtp_port; smtp_port=${smtp_port:-587}; validate_port "$smtp_port" && break || warn "Invalid port."; done
        while true; do read -p "TLS (on/off) [on]: " smtp_tls; smtp_tls=${smtp_tls:-on}; [[ "$smtp_tls" == "on" || "$smtp_tls" == "off" ]] && break || warn "Invalid input (on/off)."; done
        read -p "CA certificate file [/etc/ssl/certs/ca-certificates.crt]: " smtp_trust_file; smtp_trust_file=${smtp_trust_file:-/etc/ssl/certs/ca-certificates.crt}
        while true; do read -p "Sender (From): " smtp_from; validate_email "$smtp_from" && break || warn "Invalid email address."; done
        while true; do read -p "SMTP Username [$smtp_from]: " smtp_user; smtp_user=${smtp_user:-$smtp_from}; validate_email "$smtp_user" && break || warn "Invalid email address."; done
        while true; do read -sp "SMTP Password: " smtp_password; echo; [[ -n "$smtp_password" ]] && break || warn "Password cannot be empty."; done
        read -p "Alias file [/etc/aliases]: " smtp_aliases; smtp_aliases=${smtp_aliases:-/etc/aliases}

        # Show example config and confirm
        info "--- Example Configuration ---"
        echo -e "defaults\nport $smtp_port\ntls $smtp_tls\ntls_trust_file $smtp_trust_file\nlogfile ${user_home}/.msmtp.log\n\naccount root\nhost $smtp_host\nfrom $smtp_from\nauth on\nuser $smtp_user\npassword ********\n\naccount default : root\naliases $smtp_aliases"
        echo "--------------------------------"

        if ask_yes_no "Save these settings to '$config_file_path'?" "y"; then
            backup_file "$config_file_path" || return 1 # Backup before writing

            # Create the configuration file content
cat <<EOF > "$config_file_path"
# MSMTP configuration generated by security_script.sh
defaults
port $smtp_port
tls $smtp_tls
tls_trust_file $smtp_trust_file
logfile ${user_home}/.msmtp.log

account root
host $smtp_host
from $smtp_from
auth on
user $smtp_user
password $smtp_password

# Set default account
account default : root

# Use system aliases file (optional)
aliases $smtp_aliases
EOF
            # Set secure permissions and ownership
            chmod 600 "$config_file_path"
            # Ensure correct ownership, especially for user config
            if [[ "$MSMTP_CONFIG_CHOICE" == "user" ]]; then
                 chown "$config_owner":"$config_owner" "$config_file_path"
                 # Ensure log file dir exists and is writable by user
                 mkdir -p "$(dirname "${user_home}/.msmtp.log")"
                 chown "$config_owner":"$config_owner" "$(dirname "${user_home}/.msmtp.log")"
                 touch "${user_home}/.msmtp.log"
                 chown "$config_owner":"$config_owner" "${user_home}/.msmtp.log"
                 chmod 600 "${user_home}/.msmtp.log"
            else
                 # System config owned by root is usually fine
                 chown root:root "$config_file_path"
                 # Log file location might need adjustment for system-wide
                 touch "${user_home}/.msmtp.log" # Usually /root/.msmtp.log
                 chown root:root "${user_home}/.msmtp.log"
                 chmod 600 "${user_home}/.msmtp.log"
            fi

            success "MSMTP configuration saved in '$config_file_path'."
            log_change "ADDED_FILE:$config_file_path" # Log creation/overwrite

            # Send test email if mailutils is installed
            if is_package_installed "$mailutils_pkg"; then
                if ask_yes_no "Send test email to '$smtp_from'?" "y"; then
                    # Use timeout to prevent hanging if SMTP server is slow/unreachable
                    if timeout 15s echo "This is a test email from the Linux Security Script." | mail -s "MSMTP Test $(date)" "$smtp_from"; then
                        success "Test email sent (check spam folder if not received)."
                    else
                        warn "Could not send test email (timed out or error). Check ${user_home}/.msmtp.log"
                    fi # <<<--- CORRECTED FI LOCATION
                fi
            else
                warn "Package 'mailutils' not found, skipping test email."
            fi
        fi
    fi
    echo "--- Section 3 completed ---"
    echo
}

# Section 4a: Harden SSH configuration (Edit /etc/ssh/sshd_config, including AllowUsers)
configure_ssh_hardening() {
    info "${C_BOLD}4a. Harden SSH Configuration (Editing /etc/ssh/sshd_config)${C_RESET}"
    if ! ask_yes_no "Execute this step (SSH Hardening)?" "y"; then
        info "Step skipped."; echo; return 0
    fi

    # Optional: Configure AllowUsers
    if ask_yes_no "Adjust AllowUsers setting in /etc/ssh/sshd_config?" "n"; then
        local effective_allow_users; effective_allow_users=$(get_effective_sshd_config "allowusers")
        local target_users; local apply_allowusers=false; local suggested_user

        # Suggest the first non-system user as a sensible default
        suggested_user=$(awk -F: '$3 >= 1000 && $3 < 65534 { print $1; exit }' /etc/passwd)
        [[ -z "$suggested_user" ]] && suggested_user="your_admin_user" # Fallback if no user found

        warn "Recommendation: Restrict SSH access to specific admin users (not root)."
        read -p "Which users should have SSH access? (Suggestion: $suggested_user, Space-separated, Empty = skip): " target_users

        if [[ -n "$target_users" ]]; then
            # Validate if all specified users exist
            local all_users_exist=true
            for user in $target_users; do
                if ! id "$user" &>/dev/null; then
                    error "User '$user' does not exist."
                    all_users_exist=false
                fi
            done

            if $all_users_exist; then
                # Compare with current effective setting and prompt for change
                if [[ -n "$effective_allow_users" ]]; then
                    # Normalize space-separated lists for comparison
                    local normalized_effective sorted_effective
                    normalized_effective=$(echo "$effective_allow_users" | tr ' ' '\n' | sort | tr '\n' ' ')
                    sorted_effective=$(echo "$normalized_effective" | sed 's/ $//') # Remove trailing space

                    local normalized_target sorted_target
                    normalized_target=$(echo "$target_users" | tr ' ' '\n' | sort | tr '\n' ' ')
                    sorted_target=$(echo "$normalized_target" | sed 's/ $//') # Remove trailing space

                    if [[ "$sorted_effective" == "$sorted_target" ]]; then
                        success "AllowUsers is already set correctly to '$target_users'."
                    else
                        if ask_yes_no "Change AllowUsers from '$effective_allow_users' to '$target_users'?" "y"; then
                            apply_allowusers=true
                        fi
                    fi
                else
                    # No current AllowUsers setting found
                    if ask_yes_no "Set AllowUsers to '$target_users'?" "y"; then
                        apply_allowusers=true
                    fi
                fi

                # Apply the change if confirmed
                if $apply_allowusers; then
                    backup_file "/etc/ssh/sshd_config" || return 1
                    # Modify or add the AllowUsers line robustly
                    if grep -qE "^\s*#?\s*AllowUsers" /etc/ssh/sshd_config; then
                        # Parameter exists, modify it and ensure uncommented
                         sed -i -E "s|^\s*#?\s*(AllowUsers)\s+.*|AllowUsers $target_users|" /etc/ssh/sshd_config
                    else
                        # Parameter doesn't exist, add it
                        echo "" >> /etc/ssh/sshd_config # Ensure newline before adding
                        echo "AllowUsers $target_users" >> /etc/ssh/sshd_config
                    fi
                    log_change "MODIFIED_PARAM:AllowUsers:$target_users"

                    # Validate config and restart SSH
                    if sshd -t; then
                        if systemctl restart "$SSH_SERVICE"; then
                             # Double-check service status after restart
                             sleep 1 # Give service a moment
                             if systemctl is-active --quiet "$SSH_SERVICE"; then
                                 success "SSH service restarted and AllowUsers set."
                                 log_change "SERVICE_RESTARTED:$SSH_SERVICE"
                             else
                                 error "SSH service inactive after restart. Reverting changes."
                                 restore_file "/etc/ssh/sshd_config" && systemctl try-restart "$SSH_SERVICE"
                                 return 1
                             fi
                        else
                             error "Could not restart SSH service. Reverting changes."
                             restore_file "/etc/ssh/sshd_config" && systemctl try-restart "$SSH_SERVICE"
                             return 1
                        fi
                    else
                        error "SSH configuration test ('sshd -t') failed. Changes will not be applied."
                        restore_file "/etc/ssh/sshd_config"
                        return 1
                    fi
                fi
            else
                info "AllowUsers configuration skipped due to non-existent user(s)."
            fi
        else
            info "AllowUsers configuration skipped."
        fi
    else
        info "AllowUsers configuration skipped."
    fi


    # Further SSH hardening (individual parameters)
    declare -A ssh_recommendations=(
        ["PermitRootLogin"]="prohibit-password" # Disallow root password login, allow key
        ["ChallengeResponseAuthentication"]="no" # Typically used for passwords/OTP via PAM
        ["PasswordAuthentication"]="no"         # Disallow password login entirely (requires key)
        ["UsePAM"]="yes"                        # Enable Pluggable Authentication Modules
        ["X11Forwarding"]="no"                  # Disable GUI forwarding unless needed
        ["PrintLastLog"]="yes"                  # Show last login info
    )

    local current_value recommended_value
    declare -A changes_to_apply # Store changes user agrees to

    # Check for existing SSH keys before disabling password auth
    local current_key_check_user; if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then current_key_check_user="$SUDO_USER"; else current_key_check_user=$(whoami); fi
    local user_key_home; user_key_home=$(eval echo "~$current_key_check_user")
    local ed25519_key_count=0
    if [[ -d "$user_key_home/.ssh" ]]; then
       ed25519_key_count=$(find "$user_key_home/.ssh" -maxdepth 1 -type f -name "*.pub" -exec grep -Eil "ssh-ed25519" {} + 2>/dev/null | wc -l)
       if [[ -f "$user_key_home/.ssh/authorized_keys" ]]; then
         local auth_key_count; auth_key_count=$(grep -Eic "ssh-ed25519" "$user_key_home/.ssh/authorized_keys")
         ed25519_key_count=$((ed25519_key_count + auth_key_count))
       fi
    fi


    # Iterate through recommended settings
    for param in "${!ssh_recommendations[@]}"; do
        current_value=$(get_effective_sshd_config "$param")
        # Handle default value interpretation if not explicitly set by sshd -T
        if [[ -z "$current_value" ]]; then
             if [[ "$param" == "ChallengeResponseAuthentication" ]]; then
                  local pam_status=$(get_effective_sshd_config "UsePAM")
                  [[ "$pam_status" == "yes" ]] && current_value="yes" || current_value="no"
             elif [[ "$param" == "PasswordAuthentication" ]]; then
                 current_value="yes"
             elif [[ "$param" == "PermitRootLogin" ]]; then
                 current_value="yes" # Safer default assumption for comparison
              elif [[ "$param" == "X11Forwarding" ]]; then
                  current_value="no"
              elif [[ "$param" == "PrintLastLog" ]]; then
                  current_value="yes"
             fi
             debug "Parameter '$param' not explicitly set, using assumed default '$current_value' for comparison."
        fi

        recommended_value="${ssh_recommendations[$param]}"

        # Special handling for PermitRootLogin comparison
        if [[ "$param" == "PermitRootLogin" ]]; then
            # Consider both secure options as 'correct'
            if [[ "$current_value" == "without-password" || "$current_value" == "prohibit-password" ]]; then
                success "PermitRootLogin is already secure ($current_value)."
                continue # Skip to next parameter
            fi
        fi

        # Compare current value with recommended value
        if [[ "$current_value" != "$recommended_value" ]]; then
            echo -e "\nParameter: ${C_BOLD}$param${C_RESET}"
            echo "Current: $current_value"
            echo "Recommended: $recommended_value"

            # Provide explanation for the recommendation
            case "$param" in
                "PermitRootLogin")
                    echo "Explanation: Disabling direct root login (with password) hardens against brute-force attacks. 'prohibit-password' still allows key-based root login." ;;
                "ChallengeResponseAuthentication")
                    echo "Explanation: Disabling allows clearer separation; authentication methods managed elsewhere (e.g., PasswordAuthentication, PubkeyAuthentication, PAM)." ;;
                "PasswordAuthentication")
                    echo "Explanation: Key-based authentication is more secure. ${C_RED}WARNING:${C_RESET} Disabling passwords without a working SSH key ${C_BOLD}will lock you out${C_RESET}."
                    if [[ $ed25519_key_count -eq 0 ]]; then
                        warn "No Ed25519 SSH keys found for user '$current_key_check_user'! Please ensure you have a working key before disabling passwords."
                    else
                         success "Found $ed25519_key_count Ed25519 key(s) for '$current_key_check_user'."
                    fi
                     ;;
                "UsePAM")
                    echo "Explanation: PAM enables integration with system authentication policies (like 2FA, password complexity, etc.). Recommended to keep 'yes'." ;;
                "X11Forwarding")
                    echo "Explanation: Disabling X11 forwarding reduces the attack surface if graphical applications are not tunneled over SSH." ;;
                "PrintLastLog")
                    echo "Explanation: Displaying the last login time and location helps identify unauthorized access attempts upon login." ;;
            esac

            # Ask user if they want to apply the change
            local default_answer="y"
            # Default to 'n' for disabling passwords if no keys found
            if [[ "$param" == "PasswordAuthentication" && $ed25519_key_count -eq 0 ]]; then
                default_answer="n"
            fi

            if ask_yes_no "Change $param from '$current_value' to '$recommended_value'?" "$default_answer"; then
                changes_to_apply["$param"]="$recommended_value"
            else
                info "$param remains unchanged."
            fi
        else
            success "$param is already correct ($current_value)."
        fi
    done

    # Apply confirmed changes
    if [ ${#changes_to_apply[@]} -eq 0 ]; then
        info "No further changes selected for SSH hardening."
    else
        info "The following changes will be applied:"
        for key in "${!changes_to_apply[@]}"; do
            echo "  $key -> ${changes_to_apply[$key]}"
        done

        if ask_yes_no "Save changes to '/etc/ssh/sshd_config' and restart SSH?" "y"; then
            backup_file "/etc/ssh/sshd_config" || return 1
            # Apply each confirmed change using sed or adding the line
            for key in "${!changes_to_apply[@]}"; do
                # Check if parameter exists (commented or uncommented)
                if grep -qE "^\s*#?\s*$key" /etc/ssh/sshd_config; then
                    # Modify existing line, ensuring it's uncommented
                     sed -i -E "s|^\s*#?\s*($key)\s+.*|$key ${changes_to_apply[$key]}|" /etc/ssh/sshd_config
                else
                    # Add the parameter if it doesn't exist
                    echo "" >> /etc/ssh/sshd_config # Ensure newline
                    echo "$key ${changes_to_apply[$key]}" >> /etc/ssh/sshd_config
                fi
                log_change "MODIFIED_PARAM:$key:${changes_to_apply[$key]}"
            done

            # Validate configuration and restart SSH service
            if sshd -t; then
                if systemctl restart "$SSH_SERVICE"; then
                    # Double-check service status after restart
                    sleep 1 # Give service a moment
                    if systemctl is-active --quiet "$SSH_SERVICE"; then
                        success "SSH service restarted. Changes applied to /etc/ssh/sshd_config."
                        log_change "SERVICE_RESTARTED:$SSH_SERVICE"
                    else
                        error "SSH service inactive after restart. Reverting changes."
                        restore_file "/etc/ssh/sshd_config" && systemctl try-restart "$SSH_SERVICE"
                        return 1 # Indicate failure
                    fi
                else
                    error "Could not restart SSH service. Reverting changes."
                    restore_file "/etc/ssh/sshd_config" && systemctl try-restart "$SSH_SERVICE" # Attempt recovery restart
                    return 1 # Indicate failure
                fi
            else
                error "SSH configuration test ('sshd -t') failed. Changes will not be applied."
                restore_file "/etc/ssh/sshd_config" # Restore the backup
                return 1 # Indicate failure
            fi
        else
            info "No changes applied to SSH hardening."
        fi
    fi
    echo "--- Section 4a completed ---"
    echo
}

# --- Fail2ban Helper Function ---
# Basic check if an IP or subnet is covered by an ignoreip entry (supports simple private CIDRs)
# Usage: is_ip_covered_by_ignoreip "IP_OR_SUBNET_TO_CHECK" $current_ignoreip_entries_as_string
is_ip_covered_by_ignoreip() {
    local check_item="$1"
    shift # Remove check_item, remaining args are the ignore list items
    local ignore_list_items=("$@")
    local ip_to_check subnet_to_check

    # Determine if check_item is IP or subnet
    if [[ "$check_item" =~ / ]]; then # It's likely a subnet
        subnet_to_check="$check_item"
    else # It's likely an IP
        ip_to_check="$check_item"
        # Derive /24 subnet for IPv4 for checking against broader rules
         if [[ "$ip_to_check" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
             subnet_to_check=$(echo "$ip_to_check" | cut -d. -f1-3).0/24
         fi
         # IPv6 subnet derivation is complex, skip for now in this basic check
    fi
    debug "Checking coverage for IP: '$ip_to_check', Subnet: '$subnet_to_check'"

    for ignored_entry in "${ignore_list_items[@]}"; do
        # 1. Exact match
        if [[ "$ip_to_check" == "$ignored_entry" ]] || [[ "$subnet_to_check" == "$ignored_entry" ]]; then
             debug "$check_item covered by exact match: $ignored_entry"
             return 0
        fi
        # 2. Simple Private CIDR checks (for IPv4)
        if [[ -n "$ip_to_check" ]]; then # Only check if we have an IP
            if ([[ "$ignored_entry" == "192.168.0.0/16" ]] && [[ "$ip_to_check" =~ ^192\.168\. ]]) || \
               ([[ "$ignored_entry" == "172.16.0.0/12" ]] && [[ "$ip_to_check" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]) || \
               ([[ "$ignored_entry" == "10.0.0.0/8" ]] && [[ "$ip_to_check" =~ ^10\. ]]) || \
               ([[ "$ignored_entry" == "$subnet_to_check" ]]); then # Check if covered by derived /24
                debug "$ip_to_check covered by CIDR rule: $ignored_entry"
                return 0
            fi
        fi
         # 3. Check if the item *is* the derived subnet (handles case where only subnet was passed)
         if [[ -n "$subnet_to_check" && "$subnet_to_check" == "$ignored_entry" ]]; then
             debug "$subnet_to_check covered by exact subnet match: $ignored_entry"
             return 0
         fi

        # Add more complex CIDR checks here if needed using external tools or bash functions
    done
    debug "$check_item NOT covered by current ignoreip list."
    return 1 # Not covered
}


configure_fail2ban() {
    info "${C_BOLD}4b. Fail2ban Configuration${C_RESET}"
    if ! ask_yes_no "Configure Fail2ban?" "y"; then
        info "Fail2ban skipped."; echo; return 0
    fi

    local pkg="fail2ban" jail_local="/etc/fail2ban/jail.local" jail_conf="/etc/fail2ban/jail.conf"
    local needs_restart=false # Track if service needs restart due to config change

    # Check if package is installed
    if ! is_package_installed "$pkg"; then
        warn "'$pkg' not installed."
        if ask_yes_no "Install '$pkg'?" "y"; then
            if ! $SCRIPT_APT_UPDATED; then info "Running 'apt update'..."; apt update && SCRIPT_APT_UPDATED=true || { error "'apt update' failed."; return 1; }; fi
            apt install -y "$pkg" && log_change "INSTALLED:$pkg" && success "'$pkg' installed." || { error "Installation failed."; return 1; }
        else
            info "Fail2ban skipped."; return 0
        fi
    else
        success "Package '$pkg' is already installed."
    fi

    # Ensure jail.local exists by copying jail.conf if needed
    if [[ ! -f "$jail_local" ]]; then
        warn "'$jail_local' not found."
        if [[ -f "$jail_conf" ]]; then
            if ask_yes_no "Create '$jail_local' by copying '$jail_conf'?" "y"; then
                 cp "$jail_conf" "$jail_local" && success "Created '$jail_local'." && log_change "ADDED_FILE:$jail_local" || { error "Failed to copy '$jail_conf'."; return 1; }
                 needs_restart=true # New config likely needs service reload
            else
                 error "Cannot proceed without '$jail_local'."; return 1
            fi
        else
             error "'$jail_conf' not found either. Cannot create '$jail_local'."; return 1
        fi
    else
        success "Local Fail2ban configuration '$jail_local' found."
    fi

    # Check [sshd] jail status
    local ssh_jail_name="sshd" # Common name, check if different if needed
    if is_fail2ban_jail_enabled "$ssh_jail_name"; then
        success "Jail '[$ssh_jail_name]' is enabled in '$jail_local'."
    else
        warn "Jail '[$ssh_jail_name]' is not enabled in '$jail_local'."
         if ask_yes_no "Enable jail '[$ssh_jail_name]' now?" "y"; then
             backup_file "$jail_local" || return 1
             # Simple awk script to enable the jail
             local temp_jail_awk; temp_jail_awk=$(mktemp /tmp/f2b-jail.XXXXXX)
             if awk -v jail="[$ssh_jail_name]" '
                BEGIN { enabled_updated = 0; in_section = 0; }
                $0 == jail { in_section = 1; print; next; }
                /^\s*\[/ && NR > 1 && in_section { # Leaving target section
                    if (!enabled_updated) { print "enabled = true"; } # Add if not found/updated
                    in_section = 0;
                    enabled_updated = 1; # Prevent adding again at END
                }
                in_section && /^\s*#?\s*enabled\s*=/ { # Found existing enabled line
                    print "enabled = true";
                    enabled_updated = 1;
                    next; # Skip printing old line
                }
                { print } # Print other lines
                END { if (in_section && !enabled_updated) print "enabled = true"; } # Add if section ends without finding it
             ' "$jail_local" > "$temp_jail_awk"; then
                if mv "$temp_jail_awk" "$jail_local"; then
                    success "Enabled jail '[$ssh_jail_name]' in '$jail_local'."
                    log_change "MODIFIED:$jail_local (Jail $ssh_jail_name enabled)"
                    needs_restart=true
                else
                    error "Failed to move temp file for jail enable."; rm "$temp_jail_awk"; restore_file "$jail_local"; return 1;
                fi
             else
                  error "Failed to process file for jail enable."; rm "$temp_jail_awk"; restore_file "$jail_local"; return 1;
             fi
        fi
    fi

    # --- Whitelist local IPs (Revised Logic) ---
    info "Checking Fail2ban ignoreip for local networks..."
    local current_ignoreip apply_ignoreip=false
    local proposed_additions=() # Store only the IPs/subnets to add this run
    # Get current ignoreip (handle multi-line definitions if necessary)
    current_ignoreip=$(awk '/^\s*\[/{if (in_section) exit; if ($0 == "[DEFAULT]") in_section=1} in_section && /^\s*ignoreip\s*=/{gsub(/^\s*ignoreip\s*=\s*/,""); current_line=$0; while (getline > 0 && $0 ~ /^[[:space:]]/) { current_line=current_line $0 }; gsub(/[[:space:]]+/, " ", current_line); print current_line; exit}' "$jail_local")
    # Read current ignoreip string into an array for easier checking
    read -ra current_ignoreip_array <<< "$current_ignoreip"
    debug "Current ignoreip items from file: ${current_ignoreip_array[*]}"

    # Base ignore list (always include loopback)
    local base_ignore_list=("127.0.0.1/8" "::1")

    # Find all non-loopback IPv4 addresses on the system
    local local_ips4
    local_ips4=$(ip -4 addr show | grep -oP 'inet \K[\d.]+' | grep -v '^127\.')
    debug "Detected local IPv4: $local_ips4"

    # Check local IPs
    for ip in $local_ips4; do
         local subnet4; subnet4=$(echo "$ip" | cut -d. -f1-3).0/24

         # Check if IP OR its /24 subnet is covered by existing rules using the helper function
         if ! is_ip_covered_by_ignoreip "$ip" "${current_ignoreip_array[@]}" && \
            ! is_ip_covered_by_ignoreip "$subnet4" "${current_ignoreip_array[@]}"; then

             # Check if already proposed in *this run*
             local already_proposed=false
             for proposed in "${proposed_additions[@]}"; do
                 if [[ "$subnet4" == "$proposed" ]]; then
                     already_proposed=true; break
                 fi
             done

             if ! $already_proposed; then
                 warn "Local IP $ip (subnet $subnet4) not found or covered in current ignoreip."
                 apply_ignoreip=true
                 proposed_additions+=("$subnet4") # Add the /24 subnet
                 info "Will propose adding '$subnet4' to ignoreip."
             fi
        else
              debug "IP $ip or subnet $subnet4 is already covered by ignoreip."
        fi
    done

    # If changes proposed, build final list and apply
    if [[ "$apply_ignoreip" = true ]]; then
        # Create the new full list: base loopback + unique current entries + unique new proposals
        local final_ignoreip_list
        final_ignoreip_list=$(printf '%s\n' "${base_ignore_list[@]}" "${current_ignoreip_array[@]}" "${proposed_additions[@]}" | sort -u | tr '\n' ' ')
        final_ignoreip_list=$(echo "$final_ignoreip_list" | sed 's/ $//') # Trim trailing space

        info "Proposed updated ignoreip list: $final_ignoreip_list"
        if ask_yes_no "Update ignoreip in [DEFAULT] section of '$jail_local'?" "y"; then
             backup_file "$jail_local" || return 1
             # Use awk to find [DEFAULT] and replace/add ignoreip line
             local temp_f2b_awk; temp_f2b_awk=$(mktemp /tmp/f2b-awk.XXXXXX)
             # Refined awk script to handle single/multi-line replacement better
              if awk -v ignorelist="$final_ignoreip_list" '
                BEGIN { added=0; in_default_section=0 }
                /^\s*\[DEFAULT\]/ { print; in_default_section=1; next } # Print section header and mark entry
                /^\s*\[/ && NR > 1 && in_default_section { # Leaving DEFAULT section
                    if (!added) { print "ignoreip = " ignorelist }; # Add if not found within section
                    in_default_section=0;
                    added=1; # Prevent adding again at END
                    print; # Print the new section header
                    next;
                }
                in_default_section && /^\s*#?\s*ignoreip\s*=/ { # Found existing ignoreip line start
                    if (!added) { # Replace only the first occurrence in section
                       print "ignoreip = " ignorelist;
                       added=1;
                    }
                    # Skip the rest of the old definition (potentially multi-line)
                    while (getline > 0 && $0 ~ /^[[:space:]]+/) { next }
                    # If the line that broke the loop is not empty/comment and not a new section, print it
                    if ( $0 !~ /^\s*([#;]|$)/ && $0 !~ /^\s*\[/ ) { print }
                    # Handle if the breaking line was a new section header
                    if ( $0 ~ /^\s*\[/ ) {
                         if (!added && in_default_section) { print "ignoreip = " ignorelist }; # Add if missed
                         in_default_section=0; added=1; print;
                     }
                    next;
                }
                { print } # Print other lines
                END { if (in_default_section && !added) print "ignoreip = " ignorelist } # Add if DEFAULT is last section
             ' "$jail_local" > "$temp_f2b_awk"; then
                 if mv "$temp_f2b_awk" "$jail_local"; then
                     success "ignoreip updated in '$jail_local'."
                     log_change "MODIFIED:$jail_local (ignoreip updated)"
                     needs_restart=true
                 else
                     error "Failed to move temp file for ignoreip update."; rm "$temp_f2b_awk"; restore_file "$jail_local"; return 1;
                 fi
             else
                  error "Failed to process file for ignoreip update."; rm "$temp_f2b_awk"; restore_file "$jail_local"; return 1;
             fi
        fi
    else
         success "All detected local IPv4 subnets seem covered by ignoreip."
    fi


    # Check Fail2ban service status
    info "Checking Fail2ban service status..."
    if ! systemctl is-active --quiet "$pkg"; then
        warn "Fail2ban service is not active."
        if ask_yes_no "Start Fail2ban service now?" "y"; then
             systemctl start "$pkg" && success "Fail2ban service started." && log_change "SERVICE_RESTARTED:$pkg" || error "Failed to start Fail2ban."
        fi
    elif [[ "$needs_restart" = true ]]; then
         info "Configuration changed, restarting Fail2ban..."
         # Use reload instead of restart if possible for less disruption
         if systemctl reload-or-restart "$pkg"; then
              success "Fail2ban service reloaded/restarted."
              log_change "SERVICE_RELOADED:$pkg"
         else
              error "Failed to reload/restart Fail2ban."
         fi
    else
         success "Fail2ban service is active."
    fi

    if ! systemctl is-enabled --quiet "$pkg"; then
        warn "Fail2ban service is not enabled for system startup."
        if ask_yes_no "Enable Fail2ban service now?" "y"; then
             systemctl enable "$pkg" && success "Fail2ban service enabled." && log_change "SERVICE_ENABLED:$pkg" || error "Failed to enable Fail2ban."
        fi
    else
        success "Fail2ban service is enabled."
    fi

    echo "--- Section 4b completed ---"
    echo
}

configure_sshguard() {
    info "${C_BOLD}4c. SSHGuard Configuration${C_RESET}"
    if ! ask_yes_no "Configure SSHGuard?" "y"; then
        info "SSHGuard skipped."; echo; return 0
    fi

    local pkg="sshguard" whitelist_file="/etc/sshguard/whitelist"
    local needs_restart=false # Track if service needs restart

    # Check if package is installed
    if ! is_package_installed "$pkg"; then
        warn "'$pkg' not installed."
        if ask_yes_no "Install '$pkg'?" "y"; then
             if ! $SCRIPT_APT_UPDATED; then info "Running 'apt update'..."; apt update && SCRIPT_APT_UPDATED=true || { error "'apt update' failed."; return 1; }; fi
             apt install -y "$pkg" && log_change "INSTALLED:$pkg" && success "'$pkg' installed." || { error "Installation failed."; return 1; }
        else
            info "SSHGuard skipped."; return 0
        fi
    else
        success "Package '$pkg' is already installed."
    fi

    # Check service status
    info "Checking SSHGuard service status..."
    local needs_start=false needs_enable=false

    if ! systemctl is-active --quiet "$pkg"; then
        warn "SSHGuard service is not active."; needs_start=true
    else
        success "SSHGuard service is active."
    fi
    if ! systemctl is-enabled --quiet "$pkg"; then
        warn "SSHGuard service is not enabled for system startup."; needs_enable=true
    else
        success "SSHGuard service is enabled."
    fi

    # Determine firewall backend
    local backend
    if command -v ufw > /dev/null && ufw status | grep -q "Status: active"; then
        backend="UFW"
        info "SSHGuard should block using UFW."
    elif command -v nft > /dev/null && nft list ruleset | grep -q 'hook input'; then
         backend="nftables"
         info "SSHGuard should block using nftables."
    elif command -v iptables > /dev/null && iptables -L INPUT -n | grep -q 'Chain INPUT'; then
         backend="iptables"
         info "SSHGuard should block using iptables."
    else
         backend="UNKNOWN"
         warn "Could not determine active firewall backend (UFW, nftables, iptables). SSHGuard might not block IPs effectively."
    fi


    # Check and manage whitelist
    info "Checking SSHGuard whitelist..."
    mkdir -p "$(dirname "$whitelist_file")" # Ensure directory exists
    if [[ ! -f "$whitelist_file" ]]; then
        info "Whitelist '$whitelist_file' not found. Creating empty file."
        touch "$whitelist_file" && log_change "ADDED_FILE:$whitelist_file" || { error "Failed to create whitelist file."; }
    else
        info "Whitelist '$whitelist_file' found."
    fi

    local apply_whitelist=false warned_sipcalc=false
    local proposed_whitelist=()
    # Always add loopback addresses
    proposed_whitelist+=("127.0.0.1")
    proposed_whitelist+=("::1")

    # Find local non-loopback IPs and add their /24 or /64 subnets
    local local_ips4 local_ips6
    local_ips4=$(ip -4 addr show | grep -oP 'inet \K[\d.]+' | grep -v '^127\.')
    local_ips6=$(ip -6 addr show scope global | grep -oP 'inet6 \K[0-9a-fA-F:]+' ) # Global scope IPv6

    for ip in $local_ips4; do
         local subnet4; subnet4=$(echo "$ip" | cut -d. -f1-3).0/24
         # Add if not already present in the proposed list
         if ! printf '%s\n' "${proposed_whitelist[@]}" | grep -qxF "$subnet4"; then
              proposed_whitelist+=("$subnet4")
         fi
    done
     for ip in $local_ips6; do
          local cidr6=""
          if command -v sipcalc >/dev/null; then
              local subnet6; subnet6=$(sipcalc "$ip" | awk '/Network address/ {print $NF}')
              local prefix6; prefix6=$(sipcalc "$ip" | awk '/Network mask \(prefix\)/ {print $NF}')
              if [[ -n "$subnet6" ]] && [[ -n "$prefix6" ]]; then
                  cidr6="${subnet6}/${prefix6}"
              fi
          fi
           # Fallback if sipcalc not available or fails
           if [[ -z "$cidr6" ]]; then
               # Avoid repeating the warning if sipcalc isn't installed
               if ! command -v sipcalc >/dev/null && [[ "$warned_sipcalc" != "true" ]]; then
                    warn "Cannot determine IPv6 subnet precisely (is 'sipcalc' installed?). Using /64 as fallback."
                    warned_sipcalc=true # Prevent repeated warnings
               fi
               # Basic /64 extraction - NOTE: This is a rough guess and might not be the actual subnet
               IFS=':' read -ra parts <<< "$ip"
               local subnet_guess; subnet_guess=$(printf "%s:%s:%s:%s::" "${parts[0]}" "${parts[1]}" "${parts[2]}" "${parts[3]}")
               cidr6="${subnet_guess}/64" # Use the guessed /64 subnet
           fi

          if ! printf '%s\n' "${proposed_whitelist[@]}" | grep -qxF "$cidr6"; then
               proposed_whitelist+=("$cidr6")
          fi
     done

    # Check if proposed IPs/subnets are already in the file
    local missing_items=()
    # Read existing whitelist into an associative map for efficient checking
    declare -A existing_whitelist_map
    if [[ -f "$whitelist_file" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Skip empty lines and comments
            [[ -z "$line" ]] || [[ "$line" =~ ^# ]] && continue
            existing_whitelist_map["$line"]=1
            debug "Read existing whitelist item: $line"
        done < "$whitelist_file"
    fi

    debug "Checking proposed whitelist items against existing map..."
    for item in "${proposed_whitelist[@]}"; do
        # Check if the item exists as a key in the map
        if [[ ! -v existing_whitelist_map["$item"] ]]; then
             debug "Item '$item' missing from whitelist file."
             missing_items+=("$item")
             apply_whitelist=true
        fi
    done

    if [[ "$apply_whitelist" = true ]]; then
        warn "Some local IPs/subnets are missing from '$whitelist_file': ${missing_items[*]}"
        if ask_yes_no "Add missing local IPs/subnets to whitelist '$whitelist_file'?" "y"; then
            backup_file "$whitelist_file" || return 1
            # Append missing items to the file
            printf '%s\n' "${missing_items[@]}" >> "$whitelist_file"
            if [[ $? -eq 0 ]]; then
                 # Optional: Sort and unique the file after adding
                 local temp_wl_sort; temp_wl_sort=$(mktemp /tmp/sshguard-wl-sort.XXXXXX)
                 sort -u "$whitelist_file" > "$temp_wl_sort" && mv "$temp_wl_sort" "$whitelist_file" || warn "Could not sort/unique whitelist file."

                 success "Updated SSHGuard whitelist '$whitelist_file'."
                 log_change "MODIFIED:$whitelist_file (Added missing local IPs/subnets)"
                 needs_restart=true # SSHGuard needs to reload its whitelist
            else
                 error "Failed to append to whitelist file."
                 restore_file "$whitelist_file"
                 return 1
            fi
        fi
    else
        success "All detected local IPs/subnets seem to be present in '$whitelist_file'."
    fi


    # Start/Enable/Restart service as needed
    if [[ "$needs_start" = true ]]; then
        if systemctl start "$pkg"; then success "SSHGuard service started."; log_change "SERVICE_RESTARTED:$pkg"; else error "Error starting SSHGuard."; fi
    elif [[ "$needs_restart" = true ]]; then
        info "Configuration changed, restarting SSHGuard..."
        if systemctl restart "$pkg"; then success "SSHGuard service restarted."; log_change "SERVICE_RESTARTED:$pkg"; else error "Error restarting SSHGuard."; fi
    fi
    if [[ "$needs_enable" = true ]]; then
        if systemctl enable "$pkg"; then success "SSHGuard permanently enabled."; log_change "SERVICE_ENABLED:$pkg"; else error "Error enabling SSHGuard."; fi
    fi


    echo "--- Section 4c completed ---"
    echo
}

# --- UFW Firewall Functions ---

# Function to parse 'ufw status' and populate the global map with numeric ports only
get_ufw_allowed_ports() {
    # Needs bash 4+ for associative arrays
    # declare -gA ufw_allowed_ports_map (declared globally)

    # Reset the map for fresh status
    ufw_allowed_ports_map=()
    debug "Reset ufw_allowed_ports_map"

    # Check if UFW is active first
    if ! ufw status | grep -q "Status: active"; then
        warn "UFW is inactive. Cannot get allowed ports."
        return 1 # Indicate failure to get ports
    fi

    # Capture UFW status output once to parse it
    local ufw_output
    ufw_output=$(ufw status)

    # Add debug output to see what we're working with
    debug "Raw UFW Status:"
    debug "$ufw_output"

    # Process the output to extract port numbers
    local port_list
    port_list=$(echo "$ufw_output" | awk '
        # Skip everything until we find the header line
        /^To[ \t]+Action[ \t]+From/ { in_rules = 1; next }

        # Process only if we are in the rules section
        in_rules {
            # Skip blank lines
            if (NF == 0) next

            # Look for ALLOW action
            if ($2 ~ /ALLOW/) {
                # Extract port numbers from different formats in the "To" column
                to_field = $1

                # Format: 22/tcp
                if (to_field ~ /^[0-9]+\/(tcp|udp)$/) {
                    split(to_field, parts, "/")
                    port = parts[1]
                    if (port > 0 && port < 65536) print port
                }
                # Format: 22 (standalone number that is a port)
                else if (to_field ~ /^[0-9]+$/) {
                    port = to_field
                    if (port > 0 && port < 65536) print port
                }
                # Handle service names that may appear instead of port numbers
                else if (to_field ~ /^[a-zA-Z]+\/(tcp|udp)$/) {
                    # Service names like "ssh/tcp" are handled here
                    # You could use getent services to resolve these if needed
                    debug "Service name found: " to_field
                }
            }
        }
    ' | sort -un)

    # Populate the associative array
    while read -r port; do
        if [[ -n "$port" && "$port" =~ ^[0-9]+$ ]]; then
            ufw_allowed_ports_map["$port"]=1
            debug "Added allowed UFW port: $port"
        fi
    done <<< "$port_list"

    debug "Finished populating ufw_allowed_ports_map. Size: ${#ufw_allowed_ports_map[@]}"
    # Debug: List all allowed ports
    for port in "${!ufw_allowed_ports_map[@]}"; do
        debug "UFW allowed port in map: $port"
    done
    return 0 # Return success
}

# Function to identify listening ports with protocol information
get_listening_ports() {
    # Execute ss to get TCP and UDP listening sockets
    local ss_tcp_output ss_udp_output
    ss_tcp_output=$(ss -ltn)
    ss_udp_output=$(ss -lun)

    debug "Raw ss TCP output:"
    debug "$ss_tcp_output"
    debug "Raw ss UDP output:"
    debug "$ss_udp_output"

    # Parse ss TCP output to extract port numbers with protocol
    local tcp_port_list
    tcp_port_list=$(echo "$ss_tcp_output" | awk '
        # Skip the header line
        NR > 1 {
            # Extract port from the Local Address:Port column (usually $4 or $5)
            for (i = 1; i <= NF; i++) {
                if ($i ~ /:/) {  # Find field containing colon (address:port format)
                    split($i, addr_parts, ":")
                    # Get the last part (port number)
                    port = addr_parts[length(addr_parts)]
                    # If port contains % (interface), remove it
                    sub(/%.*$/, "", port)
                    # Validate port is numeric and in valid range
                    if (port ~ /^[0-9]+$/ && port > 0 && port < 65536) {
                        print port ",tcp"
                    }
                }
            }
        }
    ')

    # Parse ss UDP output to extract port numbers with protocol
    local udp_port_list
    udp_port_list=$(echo "$ss_udp_output" | awk '
        # Skip the header line
        NR > 1 {
            # Extract port from the Local Address:Port column (usually $4 or $5)
            for (i = 1; i <= NF; i++) {
                if ($i ~ /:/) {  # Find field containing colon (address:port format)
                    split($i, addr_parts, ":")
                    # Get the last part (port number)
                    port = addr_parts[length(addr_parts)]
                    # If port contains % (interface), remove it
                    sub(/%.*$/, "", port)
                    # Validate port is numeric and in valid range
                    if (port ~ /^[0-9]+$/ && port > 0 && port < 65536) {
                        print port ",udp"
                    }
                }
            }
        }
    ')

    # Combine TCP and UDP port lists
    echo "${tcp_port_list}"
    echo "${udp_port_list}"

    # Debug: show what ports we found
    debug "Detected listening ports from ss:"
    while IFS="," read -r port proto; do
        if [[ -n "$port" && -n "$proto" ]]; then
            debug "  - Listening port: $port/$proto"
        fi
    done <<< "${tcp_port_list}${udp_port_list:+$'\n'$udp_port_list}"
}

get_container_ports() {
    # Check if Docker is installed and running
    if command -v docker &>/dev/null && systemctl is-active --quiet docker; then
        debug "Docker detected, checking for container ports..."
        # Get ports exposed by running Docker containers
        local docker_ports
        docker_ports=$(docker ps --format '{{.Ports}}' | grep -oE ':[0-9]+->' | tr -d ':>' | sort -un)

        if [[ -n "$docker_ports" ]]; then
            # Add protocol information (assume TCP for simplicity)
            while read -r port; do
                if [[ -n "$port" ]]; then
                    echo "${port},tcp"
                    debug "Found Docker port: ${port}/tcp"
                fi
            done <<< "$docker_ports"
        fi
    else
        debug "Docker not detected or not running."
    fi

    # Check if Podman is installed
    if command -v podman &>/dev/null; then
        debug "Podman detected, checking for container ports..."
        # Get ports exposed by running Podman containers
        local podman_ports
        podman_ports=$(podman ps --format '{{.Ports}}' 2>/dev/null | grep -oE ':[0-9]+->' | tr -d ':>' | sort -un)

        if [[ -n "$podman_ports" ]]; then
            # Add protocol information (assume TCP for simplicity)
            while read -r port; do
                if [[ -n "$port" ]]; then
                    echo "${port},tcp"
                    debug "Found Podman port: ${port}/tcp"
                fi
            done <<< "$podman_ports"
        fi
    else
        debug "Podman not detected."
    fi
}

configure_ufw() {
    info "${C_BOLD}5. UFW (Firewall) Configuration${C_RESET}"
    if ! ask_yes_no "Execute this step (UFW)?" "y"; then
        info "Step skipped."; echo; return 0
    fi

    if ! is_package_installed "ufw"; then
        warn "UFW package not installed."
        if ask_yes_no "Install UFW?" "y"; then
             if ! $SCRIPT_APT_UPDATED; then info "Running 'apt update'..."; apt update && SCRIPT_APT_UPDATED=true || { error "'apt update' failed."; return 1; }; fi
             apt install -y ufw && success "UFW installed." && log_change "INSTALLED:ufw" || { error "UFW installation failed."; return 1; }
             # Enable UFW after installation? Ask user.
             if ask_yes_no "Enable UFW firewall now (might disconnect SSH if rule missing)? WARNING!" "n"; then
                  ufw enable && success "UFW enabled." || error "Failed to enable UFW."
             fi
        else
            info "UFW skipped."; return 0
        fi
    fi

    info "Checking UFW status and rules..."
    ufw status verbose # Show detailed status

    if ! ufw status | grep -q "Status: active"; then
        warn "UFW is installed but not active."
        if ask_yes_no "Enable UFW now (might disconnect SSH if rule missing)? WARNING!" "n"; then
            # Ensure SSH port is allowed BEFORE enabling
            local ssh_port_ufw; ssh_port_ufw=$(get_effective_sshd_config "port")
            ssh_port_ufw=${ssh_port_ufw:-22} # Default to 22 if not found
            if validate_port "$ssh_port_ufw"; then
                info "Ensuring SSH port $ssh_port_ufw is allowed before enabling UFW..."
                ufw allow "$ssh_port_ufw/tcp" comment "Allow SSH access before UFW enable"
            else
                warn "Could not determine SSH port. Skipping pre-allow rule."
            fi
            # Now enable
            ufw enable && success "UFW enabled." || error "Failed to enable UFW."
        else
            info "UFW remains inactive."; echo "--- Section 5 completed ---"; echo; return 0
        fi
    else
        success "UFW is active."
    fi

    # Get currently allowed ports using the improved function
    # This populates the global ufw_allowed_ports_map with numeric ports only
    if ! get_ufw_allowed_ports; then
         # Error message is printed inside the function if UFW is inactive
         error "Could not reliably get UFW allowed ports. Skipping interactive check."
         echo "--- Section 5 completed ---"; echo; return 1
    fi
    info "Currently allowed ports in UFW map (found ${#ufw_allowed_ports_map[@]} entries)."
    # Print the map content for debugging
    debug "UFW allowed ports in map:"
    for key in "${!ufw_allowed_ports_map[@]}"; do debug " - $key"; done

    # Identify listening ports with protocol information
    info "Determining listening host ports..."
    local host_ports_str; host_ports_str=$(get_listening_ports)

    # Create associative array for listening ports with protocol info
    declare -A listening_ports_map

    if [[ -z "$host_ports_str" ]]; then
        warn "Could not detect any listening host ports via ss."
    else
        while IFS="," read -r port proto; do
            if [[ -n "$port" && -n "$proto" ]]; then
                listening_ports_map["$port"]="$proto"
                debug "Added listening port to map: $port/$proto"
            fi
        done <<< "$host_ports_str"
        success "Detected ${#listening_ports_map[@]} listening host ports."
    fi

    # Identify container ports
    info "Determining container ports..."
    local container_ports_str; container_ports_str=$(get_container_ports)

    if [[ -n "$container_ports_str" ]]; then
        while IFS="," read -r port proto; do
            if [[ -n "$port" && -n "$proto" ]]; then
                listening_ports_map["$port"]="$proto"
                debug "Added container port to map: $port/$proto"
            fi
        done <<< "$container_ports_str"
        success "Added container ports to the listening ports map."
    else
        info "No container ports detected."
    fi

    if [[ ${#listening_ports_map[@]} -eq 0 ]]; then
        info "No listening ports found to check against firewall."
        echo "--- Section 5 completed ---"; echo; return 0
    fi

    # Get current SSH port
    local ssh_port; ssh_port=$(get_effective_sshd_config "port")
    ssh_port=${ssh_port:-22} # Default to 22
    if validate_port "$ssh_port"; then
        success "Detected SSH Port: $ssh_port."
    else
        warn "Could not reliably determine SSH port, assuming 22."
        ssh_port=22
    fi

    # Interactively check ports
    info "Starting interactive port allow check..."
    local ports_to_allow=() ports_to_deny=() port_info

    for port in "${!listening_ports_map[@]}"; do
        local proto="${listening_ports_map[$port]}"

        # Debug: Check port comparison
        debug "Checking port $port/$proto against UFW allowed ports map"

        # Check if port is already allowed (pure numeric comparison)
        if [[ -v ufw_allowed_ports_map["$port"] ]]; then
            info "Port $port already allowed in UFW (Skipping)."
            continue
        fi

        # Always allow the detected SSH port for TCP
        if [[ "$port" == "$ssh_port" && "$proto" == "tcp" ]]; then
            info "SSH port $port/$proto -> Will be automatically ALLOWED."
            ports_to_allow+=("$port/$proto")
            continue # Move to next port
        fi

        # --- Port is listening but not explicitly allowed in UFW ---

        # Get process info for context (best effort)
        if [[ "$proto" == "tcp" ]]; then
            port_info=$(ss -ltnp "sport = :$port" 2>/dev/null | awk 'NR==2 { match($0, /users:\(\("([^"]+)"/); if (RSTART) print substr($0, RSTART+8, RLENGTH-9) }')
        else
            port_info=$(ss -lunp "sport = :$port" 2>/dev/null | awk 'NR==2 { match($0, /users:\(\("([^"]+)"/); if (RSTART) print substr($0, RSTART+8, RLENGTH-9) }')
        fi
        [[ -z "$port_info" ]] && port_info="Unknown Process"

        echo # Add newline for readability
        info "Detected listening port: ${C_BOLD}$port/$proto${C_RESET} (Process: $port_info) - ${C_YELLOW}Not allowed in UFW.${C_RESET}"

        # Ask user whether to allow this port/protocol
        if ask_yes_no "Allow incoming connections to $port/$proto?" "n"; then
            ports_to_allow+=("$port/$proto")
            success "Port $port/$proto -> Marked for ALLOW."
        else
            warn "Port $port/$proto -> Marked for DENY (no rule will be added)."
            ports_to_deny+=("$port/$proto") # Track denials for summary
        fi
    done

    # Apply the rules chosen by the user
    if [[ ${#ports_to_allow[@]} -gt 0 ]]; then
        info "Applying new ALLOW rules for: ${ports_to_allow[*]}"
        local rule_applied=false
        for rule in "${ports_to_allow[@]}"; do
            # Extract port number from rule (e.g. from "9100/tcp" get "9100")
            local port_num="${rule%%/*}"

            # Add comment to identify rules added by the script
            local comment="Allowed by security script v2.8.4" # Update version in comment

            # Check if port is already allowed
            if [[ ! -v ufw_allowed_ports_map["$port_num"] ]]; then
                if ufw insert 1 allow "$rule" comment "$comment"; then
                    success "Rule 'ALLOW $rule' added."
                    log_change "UFW_RULE_ADDED:ALLOW $rule"
                    ufw_allowed_ports_map["$port_num"]=1 # Update map with newly allowed port
                    rule_applied=true
                else
                    error "Failed to add rule 'ALLOW $rule'."
                fi
            else
                info "Rule for port '$port_num' seems to exist already. Skipping add."
            fi
        done
        # Refresh map if rules were added
        if $rule_applied; then get_ufw_allowed_ports; fi
    else
        info "No new ports selected to be allowed."
    fi

    echo # Newline before summary
    info "--- UFW Summary ---"
    info "Final UFW Status:"
    ufw status verbose # Show final status

    # Get final allowed ports list AFTER applying changes (map should be up-to-date)
    local final_allowed_str=""
    # Sort the keys for consistent output
    local sorted_keys
    sorted_keys=$(printf '%s\n' "${!ufw_allowed_ports_map[@]}" | sort -n)
    while IFS= read -r key; do final_allowed_str+="$key "; done <<< "$sorted_keys"
    final_allowed_str=$(echo "$final_allowed_str" | sed 's/ $//') # Trim trailing space

    info "Allowed Ports (numeric values): $final_allowed_str"
    if [[ ${#ports_to_deny[@]} -gt 0 ]]; then
        info "Ports user chose NOT to allow in this run: ${ports_to_deny[*]}"
    fi

    echo "--- Section 5 completed ---"
    echo
}

# End of ufw functions



configure_journald() {
    info "${C_BOLD}6. Configure Systemd-Journald Log Limit${C_RESET}" # Adjusted section number
    if ! ask_yes_no "Execute this step (Journald Log Limit)?" "y"; then
        info "Step skipped."; echo; return 0
    fi

    local config_file="/etc/systemd/journald.conf"
    local param_key="SystemMaxUse"
    local desired_value="${JOURNALD_MAX_USE}" # Use value from config section

    info "Checking Journald disk usage limit..."
    # Check current value (ignoring comments and whitespace)
    local current_value
    if [[ -f "$config_file" ]]; then
        # Grep for uncommented line, get last match, extract value after '='
        current_value=$(grep -E "^\s*$param_key=" "$config_file" | tail -n 1 | cut -d'=' -f2 | sed 's/^[ \t]*//;s/[ \t]*$//')
    else
         warn "Journald config file '$config_file' not found. Cannot check current limit."
         current_value=""
    fi

    if [[ "$current_value" == "$desired_value" ]]; then
        success "Journald $param_key is already set to '$desired_value' in '$config_file'."
    else
        if [[ -n "$current_value" ]]; then
             warn "Journald $param_key currently set to '$current_value' (or commented out/default)."
        else
             warn "Journald $param_key is not explicitly set."
        fi
        info "Recommended value: $desired_value"

        if ask_yes_no "Set $param_key to '$desired_value' in '$config_file'?" "y"; then
            backup_file "$config_file" || return 1
            # Modify or add the parameter robustly
            if grep -qE "^\s*#?\s*$param_key=" "$config_file"; then
                 # Modify existing line, ensure uncommented
                 sed -i -E "s|^\s*#?\s*($param_key)\s*=.*|$param_key=$desired_value|" "$config_file"
            else
                 # Add under [Journal] section, or append if section missing
                 if grep -q "^\s*\[Journal\]" "$config_file"; then
                      # Insert after [Journal] line
                      sed -i "/^\s*\[Journal\]/a $param_key=$desired_value" "$config_file"
                 else
                      warn "Could not find [Journal] section in '$config_file'. Appending setting."
                      # Add section header if missing entirely
                      if ! grep -q "^\s*\[Journal\]" "$config_file"; then
                           echo "" >> "$config_file" # Ensure newline
                           echo "[Journal]" >> "$config_file"
                      fi
                      echo "$param_key=$desired_value" >> "$config_file"
                 fi
            fi
            success "$param_key set to '$desired_value' in '$config_file'."
            log_change "MODIFIED_PARAM:$param_key:$desired_value:$config_file"

            # Restart journald service to apply changes
            info "Restarting systemd-journald service..."
            if systemctl restart systemd-journald; then
                 success "systemd-journald restarted."
                 log_change "SERVICE_RESTARTED:systemd-journald"
            else
                 error "Failed to restart systemd-journald. Changes might not be active yet."
                 # Not restoring file here, as the config change is likely valid
            fi
        else
            info "$param_key remains unchanged."
        fi
    fi

    echo "--- Section 6 completed ---"
    echo
}

# --- Main Script Execution ---
echo "=== Interactive Linux Server Security Script (V2.8.4) ==="
echo "Checks and configures security settings."
echo "Log file: $SCRIPT_LOG_FILE"
echo "Backups: Files ending with '$BACKUP_SUFFIX'"
warn "Use at your own risk! Create backups beforehand!"
echo

if ! ask_yes_no "Proceed?" "y"; then
    info "Exiting."
    exit 0
fi

# Check root privileges
if [[ "$(id -u)" -ne 0 ]]; then
   error "This script must be run as root or with sudo."
   exit 1
fi

# Check Bash version for associative array support (used by UFW)
if (( BASH_VERSINFO[0] < 4 )); then
    error "Bash version 4 or higher is required for this script (due to associative arrays)."
    exit 1
fi

# Ensure log file exists and is writable
if ! touch "$SCRIPT_LOG_FILE" &>/dev/null; then
    # Attempt to create the directory if it doesn't exist
    log_dir=$(dirname "$SCRIPT_LOG_FILE")
    if [[ ! -d "$log_dir" ]]; then
        mkdir -p "$log_dir" || { error "Cannot create log directory: $log_dir"; exit 1; }
    fi
    # Try touching again
    if ! touch "$SCRIPT_LOG_FILE" &>/dev/null; then
         error "Cannot write to log file: $SCRIPT_LOG_FILE"
         exit 1
    fi
fi
log_change "SCRIPT_STARTED Version=2.8.4"
# Determine SSH Service Name only once here
if [[ -z "$SSH_SERVICE" ]]; then # Check if detection failed earlier
    warn "Could not definitively determine SSH service name, assuming 'sshd'."
    SSH_SERVICE="sshd"
fi
info "Using SSH Service Name: $SSH_SERVICE" # Inform user


# --- Call Functions ---
# Reset apt update tracker for this run
SCRIPT_APT_UPDATED=false

configure_ssh_key_and_users
configure_unattended_upgrades
configure_msmtp
configure_ssh_hardening
configure_fail2ban # Run this before SSHGuard if both used
configure_sshguard
configure_ufw
configure_journald # Add calls for other functions

# --- Optional Uninstall/Cleanup ---
# info "Optional Uninstall Steps:" # Commented out for now
# Add logic here if needed to revert changes based on the log file or backups

# --- End of Script ---
success "=== Script finished ==="
info "Please review the output and the log file ($SCRIPT_LOG_FILE)."
info "Backups, if created, are in the same directory ending with '$BACKUP_SUFFIX'."
info "In case of issues: Check log file, UFW status ('sudo ufw status'), service statuses."
info "A system reboot is recommended to ensure all changes are effective."
log_change "SCRIPT_FINISHED"

exit 0
