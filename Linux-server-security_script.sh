#!/bin/bash

# === Interactive Linux Server Security Script ===
# Version: 1.7.3
# Original Author: Paul Schumacher
# Purpose: Check and harden Debian/Ubuntu servers
# License: Free to use, but at your own risk.
# NO WARRANTY.
#
# Backup and Recovery:
# - Before each change, a backup of the affected configuration file is created automatically.
# - In case of errors, an attempt is made to restore the backup.
# - Affected services are automatically restarted as needed.
#
# Whitelisting:
# - Fail2ban: Automatic whitelisting of local network subnets in [DEFAULT] ignoreip.
# - SSHGuard: Automatic whitelisting of local network subnets in /etc/sshguard/whitelist.
#
# Dry-Run Feature:
# - Use --dry-run option to simulate changes without applying them.

# --- Configuration ---
: ${JOURNALD_MAX_USE:="1G"}
SCRIPT_LOG_FILE="/var/log/security_script_changes.log"
BACKUP_SUFFIX=".security_script_backup"
MSMTP_CONFIG_CHOICE="user"  # 'user' (~/.msmtprc) or 'system' (/etc/msmtprc)
SYSCTL_CONFIG_FILE="/etc/sysctl.d/99-security-script.conf"
SUDOERS_TTY_FILE="/etc/sudoers.d/tty_tickets"
# AllowUsers is configured directly in /etc/ssh/sshd_config
SCRIPT_DEBUG=${SCRIPT_DEBUG:-false} # Set SCRIPT_DEBUG=true env var for debug output

# --- Global Variables ---
DRY_RUN=false # Global flag for Dry-Run mode
declare -gA ufw_allowed_ports_map # Associative array for UFW allowed ports (Bash 4+)
SCRIPT_APT_UPDATED=false # Track if apt update has run in this script instance

# --- Argument Parsing for --dry-run ---
TEMP=$(getopt -o '' --long dry-run -n "$0" -- "$@")
if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi
eval set -- "$TEMP" # Note the quotes

while true; do
  case "$1" in
    --dry-run ) DRY_RUN=true; shift ;;
    -- ) shift; break ;;
    * ) break ;;
  esac
done

# Check root privileges *after* parsing args
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root!" >&2
    exit 1
fi

# Announce Dry-Run mode if active
if $DRY_RUN; then
    echo -e "\n\e[1;35m*** DRY-RUN MODE ACTIVE: No changes will be made. ***\e[0m\n"
fi


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
C_MAGENTA='\e[0;35m' # Added Magenta for Dry Run
C_BOLD='\e[1m'

# --- Helper Functions ---
debug() { [[ "$SCRIPT_DEBUG" == "true" ]] && echo -e "${C_YELLOW}DEBUG [${FUNCNAME[1]}]:${C_RESET} $1"; }
info() { echo -e "${C_BLUE}INFO:${C_RESET} $1"; }
success() { echo -e "${C_GREEN}SUCCESS:${C_RESET} $1"; }
warn() { echo -e "${C_YELLOW}WARNING:${C_RESET} $1"; }
error() { echo -e "${C_RED}ERROR:${C_RESET} $1" >&2; }
dry_run_echo() { # DRY-RUN Handling: Function to echo dry-run actions
    echo -e "${C_MAGENTA}DRY-RUN:${C_RESET} Would execute: $1"
}

# DRY-RUN Handling: Wrapper for executing commands
# Usage: execute_command "Description for log" "command" "arg1" "arg2" ...
execute_command() {
    local log_description="$1"
    shift # Remove description from arguments
    local command_str="$*" # The rest is the command and its arguments

    if $DRY_RUN; then
        dry_run_echo "$command_str"
        # Simulate success in dry-run to allow script logic to proceed
        # unless it's a command meant to produce output that's captured,
        # in which case, more complex simulation might be needed.
        # For most system changes, returning 0 is sufficient.
        return 0
    else
        info "Executing: $command_str" # Log execution when not in dry run
        eval "$command_str" # Use eval to handle complex commands/pipelines correctly
        local exit_code=$?
        if [[ $exit_code -eq 0 ]]; then
            log_change "$log_description" # Log successful change
            return 0
        else
            error "Command failed with exit code $exit_code: $command_str"
            return $exit_code
        fi
    fi
}

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

log_change() {
    # DRY-RUN Handling: Do not write to log file in dry-run mode
    if ! $DRY_RUN; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') | $1" >> "$SCRIPT_LOG_FILE";
    fi
}

backup_file() {
    local file="$1" backup_path="${file}${BACKUP_SUFFIX}"
    if [[ -f "$file" ]] && [[ ! -f "$backup_path" ]]; then
        # DRY-RUN Handling
        if $DRY_RUN; then
            dry_run_echo "cp -a \"$file\" \"$backup_path\""
            return 0 # Assume success in dry run
        else
            if cp -a "$file" "$backup_path"; then
                info "Backup of '$file' created: '$backup_path'"
                log_change "BACKUP_CREATED:$file:$backup_path"
                return 0
            else
                error "Could not create backup of '$file'."
                return 1
            fi
        fi
    elif [[ -f "$backup_path" ]]; then
        info "Backup '$backup_path' already exists."
        return 0
    elif [[ ! -f "$file" ]]; then
        # File doesn't exist, no backup needed
        return 0
    fi
    return 1 # Should not happen
}

restore_file() {
    local file="$1" backup_path="${file}${BACKUP_SUFFIX}"
    if [[ -f "$backup_path" ]]; then
        # DRY-RUN Handling
        if $DRY_RUN; then
            dry_run_echo "mv \"$backup_path\" \"$file\""
            return 0 # Assume success
        else
            if mv "$backup_path" "$file"; then
                success "File '$file' restored from backup '$backup_path'."
                log_change "FILE_RESTORED:$file:$backup_path" # Log restoration
                return 0
            else
                error "Restoration of '$file' from backup '$backup_path' failed."
                return 1
            fi
        fi
    else
        # Check if the script originally added this file (only check log if NOT dry run)
        if ! $DRY_RUN && grep -q "ADDED_FILE:$file" "$SCRIPT_LOG_FILE"; then
            if [[ -f "$file" ]]; then
                 info "No backup found for '$file', but logged as ADDED_FILE. Removing file..."
                 # DRY-RUN Handling for removal
                 if execute_command "REMOVED_ADDED_FILE:$file" "rm \"$file\""; then
                     success "File '$file' removed."
                     return 0
                 else
                     error "Could not remove file '$file'."
                     return 1
                 fi
            fi
        else
            # Only warn if not in dry run or if file exists unexpectedly
            if ! $DRY_RUN || [[ -f "$file" ]]; then
                warn "No backup '$backup_path' found for '$file'. Cannot restore."
            fi
        fi
        return 0 # Not an error if no backup and not added by script
    fi
}


validate_email() { [[ "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && return 0 || return 1; }
validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ] && return 0 || return 1; }

get_effective_sshd_config() {
    local parameter="$1"
    if command -v sshd >/dev/null; then
        # Use sshd -T to get the effective configuration, handling potential case differences
        sshd -T -C user=root -C host=localhost -C addr=127.0.0.1 2>/dev/null | \
        grep -i "^${parameter}[[:space:]]" | head -n 1 | \
        awk '{print $2}'
    else
        echo "sshd_not_found" # Indicate sshd command is missing
    fi
}

# NEW Function: Get uncommented value directly from sshd_config file
get_config_file_sshd_setting() {
    local parameter="$1"
    local config_file="/etc/ssh/sshd_config"
    if [[ -f "$config_file" ]]; then
        # Grep for uncommented line, case-insensitive, get last match, extract value
        grep -iE "^\s*${parameter}\s+" "$config_file" | \
        tail -n 1 | \
        awk '{print $2}'
    else
        echo "config_not_found"
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

# --- Google 2FA ---
configure_google_2fa() {
    info "${C_BOLD}5. Configure Google Authenticator 2FA${C_RESET}"
    if ! ask_yes_no "Execute Google Authenticator setup?" "y"; then
        info "Skipping Google Authenticator."; echo;
        return 0
    fi

    local target_user=${SUDO_USER:-$(whoami)}
    local user_home
    user_home=$(eval echo "~$target_user")

    info "Setting up 2FA for user: ${target_user}"

    if [[ -f "${user_home}/.google_authenticator" ]]; then
        if ! ask_yes_no "Google Authenticator already configured for ${target_user}. Reconfigure?" "n"; then
            info "Keeping existing configuration."; echo;
            return 0
        fi
        # DRY-RUN Handling: If reconfiguring, note the potential removal/overwrite
        if $DRY_RUN; then
             dry_run_echo "Potential overwrite/removal of ${user_home}/.google_authenticator"
        fi
    fi

    # 1) Paket installieren
    local pkg="libpam-google-authenticator"
    if ! is_package_installed "$pkg"; then
        info "Installing $pkg..."
        # DRY-RUN Handling
        if execute_command "INSTALLED:$pkg" "apt-get install -y \"$pkg\""; then
            success "$pkg installed successfully."
        else
            error "Failed to install $pkg"
            return 1
        fi
    else
        success "$pkg already installed."
    fi

    # 2) Interaktive Konfiguration
    info "Now initializing Google Authenticator for ${target_user}..."
    echo "- You'll need to scan a QR code with your Google Authenticator app"
    echo "- Save your emergency scratch codes in a secure location"
    echo "- Answer 'y' to the following security-related questions"
    echo

    # DRY-RUN Handling: Skip the actual interactive command, just explain
    if $DRY_RUN; then
        dry_run_echo "sudo -u \"$target_user\" google-authenticator -t -f -d -r 3 -R 30 -w 17"
        info "DRY-RUN: Skipping interactive Google Authenticator setup for $target_user."
        # Simulate success for PAM/SSH config steps
    else
      if ! sudo -u "$target_user" google-authenticator -t -f -d -r 3 -R 30 -w 17; then
          error "Google Authenticator setup failed for user ${target_user}."
          return 1
      fi
       success "Google Authenticator initialized for ${target_user}. Scan the QR code with your authenticator app."
       echo "IMPORTANT: Note down your emergency scratch codes!"
    fi
    echo

    # 3) PAM-Konfiguration (/etc/pam.d/sshd) anpassen
    local pam_file="/etc/pam.d/sshd"
    info "Configuring PAM for SSH..."

    if [[ ! -f "$pam_file" ]]; then error "PAM configuration file $pam_file not found!"; return 1; fi
    backup_file "$pam_file" || return 1

    # Temporäre Datei für PAM Änderungen
    local temp_pam_file
    temp_pam_file=$(mktemp)
    cp "$pam_file" "$temp_pam_file" # Work on a copy

    local pam_changed=false
    # common-auth auskommentieren
    if grep -q "^@include common-auth" "$temp_pam_file"; then
        sed -i 's/^@include common-auth/#@include common-auth/' "$temp_pam_file"
        info "Commented out common-auth in temporary PAM file."
        pam_changed=true
    fi
    # Google-Auth-Modul eintragen
    if ! grep -q "pam_google_authenticator.so" "$temp_pam_file"; then
        echo "auth required pam_google_authenticator.so nullok" >> "$temp_pam_file"
        info "Added Google Authenticator PAM line to temporary PAM file."
        pam_changed=true
    elif ! grep -q "pam_google_authenticator.so nullok" "$temp_pam_file"; then
        sed -i 's/pam_google_authenticator.so/pam_google_authenticator.so nullok/' "$temp_pam_file"
        info "Added nullok option to Google Authenticator PAM line in temporary PAM file."
        pam_changed=true
    fi

    # Änderungen an PAM-Datei übernehmen
    if $pam_changed; then
        # DRY-RUN Handling
        if $DRY_RUN; then
            dry_run_echo "mv \"$temp_pam_file\" \"$pam_file\""
            dry_run_echo "chmod 644 \"$pam_file\"" # Although mv usually preserves permissions
            success "DRY-RUN: Would update $pam_file for Google Authenticator."
        else
            if mv "$temp_pam_file" "$pam_file"; then
                chmod 644 "$pam_file"
                log_change "MODIFIED:$pam_file (Google Authenticator PAM)"
                success "Updated $pam_file for Google Authenticator."
            else
                error "Failed to apply PAM changes to $pam_file"
                rm -f "$temp_pam_file" 2>/dev/null
                restore_file "$pam_file"
                return 1
            fi
        fi
    else
        success "$pam_file already configured for Google Authenticator."
        rm -f "$temp_pam_file" 2>/dev/null
    fi


    # 4) SSHD-Config (/etc/ssh/sshd_config) anpassen
    local ssh_conf="/etc/ssh/sshd_config"
    info "Configuring SSH daemon..."

    if [[ ! -f "$ssh_conf" ]]; then error "SSH configuration file $ssh_conf not found!"; return 1; fi
    backup_file "$ssh_conf" || return 1

    local temp_ssh_conf
    temp_ssh_conf=$(mktemp)
    cp "$ssh_conf" "$temp_ssh_conf"
    local ssh_conf_changed=false

    # Function to modify or add SSHD config line in the temp file
    set_sshd_param() {
        local key="$1" value="$2" file="$3" changed_flag_ref="$4"
        local current_val_in_file
        current_val_in_file=$(grep -iE "^\s*${key}\s+" "$file" | tail -n 1 | awk '{print $2}')

        # Compare case-insensitively
        if [[ -n "$current_val_in_file" ]] && [[ "$(echo "$current_val_in_file" | tr '[:upper:]' '[:lower:]')" == "$(echo "$value" | tr '[:upper:]' '[:lower:]')" ]]; then
            debug "SSHD Param '$key' already set to '$value' in temp file."
            return # Already correct
        fi

        if grep -qE "^\s*#?\s*$key" "$file"; then
            sed -i -E "s|^\s*#?\s*($key)\s+.*|$key $value|" "$file"
        else
            echo "$key $value" >> "$file"
        fi
        info "Set '$key $value' in temporary SSH config."
        eval "$changed_flag_ref=true" # Set the changed flag via indirect reference
    }

     # Set necessary SSHD parameters for 2FA
    set_sshd_param "ChallengeResponseAuthentication" "yes" "$temp_ssh_conf" ssh_conf_changed
    set_sshd_param "KbdInteractiveAuthentication" "yes" "$temp_ssh_conf" ssh_conf_changed
    set_sshd_param "AuthenticationMethods" "publickey,keyboard-interactive" "$temp_ssh_conf" ssh_conf_changed
    # Ensure UsePAM is yes (important for google_authenticator)
    set_sshd_param "UsePAM" "yes" "$temp_ssh_conf" ssh_conf_changed


    # Änderungen an SSH-Datei übernehmen
    if $ssh_conf_changed; then
         # DRY-RUN Handling
        if $DRY_RUN; then
            dry_run_echo "mv \"$temp_ssh_conf\" \"$ssh_conf\""
            dry_run_echo "chmod 644 \"$ssh_conf\""
            success "DRY-RUN: Would update $ssh_conf for Google Authenticator."
        else
            # Validate syntax BEFORE moving
            if sshd -t -f "$temp_ssh_conf"; then
                 if mv "$temp_ssh_conf" "$ssh_conf"; then
                     chmod 644 "$ssh_conf"
                     log_change "MODIFIED:$ssh_conf (Google Authenticator SSH settings)"
                     success "Updated $ssh_conf for Google Authenticator."
                 else
                     error "Failed to apply SSH config changes to $ssh_conf"
                     rm -f "$temp_ssh_conf" 2>/dev/null
                     restore_file "$ssh_conf"
                     return 1
                 fi
            else
                 error "SSHD config test failed on temporary file. Changes not applied."
                 rm -f "$temp_ssh_conf" 2>/dev/null
                 restore_file "$ssh_conf" # Restore original if temp file is bad
                 return 1
            fi
        fi
    else
        success "$ssh_conf already configured for Google Authenticator."
        rm -f "$temp_ssh_conf" 2>/dev/null
    fi


    # 5) SSH neu starten (nur wenn Änderungen vorgenommen wurden)
    if $pam_changed || $ssh_conf_changed; then
        local ssh_services=("ssh" "sshd")
        local restart_success=false

        info "Restarting SSH service..."
        for service in "${ssh_services[@]}"; do
            if systemctl is-active --quiet "$service"; then
                 # DRY-RUN Handling
                 if execute_command "SERVICE_RESTARTED:$service (2FA setup)" "systemctl restart \"$service\""; then
                    success "Service $service restarted successfully."
                    restart_success=true
                    break # Important: break after successful restart
                 else
                    # Error message handled by execute_command
                    # Attempt to restore config if restart fails when NOT in dry run
                    if ! $DRY_RUN; then
                        error "Restart failed. Attempting to restore previous config..."
                        if $pam_changed; then restore_file "$pam_file"; fi
                        if $ssh_conf_changed; then restore_file "$ssh_conf"; fi
                        # Try restarting again after restore
                        execute_command "SERVICE_RESTARTED:$service (after 2FA restore)" "systemctl try-restart \"$service\""
                    fi # <<< This is the corrected closing fi for the 'if ! $DRY_RUN' block
                    # Even if restore fails, we should indicate the main failure
                    restart_success=false # Ensure it's marked as failed
                    break # Stop trying other service names
                 fi
            fi
        done

        # Fallback logic removed as execute_command handles failure reporting
        # if ! $restart_success && ! $DRY_RUN; then
        #    warn "Could not determine/restart the correct SSH service. Please restart manually."
        # fi
    else
        info "No PAM or SSH config changes made, skipping SSH restart."
    fi

    echo
    info "--- Google Authenticator setup completed (or simulated) ---"
    echo
    info "${C_BOLD}IMPORTANT NOTES:${C_RESET}"
    echo "1. Test the new login in a separate SSH session before closing this one!"
    echo "2. Make sure your authenticator app shows correct codes."
    echo "3. Keep your emergency scratch codes in a safe place."
    echo

    return 0
}
# --- End of Google Authenticator 2FA ---

# --- SSH Key and Users ---
configure_ssh_key_and_users() {
    info "${C_BOLD}1. Create SSH Key Pair (Ed25519)${C_RESET}"
    if ! ask_yes_no "Execute this step (SSH Key)?" "y"; then
        info "Step skipped."; echo;
        return 0
    fi

    local current_user
    if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
        current_user="$SUDO_USER"
    else
        current_user=$(whoami)
    fi
    local user_home
    user_home=$(eval echo "~$current_user")

    # Check existing keys (no changes made here)
    local existing_ed25519_count=0
    if [[ -d "$user_home/.ssh" ]]; then
        existing_ed25519_count=$(find "$user_home/.ssh" -maxdepth 1 -type f -name "*.pub" -exec grep -Eil "ssh-ed25519" {} + 2>/dev/null | wc -l)
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

    if ask_yes_no "Create new Ed25519 SSH key pair for '$current_user'?" "y"; then
        local new_key_name
        read -p "Filename for new key (e.g., id_ed25519_new): " new_key_name
        new_key_name=${new_key_name:-id_ed25519_$(date +%Y%m%d)}
        local key_path="$user_home/.ssh/$new_key_name"
        local pub_key_path="${key_path}.pub"
        local authorized_keys_path="$user_home/.ssh/authorized_keys"

        if [[ -f "$key_path" || -f "$pub_key_path" ]]; then
             warn "Key file '$key_path' or '$pub_key_path' already exists."
             if ! ask_yes_no "Overwrite existing key files?" "n"; then
                  info "Skipping key generation.";
                  echo "--- Section 1 completed ---"; echo; return 0
             fi
             # DRY-RUN Handling: Note potential overwrite
             if $DRY_RUN; then
                 dry_run_echo "Potential overwrite of '$key_path' or '$pub_key_path'"
             fi
        fi

        local passphrase passphrase_confirm
        while true; do
            read -sp "Passphrase (empty = none): " passphrase; echo
            read -sp "Confirm passphrase: " passphrase_confirm; echo
            [[ "$passphrase" == "$passphrase_confirm" ]] && break || warn "Passphrases do not match."
        done

        # Create .ssh directory (run as root first, then chown)
        # DRY-RUN Handling for directory and permissions
        execute_command "MKDIR_SSH:$user_home/.ssh" "mkdir -p \"$user_home/.ssh\"" && \
        execute_command "CHMOD_SSH_DIR:$user_home/.ssh" "chmod 700 \"$user_home/.ssh\"" && \
        execute_command "CHOWN_SSH_DIR:$user_home/.ssh" "chown \"$current_user\":\"$current_user\" \"$user_home/.ssh\"" || \
          { error "Failed to prepare SSH directory."; return 1; }


        # Generate the key as the target user
        info "Generating new SSH key pair..."
        local ssh_keygen_cmd="sudo -u \"$current_user\" ssh-keygen -q -t ed25519 -f \"$key_path\" -N \"$passphrase\""
        # DRY-RUN Handling
        if $DRY_RUN; then
            dry_run_echo "$ssh_keygen_cmd"
            # Simulate success for subsequent steps in dry run
            # Assume key files would be created for permission setting simulation
            dry_run_echo "chmod 600 \"$key_path\""
            dry_run_echo "chmod 644 \"$pub_key_path\""
            dry_run_echo "chown \"$current_user\":\"$current_user\" \"$key_path\" \"$pub_key_path\""
            success "DRY-RUN: Simulated SSH key generation for '$key_path'."
            # Simulate adding to authorized_keys
            dry_run_echo "Check/Create $authorized_keys_path"
            dry_run_echo "Append content of $pub_key_path to $authorized_keys_path"
            success "DRY-RUN: Simulated adding public key to '$authorized_keys_path'."
        else # Actual execution
            if eval "$ssh_keygen_cmd"; then
                success "SSH key pair '${key_path}' created."
                # Set correct permissions (as root, then chown)
                chmod 600 "$key_path" && \
                chmod 644 "$pub_key_path" && \
                chown "$current_user":"$current_user" "$key_path" "$pub_key_path" || \
                  { error "Failed to set permissions on key files.";
                  rm -f "$key_path" "$pub_key_path"; return 1; } # Cleanup on perm error
                log_change "SSH_KEY_GENERATED:${key_path}"

                # Display Private Key
                echo; warn "--- Private Key ($(basename "$key_path")) --- SENSIBLE INFORMATION! ---"
                if [[ -f "$key_path" ]]; then sudo -u "$current_user" cat "$key_path"; else error "Could not read private key '$key_path'."; fi
                warn "--- End Private Key --- Copy this to a secure location ---"; echo

                # Automatically Add Public Key to authorized_keys
                info "Adding public key to '$authorized_keys_path'..."
                # Ensure authorized_keys file exists with correct perms/ownership (run as user)
                if ! sudo -u "$current_user" test -f "$authorized_keys_path"; then
                     sudo -u "$current_user" touch "$authorized_keys_path" && \
                     sudo -u "$current_user" chmod 600 "$authorized_keys_path" || \
                       { error "Failed to create or set permissions on '$authorized_keys_path'.";
                       return 1; }
                     info "Created '$authorized_keys_path'."
                     log_change "ADDED_FILE:$authorized_keys_path"
                fi

                # Check if key already present (run grep as user)
                local pub_key_content
                pub_key_content=$(sudo -u "$current_user" cat "$pub_key_path")
                if sudo -u "$current_user" grep -Fq -- "$pub_key_content" "$authorized_keys_path"; then
                     success "Public key already exists in '$authorized_keys_path'."
                else
                     # Append the public key (as the user) using tee
                     if echo "$pub_key_content" | sudo -u "$current_user" tee -a "$authorized_keys_path" > /dev/null; then
                          success "Public key added to '$authorized_keys_path'."
                          log_change "AUTHORIZED_KEY_ADDED:${pub_key_path}"
                     else
                          error "Failed to add public key to '$authorized_keys_path'."
                          # Don't return 1 here, key generation was successful, just adding failed.
                     fi
                fi

                 # Final Messages
                 echo; info "Public key file location: $pub_key_path"
                 info "${C_YELLOW}Reminder:${C_RESET} Add the public key manually to ~/.ssh/authorized_keys on target servers."
                 [[ -n "$passphrase" ]] && warn "Remember to store the passphrase securely!"
            else
                error "Error during key creation (as '$current_user')."
            fi
        fi # End Dry Run check for key generation
    fi
    echo "--- Section 1 completed ---"; echo
}
# --- End SSH Key and Users ---



# --- Improved Unattended Upgrades Function with Fixed Mail Configuration ---
configure_unattended_upgrades() {
    info "${C_BOLD}2. Configure Unattended Upgrades${C_RESET}"
    if ! ask_yes_no "Execute this step (Unattended Upgrades)?" "y"; then
        info "Step skipped."; echo; return 0
    fi

    # --- Variables ---
    local pkg="unattended-upgrades"
    local config_file="/etc/apt/apt.conf.d/50unattended-upgrades"
    local periodic_config_file="/etc/apt/apt.conf.d/20auto-upgrades"
    local distro_id distro_codename
    local changes_made=false # Track if any change was actually applied to the target file
    local temp_file

    # --- Get Distro Info ---
    # (Uses lsb_release or /etc/os-release to find distro ID and codename)
    if command -v lsb_release &>/dev/null; then
        distro_id=$(lsb_release -is)
        distro_codename=$(lsb_release -cs)
    elif [[ -f /etc/os-release ]]; then
        distro_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed 's/"//g')
        # Capitalize first letter for consistency if needed (e.g., ubuntu -> Ubuntu)
        distro_id="${distro_id^}"
        distro_codename=$(grep '^VERSION_CODENAME=' /etc/os-release | cut -d= -f2 | sed 's/"//g')
    else
        error "Cannot determine distribution ID and codename. Please set 'distro_id' and 'distro_codename' manually."
        return 1
    fi
    if [[ -z "$distro_id" || -z "$distro_codename" ]]; then
       error "Could not determine distribution ID ('$distro_id') or codename ('$distro_codename')."
       return 1
    fi
    info "Detected Distribution: $distro_id $distro_codename"


    # --- Package Installation ---
    if ! is_package_installed "$pkg"; then
        warn "'$pkg' not installed."
        if ask_yes_no "Install '$pkg'?" "y"; then
            if ! $SCRIPT_APT_UPDATED; then
                info "Running 'apt update'..."
                if ! execute_command "APT_UPDATE" "apt update"; then error "'apt update' failed."; return 1; fi
                SCRIPT_APT_UPDATED=true
            fi
            if ! execute_command "INSTALLED:$pkg" "apt install -y \"$pkg\""; then error "Installation failed."; return 1; fi
            success "'$pkg' installed."
            # Note: Installation itself doesn't set changes_made for the config file yet
        else
            info "Unattended Upgrades skipped as package installation was declined."; echo "--- Section 2 completed ---"; echo; return 0
        fi
    else
        success "Package '$pkg' is already installed."
    fi

    # --- Periodic Configuration (20auto-upgrades) ---
    # (Checks and sets APT::Periodic::Update-Package-Lists and Unattended-Upgrade to "1")
    info "Checking periodic configuration ($periodic_config_file)..."
    local periodic_correct=true
    local periodic_content="// Generated by script\nAPT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n" # Corrected content generation
    if [[ ! -f "$periodic_config_file" ]]; then
        warn "'$periodic_config_file' does not exist."
        periodic_correct=false
    else
        # Check if lines exist and are set to "1" (ignoring comments)
        if ! grep -qE '^\s*APT::Periodic::Update-Package-Lists\s*"1"\s*;' "$periodic_config_file"; then
            warn "APT::Periodic::Update-Package-Lists not set correctly in '$periodic_config_file'."
            periodic_correct=false
        fi
        if ! grep -qE '^\s*APT::Periodic::Unattended-Upgrade\s*"1"\s*;' "$periodic_config_file"; then
            warn "APT::Periodic::Unattended-Upgrade not set correctly in '$periodic_config_file'."
            periodic_correct=false
        fi
    fi

    if ! $periodic_correct; then
        if ask_yes_no "Apply recommended settings to '$periodic_config_file'?" "y"; then
             backup_file "$periodic_config_file" || { error "Backup failed for $periodic_config_file"; return 1; }
             if execute_command "WRITE_FILE:$periodic_config_file" "mkdir -p \"$(dirname "$periodic_config_file")\" && echo -e \"$periodic_content\" > \"$periodic_config_file\""; then
                 success "'$periodic_config_file' created/updated."
                 # This file change is logged by execute_command, no need for changes_made here
             else
                 error "Failed to write '$periodic_config_file'."
                 restore_file "$periodic_config_file"
                 return 1
             fi
        else
             info "Skipping changes to '$periodic_config_file'."
        fi
    else
        success "'$periodic_config_file' already configured correctly."
    fi


    # --- Main Configuration (50unattended-upgrades) ---
    info "Checking main configuration ($config_file)..."
    if [[ ! -f "$config_file" ]]; then
        error "Configuration file '$config_file' not found! Cannot proceed."
        echo "--- Section 2 completed (with error) ---"; echo; return 1
    fi

    # Create temporary file for modifications
    temp_file=$(mktemp)
    # Ensure temporary file is removed on script exit or interruption
    trap 'rm -f "$temp_file"' EXIT SIGHUP SIGINT SIGQUIT SIGTERM
    cp "$config_file" "$temp_file" || { error "Could not create temporary file."; return 1; }

    # --- Define Desired Settings ---
    # Parameters check (Key-Value pairs)
    declare -A desired_params=(
        ["Unattended-Upgrade::AutoFixInterruptedDpkg"]="true"
        ["Unattended-Upgrade::MinimalSteps"]="true"
        ["Unattended-Upgrade::MailReport"]="on-change"
        ["Unattended-Upgrade::Remove-Unused-Kernel-Packages"]="true"
        ["Unattended-Upgrade::Remove-New-Unused-Dependencies"]="true" # Often redundant but harmless
        ["Unattended-Upgrade::Remove-Unused-Dependencies"]="true"
        ["Unattended-Upgrade::Automatic-Reboot"]="true"
        ["Unattended-Upgrade::Automatic-Reboot-WithUsers"]="false" # Needs "false"
        ["Unattended-Upgrade::Automatic-Reboot-Time"]="02:00"
        ["Unattended-Upgrade::Allow-downgrade"]="true" # Added from your list
        ["Unattended-Upgrade::Allow-APT-Mark-Fallback"]="true" # Added from your list
        # Mail is handled separately below
    )

    # Origins Patterns (Dynamic based on distro info)
    # Ensure quoting within the string for correct matching/replacement
    local origin_apps_pattern="\"${distro_id}ESMApps:${distro_codename}-apps-security\";"
    local origin_infra_pattern="\"${distro_id}ESM:${distro_codename}-infra-security\";"
    local origin_updates_pattern="\"${distro_id}:${distro_codename}-updates\";"
    # Add other standard origins if desired (e.g., security)
    local origin_security_pattern="\"${distro_id}:${distro_codename}-security\";" # Common important one

    declare -a desired_origins=(
        # Order might matter for readability, but not functionality
        "$origin_security_pattern" # Often the most critical
        "$origin_updates_pattern"
        "$origin_apps_pattern" # Typically for Ubuntu Pro/ESM
        "$origin_infra_pattern" # Typically for Ubuntu Pro/ESM
    )

    # --- Helper Function to Process Parameters ---
    # Ensures a specific parameter exists, is uncommented, and has the correct value
    # Returns 0 if a change was made to the temp file, 1 if it was already correct, 2 if missing (added later)
    process_parameter_line() {
        local key="$1" desired_value="$2" file="$3"
        local line_changed=false
        local current_line current_value is_commented=false

        # Use grep to find the line, capturing comment status and value
        current_line=$(grep -E "^\s*(//\s*)?${key}\s+" "$file")

        if [[ -n "$current_line" ]]; then
            # Line found, check if commented
            if [[ "$current_line" =~ ^\s*// ]]; then
                is_commented=true
            fi
            # Extract current value (handles quotes)
            current_value=$(echo "$current_line" | sed -E 's/^\s*(\/\/\s*)?.*'"${key}"'\s*"(.*)".*/\2/')
             # If no quotes, try without
             if [[ "$current_value" == "$current_line" ]]; then # Extraction failed, likely no quotes
                current_value=$(echo "$current_line" | sed -E 's/^\s*(\/\/\s*)?.*'"${key}"'\s*([^;]*)\s*;.*/\2/')
                # Simple true/false might not have quotes
                if [[ "$current_value" == "$current_line" ]]; then # Still failed? Try without value extraction, direct compare if boolean
                     if [[ "$desired_value" == "true" || "$desired_value" == "false" ]] then
                          if [[ "$current_line" =~ ${key}[[:space:]]+${desired_value}[[:space:]]* ]]; then
                                 current_value="$desired_value" # Assume match if pattern found
                           fi
                     fi
                fi
            fi


            # Check if modification is needed
            if $is_commented || [[ "$current_value" != "$desired_value" ]]; then
                # Need to uncomment and/or set the correct value
                local replacement_line="${key} \"${desired_value}\";"
                # Use @ as delimiter for sed
                local sed_pattern="s@^\s*(//\s*)?${key}\s+.*@${replacement_line}@g"
                sed -i -E "$sed_pattern" "$file"
                line_changed=true
            fi
        else
            # Line not found at all
            return 2 # Signal missing
        fi

        if $line_changed; then
            return 0 # Changed
        else
            return 1 # Already correct
        fi
    }

    # --- Process Parameters ---
    info "Processing parameters in $config_file..."
    local param_missing=false
    for key in "${!desired_params[@]}"; do
        local value="${desired_params[$key]}"
        info "Checking parameter: $key = \"$value\";"
        process_parameter_line "$key" "$value" "$temp_file"
        local result=$?
        if [[ $result -eq 0 ]]; then
            success " -> Modified/Uncommented: $key to \"$value\";"
            changes_made=true # Mark that the temp file was modified
        elif [[ $result -eq 1 ]]; then
             success " -> Already correct: $key = \"$value\";"
        elif [[ $result -eq 2 ]]; then
            warn " -> Missing parameter: $key"
            local line_to_add="$key \"$value\";"
            # Append the missing line to the temp file
            echo "$line_to_add" >> "$temp_file"
            success " -> Added missing: $key = \"$value\";"
            changes_made=true # Mark that the temp file was modified
            param_missing=true
        fi
    done
    if ! $param_missing; then success "All specified parameters are present."; fi


    # --- Process Allowed-Origins ---
    info "Processing Allowed-Origins in $config_file..."
    local origins_block_start_pattern="^\s*(//\s*)?Unattended-Upgrade::Allowed-Origins\s*\{"
    local origins_block_end_pattern="^\s*\};" # End pattern includes the semicolon now
    local origins_block_start_line origins_block_end_line

    # Find the start line number of the block
    origins_block_start_line=$(grep -nE "$origins_block_start_pattern" "$temp_file" | head -n 1 | cut -d: -f1)

    if [[ -z "$origins_block_start_line" ]]; then
        warn "Allowed-Origins block start not found. Cannot process origins automatically."
        # Consider adding the whole block if critical, but adds complexity.
        # For now, we skip origins if the block isn't found.
    else
        # Find the end line number starting from the start line
        # Add 1 to start line for tail, adjust end line number calculation
        origins_block_end_line=$(tail -n +$((origins_block_start_line)) "$temp_file" | grep -nm 1 -E "$origins_block_end_pattern" | cut -d: -f1)

        if [[ -z "$origins_block_end_line" ]]; then
             warn "Allowed-Origins block end ('};') not found after start line $origins_block_start_line. Cannot process origins."
        else
            # Calculate absolute end line number in the temp file
            origins_block_end_line=$((origins_block_start_line + origins_block_end_line -1 ))
            info "Found Allowed-Origins block between lines $origins_block_start_line and $origins_block_end_line."

            # 1. Uncomment Block Start if necessary
            if grep -qE "^\s*//\s*Unattended-Upgrade::Allowed-Origins\s*\{" "$temp_file"; then
                 local sed_script="s@^\s*//\s*\(Unattended-Upgrade::Allowed-Origins\s*{\)@\1@g"
                 sed -i "${origins_block_start_line}s@^\s*//\s*\(Unattended-Upgrade::Allowed-Origins\s*{\)@\1@g" "$temp_file"
                 success " -> Uncommented Allowed-Origins block start."
                 changes_made=true
            fi

            # 2. Process each desired origin within the block
            # 2. Process each desired origin within the block
            local origin_missing_in_block=false
            for origin in "${desired_origins[@]}"; do
                info "Checking origin: $origin"

                # Prepare patterns for grep checks (ensure quoting/escaping is correct)
                # Pattern for the exact, uncommented origin line (allowing variable leading space)
                local active_pattern="^\s*${origin}\s*$"
                # Pattern for the exact, commented origin line
                local commented_pattern="^\s*//\s*${origin}\s*$"

                # Check if the origin is already active within the block lines
                if sed -n "${origins_block_start_line},${origins_block_end_line}p" "$temp_file" | grep -qE "$active_pattern"; then
                    success " -> Origin already active: $origin"
                    continue # Already correct, move to the next origin
                fi

                # Check if the origin is commented out within the block lines
                local commented_line_num
                # Get line number relative to the start of the file
                commented_line_num=$(sed -n "${origins_block_start_line},${origins_block_end_line} { ${commented_pattern}=; }" "$temp_file" | head -n 1)

                if [[ -n "$commented_line_num" ]]; then
                    # Found it commented. Construct the uncommented version with proper indentation.
                    # Using printf to handle the tab reliably
                    local uncommented_line
                    printf -v uncommented_line '\t%s' "$origin"

                    # Escape for sed replacement string (RHS of s///)
                    local sed_rhs=${uncommented_line//\\/\\\\}
                    sed_rhs=${sed_rhs//&/\\&}
                    sed_rhs=${sed_rhs//\//\\/} # Escape slashes too for RHS

                    # Use sed to replace the found commented line with the uncommented version
                    # Match the whole commented line pattern
                    local sed_script="s@^\s*//\s*${origin}\s*$@${sed_rhs}@g"
                    sed -i "${commented_line_num}s@${sed_script}@" "$temp_file"

                    if [[ $? -eq 0 ]]; then
                         success " -> Uncommented existing origin: $origin"
                         changes_made=true
                    else
                         error " -> Failed to uncomment origin on line $commented_line_num"
                    fi
                    continue # Processed (or failed), move to the next origin
                fi

                # If we reach here, the origin was neither active nor commented out. Add it.
                warn " -> Missing origin: $origin"
                local line_to_insert
                printf -v line_to_insert '\t%s' "$origin" # Use printf for reliable tab

                # Escape backslashes and other special sed characters for the text to be inserted
                local sed_insert_text=${line_to_insert//\\/\\\\}
                sed_insert_text=${sed_insert_text//\//\\/} # Escape /
                sed_insert_text=${sed_insert_text//&/\\&}   # Escape &

                # Insert the line *before* the end line
                sed -i "${origins_block_end_line}i ${sed_insert_text}" "$temp_file"

                if [[ $? -eq 0 ]]; then
                    success " -> Added missing origin: $origin"
                    changes_made=true
                    origin_missing_in_block=true
                    # IMPORTANT: Increment the end line number since we inserted a line *before* it
                    origins_block_end_line=$((origins_block_end_line + 1))
                else
                    error " -> Failed to insert missing origin: $origin"
                fi

            done # End loop through desired_origins


            # 3. Uncomment Block End if necessary (less common, but for completeness)
            local current_end_line_content=$(sed -n "${origins_block_end_line}p" "$temp_file")
            # *** CORRECTED LINE BELOW ***
            # Checks if the line starts with optional space, then //, then optional space, then }
            if [[ "$current_end_line_content" =~ ^\s*//\s*\} ]]; then
                 # The sed command below correctly targets the commented '};' and uncomment it
                 sed -i "${origins_block_end_line}s@^\s*//\s*(\};)@\1@g" "$temp_file"
                 success " -> Uncommented Allowed-Origins block end."
                 changes_made=true
            fi
        fi # End block end found check
    fi # End block start found check

    # --- Check and Configure Email Address ---
    info "Checking Unattended-Upgrade::Mail..."
    local mail_key="Unattended-Upgrade::Mail"
    local mail_report_key="Unattended-Upgrade::MailReport"
    local mail_report_value=$(grep -E "^\s*${mail_report_key}\s+\"(.*)\";" "$temp_file" | sed -E 's/.*"(.*)".*/\1/')
    local current_mail_line mail_value current_mail_is_commented=false

    # Only check/prompt for mail if MailReport is not "only-on-error" or "never"
    if [[ "$mail_report_value" == "on-change" || "$mail_report_value" == "always" ]]; then
        current_mail_line=$(grep -E "^\s*(//\s*)?${mail_key}\s+" "$temp_file")

        if [[ -n "$current_mail_line" ]]; then
            mail_value=$(echo "$current_mail_line" | sed -E 's/^\s*(\/\/\s*)?.*'"${mail_key}"'\s*"(.*)".*/\2/')
            [[ "$current_mail_line" =~ ^\s*// ]] && current_mail_is_commented=true
            info "Found existing mail setting: Line='$current_mail_line', Value='$mail_value', Commented=$current_mail_is_commented"
        else
            info "Mail setting '$mail_key' not found in the file."
            mail_value=""
            current_mail_is_commented=true # Treat as inactive
        fi

        local is_valid_mail=false
        # Use the script's existing validate_email function [cite: 49]
        if [[ -n "$mail_value" ]] && ! $current_mail_is_commented && validate_email "$mail_value"; then
           is_valid_mail=true
        fi

        if ! $is_valid_mail; then
            if $current_mail_is_commented; then
                warn "Mail setting is missing or commented out."
            elif [[ -z "$mail_value" ]]; then
                 warn "Mail address is empty."
            else
                 warn "Existing mail address '$mail_value' seems invalid."
            fi

            if ask_yes_no "Set a valid email address for reports (required for MailReport=$mail_report_value)?" "y"; then
                 local new_mail=""
                 while true; do
                     read -p "Enter the email address: " new_mail
                     if [[ -n "$new_mail" ]] && validate_email "$new_mail"; then
                         info "Using email address: $new_mail"
                         break
                     else
                         warn "Invalid email format. Please try again (e.g., user@example.com)."
                     fi
                 done

                # Replace or add the line in the temp file
                local new_mail_line="${mail_key} \"${new_mail}\";"

                # Fix: Use a proper delimiter to avoid conflicts with the email address
                # The issue was that the email might contain slashes or other characters that sed interprets specially
                if grep -qE "^\s*(//\s*)?${mail_key}\s+" "$temp_file"; then
                    # Line exists, create a replacement using awk instead of sed
                    awk -v pattern="^[[:space:]]*(//[[:space:]]*)?${mail_key}[[:space:]]+.*" \
                        -v replacement="${mail_key} \"${new_mail}\";" \
                        'BEGIN {OFS=FS} $0 ~ pattern {$0=replacement; changed=1} {print} END {exit !changed}' \
                        "$temp_file" > "${temp_file}.new" && mv "${temp_file}.new" "$temp_file"

                    if [[ $? -eq 0 ]]; then
                        success " -> Updated mail address to: $new_mail"
                    else
                        error " -> Failed to update mail address"
                    fi
                else
                    # Line doesn't exist, add it
                    echo "$new_mail_line" >> "$temp_file"
                    success " -> Added mail address: $new_mail"
                fi
                changes_made=true # Mark temp file as modified
            else
                 info "Skipping email configuration. Mail reports might not be sent."
            fi
        else
             success "Mail address '$mail_value' found, seems valid, and is active."
        fi
    else
        info "Mail reporting is set to '$mail_report_value'. Skipping Mail address check."
    fi


    # --- Apply Changes if Modifications Occurred ---
    if $changes_made; then
        info "Applying changes to $config_file..."
        backup_file "$config_file" || { error "Backup failed for $config_file"; rm -f "$temp_file"; trap - EXIT SIGHUP SIGINT SIGQUIT SIGTERM; return 1; }

        # Optional: Show diff before applying (only if not dry run, as execute_command shows diff in dry run)
        if ! $DRY_RUN && command -v diff &>/dev/null; then
            info "--- DIFF ---"
            diff -u "$config_file" "$temp_file" || true # Ignore diff exit code
            info "--- END DIFF ---"
            if ! ask_yes_no "Apply these changes?" "y"; then
                 info "Changes discarded."
                 rm -f "$temp_file"
                 trap - EXIT SIGHUP SIGINT SIGQUIT SIGTERM # Remove trap
                 return 0 # User chose not to apply
            fi
        fi

        # Use execute_command to handle moving the file and logging
        if execute_command "APPLY_CONFIG:$config_file" "mv \"$temp_file\" \"$config_file\" && chmod 644 \"$config_file\""; then
            success "Changes applied successfully to $config_file."
            # Optional: Reload service if needed, e.g., apt-config dump might reload caches? Check documentation.
            # execute_command "RELOAD_APT_CONFIG?" "apt-config dump" # Example, might not be needed
        else
            error "Failed to apply changes to $config_file!"
            restore_file "$config_file" # Attempt restore on failure
            # temp_file might still exist if mv failed, trap will clean it up
            return 1
        fi
    else
        success "No changes were needed for $config_file based on the desired configuration."
    fi

    # Explicitly remove trap as we are done with temp_file
    trap - EXIT SIGHUP SIGINT SIGQUIT SIGTERM
    rm -f "$temp_file" 2>/dev/null # Clean up temp file if it still exists (e.g., dry run or no changes)

    echo "--- Section 2 completed ---"; echo
    return 0
}

# --- End Unattended Upgrades ---


# --- MSMTP ---
configure_msmtp() {
    info "${C_BOLD}3. MSMTP Setup for System Notifications${C_RESET}"
    if ! ask_yes_no "Execute this step (MSMTP)?" "y"; then info "Step skipped."; echo; return 0; fi

    local msmtp_pkg="msmtp" mta_pkg="msmtp-mta" mailutils_pkg="mailutils"
    local config_file_path config_owner user_home

    # Determine config scope
    if [[ "$MSMTP_CONFIG_CHOICE" == "user" ]]; then
        local target_user=${SUDO_USER:-$USER}
        read -p "For which user should MSMTP config be created? [$target_user]: " config_owner
        config_owner=${config_owner:-$target_user}
        user_home=$(eval echo "~$config_owner")
        if [[ -z "$user_home" ]] || [[ ! -d "$user_home" ]]; then error "Home dir for '$config_owner' not found."; echo "--- Section 3 completed ---"; echo; return 1; fi
        config_file_path="$user_home/.msmtprc"
        info "MSMTP will be configured for '$config_owner' in '$config_file_path'."
    else
        config_file_path="/etc/msmtprc"; config_owner="root"; user_home="/root"
        info "MSMTP will be configured system-wide in '$config_file_path'."
    fi

    # Check/Install packages
    local install_pkgs=false install_mailutils=false pkgs_to_install=""
    if ! is_package_installed "$msmtp_pkg"; then warn "'$msmtp_pkg' not installed."; install_pkgs=true; pkgs_to_install+="$msmtp_pkg "; fi
    if ! is_package_installed "$mta_pkg"; then warn "'$mta_pkg' not installed."; install_pkgs=true; pkgs_to_install+="$mta_pkg "; fi
    if ! is_package_installed "$mailutils_pkg"; then warn "'$mailutils_pkg' not installed."; if ask_yes_no "Install '$mailutils_pkg'?" "y"; then install_pkgs=true; install_mailutils=true; pkgs_to_install+="$mailutils_pkg "; fi; fi

    if [[ "$install_pkgs" = true ]]; then
         if [[ -n "$pkgs_to_install" ]]; then
            if ask_yes_no "Install packages ($pkgs_to_install)?" "y"; then
                 if ! $SCRIPT_APT_UPDATED; then info "Running 'apt update'..."; execute_command "APT_UPDATE" "apt update" && SCRIPT_APT_UPDATED=true || { error "'apt update' failed."; return 1; }; fi
                 # DRY-RUN Handling for install
                 if execute_command "INSTALLED_MSMTP_PKGS" "apt install -y $pkgs_to_install"; then success "Packages installed."; else error "Installation failed."; return 1; fi
                 # Log individual packages if successful and not dry run
                 if ! $DRY_RUN; then
                    [[ "$pkgs_to_install" =~ "$msmtp_pkg" ]] && log_change "INSTALLED:$msmtp_pkg"
                    [[ "$pkgs_to_install" =~ "$mta_pkg" ]] && log_change "INSTALLED:$mta_pkg"
                    [[ "$pkgs_to_install" =~ "$mailutils_pkg" ]] && log_change "INSTALLED:$mailutils_pkg"
                 fi
             else info "MSMTP skipped."; echo "--- Section 3 completed ---"; echo; return 0; fi
         fi
    else success "Required MSMTP packages are installed.";
    fi

    # Configure MSMTP
    local configure_msmtp=false
    if [[ -f "$config_file_path" ]]; then
        warn "MSMTP configuration found: '$config_file_path'."
        if ask_yes_no "Recreate the configuration (will overwrite)?" "n"; then configure_msmtp=true; else info "Keeping existing configuration."; fi
    else
        info "No configuration found: '$config_file_path'."
        if ask_yes_no "Set up MSMTP now?" "y"; then configure_msmtp=true; fi
    fi

    if [[ "$configure_msmtp" = true ]]; then
        info "Please enter SMTP details:"
        local smtp_host smtp_port smtp_tls smtp_trust_file smtp_from smtp_user smtp_password smtp_aliases
        while true; do read -p "SMTP Host: " smtp_host; [[ -n "$smtp_host" ]] && break || warn "Host cannot be empty."; done
        while true; do read -p "SMTP Port [587]: " smtp_port; smtp_port=${smtp_port:-587}; validate_port "$smtp_port" && break || warn "Invalid port."; done
        while true; do read -p "TLS (on/off) [on]: " smtp_tls; smtp_tls=${smtp_tls:-on}; [[ "$smtp_tls" == "on" || "$smtp_tls" == "off" ]] && break || warn "Invalid input (on/off)."; done
        read -p "CA certificate file [/etc/ssl/certs/ca-certificates.crt]: " smtp_trust_file; smtp_trust_file=${smtp_trust_file:-/etc/ssl/certs/ca-certificates.crt}
        while true; do read -p "Sender (From): " smtp_from; validate_email "$smtp_from" && break || warn "Invalid email address."; done
        while true; do read -p "SMTP Username [$smtp_from]: " smtp_user; smtp_user=${smtp_user:-$smtp_from}; validate_email "$smtp_user" && break || warn "Invalid email address."; done
        while true; do read -sp "SMTP Password: " smtp_password; echo; [[ -n "$smtp_password" ]] && break || warn "Password cannot be empty."; done
        read -p "Alias file [/etc/aliases]: " smtp_aliases; smtp_aliases=${smtp_aliases:-/etc/aliases}

        local logfile_path="${user_home}/.msmtp.log"
        local msmtp_content="# MSMTP configuration generated by security_script.sh\ndefaults\nport $smtp_port\ntls $smtp_tls\ntls_trust_file $smtp_trust_file\nlogfile ${logfile_path}\n\naccount default\nhost $smtp_host\nfrom $smtp_from\nauth on\nuser $smtp_user\npassword $smtp_password\n\naliases $smtp_aliases\n"
        info "--- Example Configuration ---"; echo -e "${msmtp_content//"$smtp_password"/"********"}"; echo "--------------------------------" # Hide password in example

        if ask_yes_no "Save these settings to '$config_file_path'?" "y"; then
            backup_file "$config_file_path" || return 1

            # DRY-RUN Handling for writing config, log dir/file, permissions, ownership
            if $DRY_RUN; then
                dry_run_echo "echo -e '...' > \"$config_file_path\" # Content not shown"
                dry_run_echo "chmod 600 \"$config_file_path\""
                dry_run_echo "mkdir -p \"$(dirname "$logfile_path")\""
                dry_run_echo "touch \"$logfile_path\""
                dry_run_echo "chmod 600 \"$logfile_path\""
                if [[ "$MSMTP_CONFIG_CHOICE" == "user" ]]; then
                    dry_run_echo "chown \"$config_owner\":\"$config_owner\" \"$config_file_path\""
                    dry_run_echo "chown \"$config_owner\":\"$config_owner\" \"$(dirname "$logfile_path")\""
                    dry_run_echo "chown \"$config_owner\":\"$config_owner\" \"$logfile_path\""
                else
                     dry_run_echo "chown root:root \"$config_file_path\""
                    dry_run_echo "chown root:root \"$logfile_path\"" # Assuming /root/.msmtp.log
                fi
                success "DRY-RUN: Would save MSMTP config to '$config_file_path' and set up log file."
            else # Actual Execution
                echo -e "$msmtp_content" > "$config_file_path" && \
                chmod 600 "$config_file_path" && \
                mkdir -p "$(dirname "$logfile_path")" && \
                touch "$logfile_path" && \
                chmod 600 "$logfile_path" || \
                  { error "Failed to write config or create/chmod log file."; restore_file "$config_file_path"; return 1; }

                # Set ownership
                local chown_ok=true
                if [[ "$MSMTP_CONFIG_CHOICE" == "user" ]]; then
                    chown "$config_owner":"$config_owner" "$config_file_path" && \
                    chown "$config_owner":"$config_owner" "$(dirname "$logfile_path")" && \
                    chown "$config_owner":"$config_owner" "$logfile_path" || chown_ok=false
                else # System config
                    chown root:root "$config_file_path" && \
                    chown root:root "$logfile_path" || chown_ok=false
                fi
                if ! $chown_ok; then error "Failed to set ownership for config/log files."; restore_file "$config_file_path"; return 1; fi

                success "MSMTP configuration saved in '$config_file_path'."
                log_change "ADDED_FILE:$config_file_path" # Log creation/overwrite

                # Send test email
                if is_package_installed "$mailutils_pkg"; then
                    if ask_yes_no "Send test email to '$smtp_from'?" "y"; then
                        local mail_cmd="echo 'This is a test email from the Linux Security Script.' | mail -s 'MSMTP Test $(date)' '$smtp_from'"
                        local effective_mail_cmd="$mail_cmd"
                        local log_msg="SEND_TEST_MAIL:$smtp_from"
                        if [[ "$MSMTP_CONFIG_CHOICE" == "user" ]] && [[ "$config_owner" != "$(whoami)" ]]; then
                             effective_mail_cmd="su - \"$config_owner\" -c \"$mail_cmd\""
                             log_msg="SEND_TEST_MAIL:$smtp_from (as $config_owner)"
                        fi

                        # DRY-RUN Handling for test mail
                        if $DRY_RUN; then
                             dry_run_echo "$effective_mail_cmd"
                             success "DRY-RUN: Would send test email to '$smtp_from'."
                        else
                             if eval "$effective_mail_cmd"; then success "Test email sent."; log_change "$log_msg"; else warn "Could not send test email. Check $logfile_path"; fi
                        fi
                    fi
                else warn "Package 'mailutils' not found, skipping test email.";
                fi
            fi # End actual execution block
        fi
    fi
    echo "--- Section 3 completed ---"; echo
}
# --- End MSMTP ---


# --- SSH Hardening ---
configure_ssh_hardening() {
    info "${C_BOLD}4a. Harden SSH Configuration (Editing /etc/ssh/sshd_config)${C_RESET}"
    if ! ask_yes_no "Execute this step (SSH Hardening)?" "y"; then info "Step skipped."; echo; return 0; fi

    local ssh_config_file="/etc/ssh/sshd_config"
    local sshd_needs_restart=false # Track if SSHD needs restart

    # --- AllowUsers Configuration ---
    if ask_yes_no "Adjust AllowUsers setting in $ssh_config_file?" "n"; then
        local effective_allow_users target_users apply_allowusers=false suggested_user
        effective_allow_users=$(get_effective_sshd_config "allowusers")
        suggested_user=$(awk -F: '$3 >= 1000 && $3 < 65534 { print $1; exit }' /etc/passwd)
        [[ -z "$suggested_user" ]] && suggested_user="your_admin_user"

        warn "Recommendation: Restrict SSH access to specific admin users (not root)."
        read -p "Which users should have SSH access? (Suggestion: $suggested_user, Space-separated, Empty = skip): " target_users

        if [[ -n "$target_users" ]]; then
            local all_users_exist=true
            for user in $target_users; do if ! id "$user" &>/dev/null; then error "User '$user' does not exist."; all_users_exist=false; fi; done

            if $all_users_exist; then
                # Comparison logic (read-only, no dry run needed)
                local compare_needed=true
                if [[ -n "$effective_allow_users" ]]; then
                    local normalized_effective sorted_effective; normalized_effective=$(echo "$effective_allow_users" | tr ' ' '\n' | sort | tr '\n' ' '); sorted_effective=$(echo "$normalized_effective" | sed 's/ $//')
                    local normalized_target sorted_target; normalized_target=$(echo "$target_users" | tr ' ' '\n' | sort | tr '\n' ' '); sorted_target=$(echo "$normalized_target" | sed 's/ $//')
                    if [[ "$sorted_effective" == "$sorted_target" ]]; then success "AllowUsers already set to '$target_users'."; compare_needed=false; fi
                fi

                # Ask user if comparison shows difference
                if $compare_needed; then
                    local prompt_msg="Set AllowUsers to '$target_users'?"
                    if [[ -n "$effective_allow_users" ]]; then prompt_msg="Change AllowUsers from '$effective_allow_users' to '$target_users'?"; fi
                    if ask_yes_no "$prompt_msg" "y"; then apply_allowusers=true; fi
                fi # End compare_needed block

                # Apply the change if confirmed
                if $apply_allowusers; then
                    backup_file "$ssh_config_file" || return 1
                    local temp_ssh_conf; temp_ssh_conf=$(mktemp)
                    cp "$ssh_config_file" "$temp_ssh_conf"

                    # Modify or add AllowUsers robustly in temp file
                    if grep -qE "^\s*#?\s*AllowUsers" "$temp_ssh_conf"; then
                         sed -i -E "s|^\s*#?\s*(AllowUsers)\s+.*|AllowUsers $target_users|" "$temp_ssh_conf"
                    else
                         echo "" >> "$temp_ssh_conf"; echo "AllowUsers $target_users" >> "$temp_ssh_conf"
                    fi # End grep if/else block
                    info "Set 'AllowUsers $target_users' in temporary SSH config."
                    # DRY-RUN Handling for applying AllowUsers
                    if $DRY_RUN; then
                         dry_run_echo "sshd -t -f \"$temp_ssh_conf\" # Validate temp config"
                         dry_run_echo "mv \"$temp_ssh_conf\" \"$ssh_config_file\""
                         dry_run_echo "chmod 644 \"$ssh_config_file\""
                         success "DRY-RUN: Would set AllowUsers to '$target_users'."
                         sshd_needs_restart=true # Assume restart needed in dry run if changes made
                         rm -f "$temp_ssh_conf" 2>/dev/null
                    else # Actual Execution
                         if sshd -t -f "$temp_ssh_conf"; then
                             if mv "$temp_ssh_conf" "$ssh_config_file"; then
                                 chmod 644 "$ssh_config_file"
                                 log_change "MODIFIED_PARAM:AllowUsers:$target_users:$ssh_config_file"
                                 success "AllowUsers set to '$target_users' in $ssh_config_file."
                                 sshd_needs_restart=true
                             else
                                 error "Failed to move temp SSH config for AllowUsers."
                                 rm -f "$temp_ssh_conf" 2>/dev/null; restore_file "$ssh_config_file"; return 1;
                             fi
                         else
                             error "SSHD config test failed for AllowUsers change. Changes not applied."
                             rm -f "$temp_ssh_conf" 2>/dev/null; restore_file "$ssh_config_file"; return 1;
                         fi # End sshd -t block
                    fi # End dry run check for AllowUsers apply
                fi # End apply_allowusers block
            else # Corresponds to: if $all_users_exist
                info "AllowUsers config skipped due to non-existent user(s)."
            fi # End all_users_exist block
        else # Corresponds to: if [[ -n "$target_users" ]]
             info "AllowUsers config skipped (no users specified)."
        fi # End target_users check
    else # Corresponds to: if ask_yes_no "Adjust AllowUsers...?"
        info "AllowUsers configuration skipped."
    fi # End main AllowUsers question block


    # --- Other SSH Hardening Parameters ---
    declare -A ssh_recommendations=( ["PermitRootLogin"]="prohibit-password" ["ChallengeResponseAuthentication"]="no" ["PasswordAuthentication"]="no" ["UsePAM"]="yes" ["X11Forwarding"]="no" ["PrintLastLog"]="yes" )
    local current_effective_value recommended_value current_config_value
    declare -A changes_to_apply # Store changes user agrees to

    # Key check (read-only, no dry run needed)
    local current_key_check_user; if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then current_key_check_user="$SUDO_USER"; else current_key_check_user=$(whoami); fi
    local user_key_home; user_key_home=$(eval echo "~$current_key_check_user")
    local ed25519_key_count=0
    if [[ -d "$user_key_home/.ssh" ]]; then
       ed25519_key_count=$(find "$user_key_home/.ssh" -maxdepth 1 -type f -name "*.pub" -exec grep -Eil "ssh-ed25519" {} + 2>/dev/null | wc -l)
       if [[ -f "$user_key_home/.ssh/authorized_keys" ]]; then local auth_key_count; auth_key_count=$(grep -Eic "ssh-ed25519" "$user_key_home/.ssh/authorized_keys"); ed25519_key_count=$((ed25519_key_count + auth_key_count)); fi
    fi

    # Iterate through recommendations (mostly read-only checks until the end)
    for param in "${!ssh_recommendations[@]}"; do
        current_effective_value=$(get_effective_sshd_config "$param")
        # Handle default value interpretation if not explicitly set
        if [[ -z "$current_effective_value" ]]; then
             if [[ "$param" == "ChallengeResponseAuthentication" ]]; then local pam_status=$(get_effective_sshd_config "UsePAM"); [[ "$pam_status" == "yes" ]] && current_effective_value="yes" || current_effective_value="no";
             elif [[ "$param" == "PasswordAuthentication" ]]; then current_effective_value="yes"; elif [[ "$param" == "PermitRootLogin" ]]; then current_effective_value="yes";
             elif [[ "$param" == "X11Forwarding" ]]; then current_effective_value="no";
             elif [[ "$param" == "PrintLastLog" ]]; then current_effective_value="yes"; fi
             debug "Parameter '$param' not explicit, using assumed default '$current_effective_value'."
        fi
        recommended_value="${ssh_recommendations[$param]}"
        current_effective_value_lower=$(echo "$current_effective_value" | tr '[:upper:]' '[:lower:]')
        recommended_value_lower=$(echo "$recommended_value" | tr '[:upper:]' '[:lower:]')

        local ask_user=true
        # Idempotency Check (PermitRootLogin special case)
        if [[ "$param" == "PermitRootLogin" ]] && ([[ "$current_effective_value_lower" == "without-password" || "$current_effective_value_lower" == "prohibit-password" ]] || [[ "$current_effective_value_lower" == "no" && "$recommended_value_lower" == "prohibit-password" ]] ); then # Allow 'no' if recommend is prohibit-password
             success "PermitRootLogin is already secure ($current_effective_value)."
             ask_user=false
        # General Idempotency Check
        elif [[ "$current_effective_value_lower" == "$recommended_value_lower" ]]; then
            success "$param is already correct ($current_effective_value)."
            ask_user=false
        else # If effective differs, check config file directly
            current_config_value=$(get_config_file_sshd_setting "$param")
            local current_config_value_lower=$(echo "$current_config_value" | tr '[:upper:]' '[:lower:]')
            if [[ -n "$current_config_value" && "$current_config_value_lower" == "$recommended_value_lower" ]]; then
                success "$param already set to '$recommended_value' in $ssh_config_file (effective: '$current_effective_value')."
                ask_user=false
            fi
        fi

        # Ask user if needed
        if $ask_user; then
            echo -e "\nParameter: ${C_BOLD}$param${C_RESET}"; echo "Current (effective): $current_effective_value"; echo "Recommended: $recommended_value"
            if [[ -n "$current_config_value" && "$current_config_value" != "$current_effective_value" ]]; then info "(Value in $ssh_config_file appears to be: $current_config_value)"; fi

            # Explanation
            case "$param" in
                "PermitRootLogin") echo "Explanation: Disabling direct root password login hardens against brute-force. 'prohibit-password' allows key-based root login."; ;;
                "ChallengeResponseAuthentication") echo "Explanation: Disabling can simplify; auth managed by PasswordAuth/PubkeyAuth/PAM."; ;;
                "PasswordAuthentication") echo "Explanation: Key-based auth is more secure. ${C_RED}WARNING:${C_RESET} Disabling passwords without a working SSH key ${C_BOLD}will lock you out${C_RESET}."; if [[ $ed25519_key_count -eq 0 ]]; then warn "No Ed25519 SSH keys found for '$current_key_check_user'!"; else success "Found $ed25519_key_count Ed25519 key(s) for '$current_key_check_user'."; fi ;;
                "UsePAM") echo "Explanation: PAM enables integration with system auth (2FA, etc.). Recommended 'yes'."; ;;
                "X11Forwarding") echo "Explanation: Disabling reduces attack surface if GUI forwarding is not needed."; ;;
                "PrintLastLog") echo "Explanation: Displaying last login info helps identify unauthorized access."; ;;
            esac

            # Ask
            local default_answer="y"
            if [[ "$param" == "PasswordAuthentication" && $ed25519_key_count -eq 0 ]]; then default_answer="n"; fi
            if ask_yes_no "Change $param from effective '$current_effective_value' to '$recommended_value'?" "$default_answer"; then
                changes_to_apply["$param"]="$recommended_value"
            else info "$param remains unchanged."; fi
        fi # End ask_user block
        current_config_value="" # Reset for next iteration
    done # End loop through parameters

    # Apply confirmed changes for parameters
    if [ ${#changes_to_apply[@]} -eq 0 ]; then
        info "No further changes selected for SSH hardening parameters."
    else
        info "The following SSH parameters will be changed:"
        for key in "${!changes_to_apply[@]}"; do echo "  $key -> ${changes_to_apply[$key]}"; done

        if ask_yes_no "Save these parameter changes to '$ssh_config_file'?" "y"; then
            # Backup only if not already backed up by AllowUsers change
            if ! $apply_allowusers; then backup_file "$ssh_config_file" || return 1; fi
            local temp_ssh_conf; temp_ssh_conf=$(mktemp)
            # Use the current state of ssh_config_file (potentially modified by AllowUsers)
            cp "$ssh_config_file" "$temp_ssh_conf"

            # Apply changes to temp file
            for key in "${!changes_to_apply[@]}"; do
                if grep -qE "^\s*#?\s*$key" "$temp_ssh_conf"; then
                     sed -i -E "s|^\s*#?\s*($key)\s+.*|$key ${changes_to_apply[$key]}|" "$temp_ssh_conf"
                else
                     echo "" >> "$temp_ssh_conf"; echo "$key ${changes_to_apply[$key]}" >> "$temp_ssh_conf"
                fi
                 info "Set '$key ${changes_to_apply[$key]}' in temporary SSH config."
            done

            # DRY-RUN Handling for applying parameter changes
            if $DRY_RUN; then
                dry_run_echo "sshd -t -f \"$temp_ssh_conf\" # Validate temp config"
                dry_run_echo "mv \"$temp_ssh_conf\" \"$ssh_config_file\""
                dry_run_echo "chmod 644 \"$ssh_config_file\""
                success "DRY-RUN: Would apply parameter changes to $ssh_config_file."
                sshd_needs_restart=true # Assume restart needed in dry run if changes made
                rm -f "$temp_ssh_conf" 2>/dev/null
            else # Actual Execution
                 if sshd -t -f "$temp_ssh_conf"; then
                     if mv "$temp_ssh_conf" "$ssh_config_file"; then
                         chmod 644 "$ssh_config_file"
                         for key in "${!changes_to_apply[@]}"; do log_change "MODIFIED_PARAM:$key:${changes_to_apply[$key]}:$ssh_config_file"; done
                         success "Parameter changes applied to $ssh_config_file."
                         sshd_needs_restart=true
                     else
                         error "Failed to move temp SSH config for parameter changes."
                         rm -f "$temp_ssh_conf" 2>/dev/null; if ! $apply_allowusers; then restore_file "$ssh_config_file"; fi; return 1;
                         # Restore only if not modified by AllowUsers
                     fi
                 else
                     error "SSHD config test failed for parameter changes. Changes not applied."
                     rm -f "$temp_ssh_conf" 2>/dev/null; if ! $apply_allowusers; then restore_file "$ssh_config_file"; fi; return 1;
                     # Restore only if not modified by AllowUsers
                 fi # End sshd -t block
            fi # End dry run check for parameter apply
        else info "No changes applied to SSH hardening parameters."; fi
    fi # End check if changes_to_apply has elements

    # Restart SSHD only if changes were actually made (or simulated) by either AllowUsers or parameters
    if $sshd_needs_restart; then
        info "Restarting SSH service due to configuration changes..."
        # DRY-RUN Handling for SSH restart
        if execute_command "SERVICE_RESTARTED:$SSH_SERVICE (SSH hardening)" "systemctl restart \"$SSH_SERVICE\""; then
             success "SSH service restarted."
             # Double check status only if not in dry run
             if ! $DRY_RUN; then
                 sleep 1; if ! systemctl is-active --quiet "$SSH_SERVICE"; then error "SSH service inactive after restart! Check config."; fi
             fi
        else
            # Error handled by execute_command, restore already attempted if applicable
            if ! $DRY_RUN; then warn "SSH service restart failed. Config *may* have been reverted. Check manually!"; fi
        fi
    else
        info "No SSH configuration changes applied, skipping SSH restart."
    fi

    echo "--- Section 4a completed ---"; echo
}
# --- End SSH Hardening ---

# --- Fail2ban Helper Function ---
is_ip_covered_by_ignoreip() {
    local check_item="$1"; shift; local ignore_list_items=("$@"); local ip_to_check subnet_to_check
    if [[ "$check_item" =~ / ]]; then subnet_to_check="$check_item"; else ip_to_check="$check_item";
    if [[ "$ip_to_check" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then subnet_to_check=$(echo "$ip_to_check" | cut -d. -f1-3).0/24; fi; fi
    # debug "Checking coverage for IP: '$ip_to_check', Subnet: '$subnet_to_check'" # Keep debug off by default
    for ignored_entry in "${ignore_list_items[@]}"; do
        if [[ "$ip_to_check" == "$ignored_entry" ]] || [[ "$subnet_to_check" == "$ignored_entry" ]]; then return 0; fi # Exact match
        if [[ -n "$ip_to_check" ]]; then # Simple Private CIDR checks (IPv4)
            if ([[ "$ignored_entry" == "192.168.0.0/16" ]] && [[ "$ip_to_check" =~ ^192\.168\. ]]) || \
               ([[ "$ignored_entry" == "172.16.0.0/12" ]] && [[ "$ip_to_check" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]) || \
               ([[ "$ignored_entry" == "10.0.0.0/8" ]] && [[ "$ip_to_check" =~ ^10\. ]]) || \
               ([[ "$ignored_entry" == "$subnet_to_check" ]]); then return 0; fi # Covered by derived /24
        fi
         if [[ -n "$subnet_to_check" && "$subnet_to_check" == "$ignored_entry" ]]; then return 0; fi # Exact subnet match
    done
    return 1 # Not covered
}


configure_fail2ban() {
    info "${C_BOLD}4b. Fail2ban Configuration${C_RESET}"
    if ! ask_yes_no "Configure Fail2ban?" "y"; then info "Fail2ban skipped."; echo; return 0; fi

    local pkg="fail2ban" jail_local="/etc/fail2ban/jail.local" jail_conf="/etc/fail2ban/jail.conf"
    local needs_restart=false # Track if service needs restart

    # Install package
    if ! is_package_installed "$pkg"; then
        warn "'$pkg' not installed."
        if ask_yes_no "Install '$pkg'?" "y"; then
            if ! $SCRIPT_APT_UPDATED; then info "Running 'apt update'..."; execute_command "APT_UPDATE" "apt update" && SCRIPT_APT_UPDATED=true || { error "'apt update' failed."; return 1; }; fi
            if execute_command "INSTALLED:$pkg" "apt install -y \"$pkg\""; then success "'$pkg' installed."; else error "Installation failed."; return 1; fi
        else info "Fail2ban skipped."; return 0; fi
    else success "Package '$pkg' is already installed.";
    fi

    # Ensure jail.local exists
    if [[ ! -f "$jail_local" ]]; then
        warn "'$jail_local' not found."
        if [[ -f "$jail_conf" ]]; then
            if ask_yes_no "Create '$jail_local' by copying '$jail_conf'?" "y"; then
                 # DRY-RUN Handling for copy
                 if execute_command "ADDED_FILE:$jail_local (copied from $jail_conf)" "cp \"$jail_conf\" \"$jail_local\""; then
                      success "Created '$jail_local'."
                      needs_restart=true
                 else error "Failed to copy '$jail_conf'."; return 1; fi
            else error "Cannot proceed without '$jail_local'."; return 1; fi
        else error "'$jail_conf' not found. Cannot create '$jail_local'."; return 1; fi
    else success "Local Fail2ban configuration '$jail_local' found.";
    fi

    # Enable [sshd] jail
    local ssh_jail_name="sshd"
    if ! is_fail2ban_jail_enabled "$ssh_jail_name"; then
        warn "Jail '[$ssh_jail_name]' is not enabled in '$jail_local'."
        if ask_yes_no "Enable jail '[$ssh_jail_name]' now?" "y"; then
             backup_file "$jail_local" || return 1
             local temp_jail_awk; temp_jail_awk=$(mktemp /tmp/f2b-jail.XXXXXX)
             # AWK script to enable jail
             awk -v jail="[$ssh_jail_name]" 'BEGIN {enabled_updated=0;in_section=0} $0 == jail {in_section=1;print;next} /^\s*\[/ && NR > 1 && in_section { if (!enabled_updated) {print "enabled = true"} in_section=0; enabled_updated=1 } in_section && /^\s*#?\s*enabled\s*=/ {print "enabled = true"; enabled_updated=1; next} {print} END { if (in_section && !enabled_updated) print "enabled = true" }' "$jail_local" > "$temp_jail_awk" || { error "AWK processing failed."; rm "$temp_jail_awk" 2>/dev/null; return 1; }

             # DRY-RUN Handling for applying awk changes
             if $DRY_RUN; then
                 dry_run_echo "mv \"$temp_jail_awk\" \"$jail_local\""
                 success "DRY-RUN: Would enable jail '[$ssh_jail_name]' in '$jail_local'."
                 needs_restart=true
                 rm "$temp_jail_awk" 2>/dev/null
             else
                 if mv "$temp_jail_awk" "$jail_local"; then
                      success "Enabled jail '[$ssh_jail_name]' in '$jail_local'."
                      log_change "MODIFIED:$jail_local (Jail $ssh_jail_name enabled)"
                      needs_restart=true
                 else
                      error "Failed to move temp file for jail enable."; rm "$temp_jail_awk" 2>/dev/null; restore_file "$jail_local"; return 1;
                 fi
             fi
        fi
    else success "Jail '[$ssh_jail_name]' is already enabled in '$jail_local'.";
    fi

    # Whitelist local IPs
    info "Checking Fail2ban ignoreip for local networks..."
    local current_ignoreip apply_ignoreip=false; local proposed_additions=()
    current_ignoreip=$(awk '/^\s*\[/{if(in_section)exit;if($0=="[DEFAULT]")in_section=1}in_section&&/^\s*ignoreip\s*=/{gsub(/^\s*ignoreip\s*=\s*/,"");cl=$0;while(getline>0&&$0~/^[[:space:]]/){cl=cl $0};gsub(/[[:space:]]+/," ",cl);print cl;exit}' "$jail_local")
    read -ra current_ignoreip_array <<< "$current_ignoreip"
    local base_ignore_list=("127.0.0.1/8" "::1")
    local local_ips4; local_ips4=$(ip -4 addr show | grep -oP 'inet \K[\d.]+' | grep -v '^127\.')
    for ip in $local_ips4; do local subnet4=$(echo "$ip" | cut -d. -f1-3).0/24; if ! is_ip_covered_by_ignoreip "$ip" "${current_ignoreip_array[@]}" && ! is_ip_covered_by_ignoreip "$subnet4" "${current_ignoreip_array[@]}"; then local already_proposed=false; for proposed in "${proposed_additions[@]}"; do if [[ "$subnet4" == "$proposed" ]]; then already_proposed=true; break; fi; done; if ! $already_proposed; then warn "Local IP $ip (subnet $subnet4) not found in ignoreip."; apply_ignoreip=true; proposed_additions+=("$subnet4"); info "Will propose adding '$subnet4'."; fi; fi; done

    if [[ "$apply_ignoreip" = true ]]; then
        local final_ignoreip_list; final_ignoreip_list=$(printf '%s\n' "${base_ignore_list[@]}" "${current_ignoreip_array[@]}" "${proposed_additions[@]}" | sort -u | tr '\n' ' '); final_ignoreip_list=$(echo "$final_ignoreip_list" | sed 's/ $//')
        info "Proposed updated ignoreip list: $final_ignoreip_list"
        if ask_yes_no "Update ignoreip in [DEFAULT] section of '$jail_local'?" "y"; then
             backup_file "$jail_local" || return 1
             local temp_sed_file; temp_sed_file=$(mktemp /tmp/f2b-ignoreip.XXXXXX)
             # Use awk to replace/add ignoreip in [DEFAULT] section robustly
             awk -v new_ignoreip="$final_ignoreip_list" '
             BEGIN { in_default = 0; ignoreip_found = 0; }
             /^\s*\[DEFAULT\]/ { print; in_default = 1; next; }
             /^\s*\[/ && NR > 1 && in_default { # Leaving DEFAULT section
                 if (!ignoreip_found) { print "ignoreip = " new_ignoreip; }
                 in_default = 0; ignoreip_found = 1; # Mark as handled
             }
             in_default && /^\s*#?\s*ignoreip\s*=/ { # Found existing line in DEFAULT
                 if (!ignoreip_found) { print "ignoreip = " new_ignoreip; } # Print new one first time
                 ignoreip_found = 1; # Mark as found/replaced
                 next; # Skip printing the old line
             }
             { print } # Print other lines
             END { if (in_default && !ignoreip_found) print "ignoreip = " new_ignoreip; } # Add if DEFAULT is last section and not found
             ' "$jail_local" > "$temp_sed_file" || { error "AWK processing for ignoreip failed."; rm "$temp_sed_file" 2>/dev/null; return 1; }

             # DRY-RUN Handling for applying ignoreip changes
             if $DRY_RUN; then
                  dry_run_echo "mv \"$temp_sed_file\" \"$jail_local\""
                  success "DRY-RUN: Would update ignoreip in '$jail_local'."
                  needs_restart=true
                  rm "$temp_sed_file" 2>/dev/null
             else
                 if mv "$temp_sed_file" "$jail_local"; then
                      success "ignoreip updated in '$jail_local'."
                      log_change "MODIFIED:$jail_local (ignoreip updated)"
                      needs_restart=true
                 else
                      error "Failed to move temp file for ignoreip update."; rm "$temp_sed_file" 2>/dev/null; restore_file "$jail_local"; return 1;
                 fi
             fi
        fi
    else success "All detected local IPv4 subnets seem covered by ignoreip.";
    fi

    # Service Management
    info "Checking Fail2ban service status..."
    local needs_start=false needs_enable=false
    if ! systemctl is-active --quiet "$pkg"; then warn "Fail2ban service not active."; needs_start=true; fi
    if ! systemctl is-enabled --quiet "$pkg"; then warn "Fail2ban service not enabled."; needs_enable=true; fi

    if [[ "$needs_restart" = true ]]; then
         info "Configuration changed, restarting Fail2ban..."
         # Use reload-or-restart for less disruption
         # DRY-RUN Handling for restart/reload
         if execute_command "SERVICE_RELOADED:$pkg" "systemctl reload-or-restart \"$pkg\""; then success "Fail2ban service reloaded/restarted."; else error "Failed to reload/restart Fail2ban."; fi
    elif [[ "$needs_start" = true ]]; then
         if ask_yes_no "Start Fail2ban service now?" "y"; then
             # DRY-RUN Handling for start
             if execute_command "SERVICE_STARTED:$pkg" "systemctl start \"$pkg\""; then success "Fail2ban service started."; else error "Failed to start Fail2ban."; fi
         fi
    else success "Fail2ban service is active.";
    fi

    if [[ "$needs_enable" = true ]]; then
         if ask_yes_no "Enable Fail2ban service now?" "y"; then
             # DRY-RUN Handling for enable
             if execute_command "SERVICE_ENABLED:$pkg" "systemctl enable \"$pkg\""; then success "Fail2ban service enabled."; else error "Failed to enable Fail2ban."; fi
         fi
    else success "Fail2ban service is enabled.";
    fi

    echo "--- Section 4b completed ---"; echo
}
# --- End Fail2ban ---

# --- SSHGuard ---
configure_sshguard() {
    info "${C_BOLD}4c. SSHGuard Configuration${C_RESET}"
    if ! ask_yes_no "Configure SSHGuard?" "y"; then info "SSHGuard skipped."; echo; return 0; fi

    local pkg="sshguard" whitelist_file="/etc/sshguard/whitelist"
    local needs_restart=false # Track if service needs restart

    # Install Package
    if ! is_package_installed "$pkg"; then
        warn "'$pkg' not installed."
        if ask_yes_no "Install '$pkg'?" "y"; then
             if ! $SCRIPT_APT_UPDATED; then info "Running 'apt update'..."; execute_command "APT_UPDATE" "apt update" && SCRIPT_APT_UPDATED=true || { error "'apt update' failed."; return 1; }; fi
             if execute_command "INSTALLED:$pkg" "apt install -y \"$pkg\""; then success "'$pkg' installed."; else error "Installation failed."; return 1; fi
        else info "SSHGuard skipped."; return 0; fi
    else success "Package '$pkg' is already installed.";
    fi

    # Check service status (read-only)
    info "Checking SSHGuard service status..."
    local needs_start=false needs_enable=false
    if ! systemctl is-active --quiet "$pkg"; then warn "SSHGuard service not active."; needs_start=true; else success "SSHGuard service is active."; fi
    if ! systemctl is-enabled --quiet "$pkg"; then warn "SSHGuard service not enabled."; needs_enable=true; else success "SSHGuard service is enabled."; fi

    # Determine firewall backend (read-only)
    local backend="UNKNOWN"
    if command -v ufw > /dev/null && ufw status | grep -q "Status: active"; then backend="UFW"; info "Detected UFW backend.";
    elif command -v nft > /dev/null && nft list ruleset | grep -q 'hook input'; then backend="nftables"; info "Detected nftables backend.";
    elif command -v iptables > /dev/null && iptables -L INPUT -n | grep -q 'Chain INPUT'; then backend="iptables"; info "Detected iptables backend.";
    else warn "Could not determine active firewall backend (UFW, nftables, iptables).";
    fi

    # Manage whitelist
    info "Checking SSHGuard whitelist..."
    # DRY-RUN Handling for directory creation
    execute_command "MKDIR_SSHGUARD_DIR:$(dirname "$whitelist_file")" "mkdir -p \"$(dirname "$whitelist_file")\"" || { error "Failed to ensure whitelist directory exists."; }

    if [[ ! -f "$whitelist_file" ]]; then
        info "Whitelist '$whitelist_file' not found."
        # DRY-RUN Handling for touch
        if execute_command "ADDED_FILE:$whitelist_file (empty)" "touch \"$whitelist_file\""; then success "Created empty whitelist file."; else error "Failed to create whitelist file."; fi
    else info "Whitelist '$whitelist_file' found."; fi

    local apply_whitelist=false warned_sipcalc=false; local proposed_whitelist=()
    proposed_whitelist+=("127.0.0.1" "::1") # Loopback
    local local_ips4; local_ips4=$(ip -4 addr show | grep -oP 'inet \K[\d.]+' | grep -v '^127\.')
    local local_ips6; local_ips6=$(ip -6 addr show scope global | grep -oP 'inet6 \K[0-9a-fA-F:]+')
    for ip in $local_ips4; do local subnet4=$(echo "$ip" | cut -d. -f1-3).0/24; if ! printf '%s\n' "${proposed_whitelist[@]}" | grep -qxF "$subnet4"; then proposed_whitelist+=("$subnet4"); fi; done
    for ip in $local_ips6; do local cidr6=""; if command -v sipcalc >/dev/null; then local subnet6=$(sipcalc "$ip" | awk '/Network address/ {print $NF}'); local prefix6=$(sipcalc "$ip" | awk '/Network mask \(prefix\)/ {print $NF}'); if [[ -n "$subnet6" && -n "$prefix6" ]]; then cidr6="${subnet6}/${prefix6}"; fi; fi; if [[ -z "$cidr6" ]]; then if ! command -v sipcalc >/dev/null && [[ "$warned_sipcalc" != "true" ]]; then warn "Cannot determine IPv6 subnet precisely (is 'sipcalc' installed?). Using /64."; warned_sipcalc=true; fi; IFS=':' read -ra parts <<< "$ip"; local subnet_guess=$(printf "%s:%s:%s:%s::" "${parts[0]}" "${parts[1]}" "${parts[2]}" "${parts[3]}"); cidr6="${subnet_guess}/64"; fi; if ! printf '%s\n' "${proposed_whitelist[@]}" | grep -qxF "$cidr6"; then proposed_whitelist+=("$cidr6"); fi; done

    local missing_items=(); declare -A existing_whitelist_map
    if [[ -f "$whitelist_file" ]]; then while IFS= read -r line || [[ -n "$line" ]]; do [[ -z "$line" ]] || [[ "$line" =~ ^# ]] && continue; existing_whitelist_map["$line"]=1; done < "$whitelist_file"; fi
    for item in "${proposed_whitelist[@]}"; do if [[ ! -v existing_whitelist_map["$item"] ]]; then missing_items+=("$item"); apply_whitelist=true; fi; done

    if [[ "$apply_whitelist" = true ]]; then
        warn "Missing local IPs/subnets in '$whitelist_file': ${missing_items[*]}"
        if ask_yes_no "Add missing local IPs/subnets to whitelist '$whitelist_file'?" "y"; then
            backup_file "$whitelist_file" || return 1
            # DRY-RUN Handling for appending to whitelist
            local content_to_append=$(printf '%s\n' "${missing_items[@]}")
            if $DRY_RUN; then
                dry_run_echo "echo -e \"$content_to_append\" >> \"$whitelist_file\""
                dry_run_echo "sort -u \"$whitelist_file\" -o \"$whitelist_file\" # Sort and unique"
                success "DRY-RUN: Would add missing items to '$whitelist_file'."
                needs_restart=true
            else # Actual execution
                if printf '%s\n' "${missing_items[@]}" >> "$whitelist_file"; then
                    # Optional: Sort and unique
                    local temp_wl_sort; temp_wl_sort=$(mktemp /tmp/sshguard-wl-sort.XXXXXX)
                    if sort -u "$whitelist_file" -o "$temp_wl_sort" && mv "$temp_wl_sort" "$whitelist_file"; then
                        success "Updated and sorted SSHGuard whitelist '$whitelist_file'."
                        log_change "MODIFIED:$whitelist_file (Added missing local IPs/subnets)"
                        needs_restart=true
                    else
                        warn "Appended to whitelist, but failed to sort/unique."; rm "$temp_wl_sort" 2>/dev/null
                        log_change "MODIFIED:$whitelist_file (Added missing local IPs/subnets - unsorted)"
                        needs_restart=true
                    fi
                else
                     error "Failed to append to whitelist file."; restore_file "$whitelist_file"; return 1
                fi
            fi # End dry run check for append
        fi
    else success "All detected local IPs/subnets seem present in '$whitelist_file'.";
    fi

    # Service Management
    if [[ "$needs_start" = true ]]; then
        # DRY-RUN Handling for start
        if execute_command "SERVICE_STARTED:$pkg" "systemctl start \"$pkg\""; then success "SSHGuard service started."; else error "Error starting SSHGuard."; fi
    elif [[ "$needs_restart" = true ]]; then
        info "Configuration changed, restarting SSHGuard..."
        # DRY-RUN Handling for restart
        if execute_command "SERVICE_RESTARTED:$pkg" "systemctl restart \"$pkg\""; then success "SSHGuard service restarted."; else error "Error restarting SSHGuard."; fi
    fi
    if [[ "$needs_enable" = true ]]; then
        # DRY-RUN Handling for enable
        if execute_command "SERVICE_ENABLED:$pkg" "systemctl enable \"$pkg\""; then success "SSHGuard permanently enabled."; else error "Error enabling SSHGuard."; fi
    fi

    echo "--- Section 4c completed ---"; echo
}
# --- End SSHGuard ---

# --- UFW Firewall Functions ---

# --- UFW Firewall Functions ---

# Global associative array for UFW allowed ports (Bash 4+)
# Keys will be "port/proto" (e.g., "80/tcp", "53/udp") or just "port" if protocol isn't specified in UFW rule
declare -gA ufw_allowed_rules_map

# Function to populate ufw_allowed_rules_map
get_ufw_allowed_rules() {
    # Reset the map
    ufw_allowed_rules_map=()
    debug "Reset ufw_allowed_rules_map"

    if ! ufw status | grep -q "Status: active"; then
        warn "UFW is inactive. Cannot get allowed rules."
        return 1
    fi

    local ufw_output
    # Use 'ufw status verbose' for potentially more detail if needed, but numbered is often easier to parse
    ufw_output=$(ufw status numbered)
    # debug "Raw UFW Status (numbered):\n$ufw_output" # Keep debug off by default

    local line_num=0
    local rule_spec=""
    # Process numbered output line by line
    while IFS= read -r line; do
        # Skip header lines, empty lines, and separator lines
        if [[ "$line" =~ ^Status: || "$line" =~ ^To[[:space:]]+Action || "$line" =~ ^-- || -z "$line" ]]; then
            continue
        fi

        # Extract the 'To' field which contains the port/proto
        # Regex tries to capture common formats like '80', '22/tcp', '5000:5100/udp', etc.
        # It also handles (v6) suffix
        if [[ "$line" =~ \[([[:space:]]?[0-9]+)\][[:space:]]+([^[:space:]]+([/][a-z]+)?)[[:space:]]+(ALLOW[[:space:]]+IN)[[:space:]]+ ]]; then
             rule_spec="${BASH_REMATCH[2]}" # The core rule specifier (e.g., 80, 22/tcp, 5000:5100/udp)
             # Normalize: Remove (v6) if present for map key consistency
             rule_spec=${rule_spec%% \(v6\)}

             # Normalize simple number to number/tcp as default assumption?
             # Or keep it as just the number? Let's keep it simple first.
             # If rule_spec is just a number, UFW often implies both TCP and UDP.
             # If it contains '/', it's specific.
             # For the map, use the exact specifier found.
             if [[ -n "$rule_spec" ]]; then
                 ufw_allowed_rules_map["$rule_spec"]=1
                 debug "Added allowed UFW rule specifier to map: $rule_spec"
             fi
        else
             debug "Could not parse UFW rule line: $line"
        fi
    done <<< "$ufw_output"

    # Fallback or alternative: Parse 'ufw status verbose' if numbered fails or lacks detail
    # This part can be added if the numbered output proves insufficient. For now, let's rely on numbered.

    debug "Finished populating ufw_allowed_rules_map. Size: ${#ufw_allowed_rules_map[@]}"
    [[ ${#ufw_allowed_rules_map[@]} -gt 0 ]] || warn "Could not parse any specific ALLOW IN rules from UFW status."
    return 0
}


# Function to get listening ports (Corrected Parsing)
# Function to get listening ports (Using split for Port Extraction)
# Function to get listening ports (Using split for Port Extraction - Cleaned)
get_listening_ports() {
    local ss_tcp_output ss_udp_output port proto listen_addr

    # Get TCP listening ports
    ss_tcp_output=$(ss -ltnp 2>/dev/null)
    if [[ -n "$ss_tcp_output" ]]; then
        # Process TCP output
        echo "$ss_tcp_output" | awk 'NR > 1 && $1 == "LISTEN" {
            listen_addr_field = $4 # 4th field is Local Address:Port
            n = split(listen_addr_field, addr_parts, ":")
            port = addr_parts[n]
            if (port ~ /^[0-9]+$/ && port > 0 && port < 65536) {
                process_info = "Unknown Process"
                line_remainder = $0
                if (match(line_remainder, /users:\(\("([^"]+)"/)) {
                    process_info = substr(line_remainder, RSTART + 8, RLENGTH - 9)
                }
                print port ",tcp," process_info
            }
        }'
    fi

    # Get UDP listening ports
    ss_udp_output=$(ss -lunp 2>/dev/null)
    if [[ -n "$ss_udp_output" ]]; then
        # Process UDP output
        echo "$ss_udp_output" | awk 'NR > 1 && $1 == "UNCONN" {
            listen_addr_field = $4 # 4th field is Local Address:Port
            n = split(listen_addr_field, addr_parts, ":")
            port = addr_parts[n]
            if (port ~ /^[0-9]+$/ && port > 0 && port < 65536) {
                process_info = "Unknown Process"
                line_remainder = $0
                if (match(line_remainder, /users:\(\("([^"]+)"/)) {
                    process_info = substr(line_remainder, RSTART + 8, RLENGTH - 9)
                }
                print port ",udp," process_info
            }
        }'
    fi
}

# --- Main UFW Configuration Function (Cleaned) ---
configure_ufw() {
    info "${C_BOLD}6. UFW (Firewall) Configuration${C_RESET}"
    if ! ask_yes_no "Execute this step (UFW)?" "y"; then info "Step skipped."; echo; return 0; fi

    # --- Installation ---
    if ! is_package_installed "ufw"; then
        warn "UFW package not installed."
        if ask_yes_no "Install UFW?" "y"; then
             if ! $SCRIPT_APT_UPDATED; then info "Running 'apt update'..."; execute_command "APT_UPDATE" "apt update" && SCRIPT_APT_UPDATED=true || { error "'apt update' failed."; return 1; }; fi
             if execute_command "INSTALLED:ufw" "apt install -y ufw"; then success "UFW installed."; else error "UFW installation failed."; return 1; fi
        else info "UFW skipped."; return 0; fi
    fi

    info "Checking UFW status and rules..."
    ufw status verbose

    # --- Enable UFW if inactive ---
    if ! ufw status | grep -q "Status: active"; then
        warn "UFW is installed but not active."
        if ask_yes_no "Enable UFW now (might disconnect SSH if rule missing)? WARNING!" "n"; then
            local ssh_port_ufw; ssh_port_ufw=$(get_effective_sshd_config "port"); ssh_port_ufw=${ssh_port_ufw:-22}
            if validate_port "$ssh_port_ufw"; then
                info "Ensuring SSH port $ssh_port_ufw/tcp is allowed before enabling UFW..."
                local ssh_allow_cmd="ufw allow \"$ssh_port_ufw/tcp\" comment \"Allow SSH access before UFW enable\""
                if $DRY_RUN; then dry_run_echo "$ssh_allow_cmd"; else eval "$ssh_allow_cmd"; fi
            else warn "Could not determine SSH port. Skipping pre-allow rule."; fi

            if execute_command "UFW_ENABLED" "ufw enable"; then success "UFW enabled."; else error "Failed to enable UFW."; fi
        else info "UFW remains inactive."; echo "--- Section 6 completed ---"; echo; return 0; fi
    else success "UFW is active."; fi

    # --- Get Allowed Rules ---
    if ! get_ufw_allowed_rules; then
        error "Could not reliably get UFW allowed rules. Skipping interactive check.";
        echo "--- Section 6 completed ---"; echo; return 1;
    fi
    info "Found ${#ufw_allowed_rules_map[@]} unique ALLOW IN rule specifiers in UFW."

    # --- Identify Listening Ports ---
    info "Determining listening host & container ports..."
    declare -A listening_ports_map
    local all_ports_output
    all_ports_output="$(get_listening_ports)$(get_container_ports)"

    if [[ -z "$all_ports_output" ]]; then
        info "No listening ports detected (or failed to parse)."
    else
        local unique_ports_count=0
        while IFS="," read -r port proto process_info; do
             if [[ -n "$port" && -n "$proto" ]]; then
                local key="$port/$proto"
                if [[ ! -v listening_ports_map["$key"] ]]; then
                   listening_ports_map["$key"]="${process_info:-Unknown Process}"
                   unique_ports_count=$((unique_ports_count + 1))
                fi
             fi
        done <<< "$all_ports_output"
        success "Detected $unique_ports_count unique listening port/protocol pairs (host+container)."
    fi

    # --- Check if map is empty ---
    if [[ ${#listening_ports_map[@]} -eq 0 ]]; then
        info "No listening ports found to check against firewall.";
        echo "--- Section 6 completed ---"; echo; return 0;
    fi

    # --- Get SSH port ---
    local ssh_port; ssh_port=$(get_effective_sshd_config "port"); ssh_port=${ssh_port:-22}
    if ! validate_port "$ssh_port"; then warn "Could not reliably determine SSH port, assuming 22."; ssh_port=22;
    else success "Detected SSH Port: $ssh_port."; fi
    local ssh_rule_spec="${ssh_port}/tcp"

    # --- Interactive Check ---
    info "Starting interactive port allow check..."
    local ports_to_allow=() ports_to_deny=()

    local sorted_listening_keys=($(printf '%s\n' "${!listening_ports_map[@]}" | sort -t '/' -k1,1n -k2,2))

    for key in "${sorted_listening_keys[@]}"; do
        local port="${key%%/*}"
        local proto="${key##*/}"
        local process_info="${listening_ports_map[$key]}"

        local is_allowed=false
        if [[ -v ufw_allowed_rules_map["$key"] ]]; then
            is_allowed=true
        elif [[ "$key" =~ / ]] && [[ -v ufw_allowed_rules_map["$port"] ]] && ! printf '%s\n' "${!ufw_allowed_rules_map[@]}" | grep -q "^${port}/"; then
             is_allowed=true
        fi

        if $is_allowed; then
            info "Port ${C_BOLD}${key}${C_RESET} (Process: $process_info) already allowed in UFW (Skipping)."
            continue
        fi

        if [[ "$key" == "$ssh_rule_spec" ]]; then
            info "SSH port $key -> Will be automatically marked for ALLOW."
            ports_to_allow+=("$key")
            continue
        fi

        echo
        info "Detected listening port: ${C_BOLD}$key${C_RESET} (Process: $process_info) - ${C_YELLOW}Not explicitly allowed in UFW.${C_RESET}"
        if ask_yes_no "Allow incoming connections to $key?" "n"; then
            ports_to_allow+=("$key")
            success "Port $key -> Marked for ALLOW."
        else
            ports_to_deny+=("$key")
            warn "Port $key -> Marked for DENY."
        fi
    done

    # --- Apply Rules ---
    if [[ ${#ports_to_allow[@]} -gt 0 ]]; then
        info "Applying new ALLOW rules for: ${ports_to_allow[*]}"
        local rules_applied_count=0
        for rule_spec_to_add in "${ports_to_allow[@]}"; do
            local port_num="${rule_spec_to_add%%/*}"
            local comment="Allowed by security script $(date +%Y-%m-%d)"

            local already_effectively_allowed=false
             if [[ -v ufw_allowed_rules_map["$rule_spec_to_add"] ]]; then
                 already_effectively_allowed=true
             elif [[ "$rule_spec_to_add" =~ / ]] && [[ -v ufw_allowed_rules_map["$port_num"] ]] && ! printf '%s\n' "${!ufw_allowed_rules_map[@]}" | grep -q "^${port_num}/"; then
                 already_effectively_allowed=true
             fi

            if ! $already_effectively_allowed; then
                 if execute_command "UFW_RULE_ADDED:ALLOW $rule_spec_to_add" "ufw insert 1 allow \"$rule_spec_to_add\" comment \"$comment\""; then
                     success "Rule 'ALLOW $rule_spec_to_add' added."
                     ufw_allowed_rules_map["$rule_spec_to_add"]=1 # Keep map updated
                     rules_applied_count=$((rules_applied_count + 1))
                 else
                     error "Failed to add rule 'ALLOW $rule_spec_to_add'."
                 fi
            else
                 info "Rule for '$rule_spec_to_add' seems effectively allowed already. Skipping redundant add."
            fi
        done
        if [[ $rules_applied_count -gt 0 ]]; then
             info "$rules_applied_count new ALLOW rule(s) potentially applied (check UFW status)."
             if ! $DRY_RUN; then
                  info "Reloading UFW to apply changes..."
                  if ufw reload; then success "UFW reloaded."; else warn "UFW reload command failed."; fi
             fi
        fi
    else
        info "No new ports selected to be allowed."
    fi

    # --- Final Summary ---
    echo
    info "--- UFW Summary ---"
    info "Final UFW Status (after potential changes):"
    ufw status verbose

    local final_allowed_str=""
    local sorted_keys=$(printf '%s\n' "${!ufw_allowed_rules_map[@]}" | sort)
    while IFS= read -r key; do final_allowed_str+="$key "; done <<< "$sorted_keys"
    final_allowed_str=$(echo "$final_allowed_str" | sed 's/ $//')
    info "Allowed Rule Specifiers (from internal map): $final_allowed_str"

    if [[ ${#ports_to_deny[@]} -gt 0 ]]; then
        info "Ports user chose NOT to allow/add: ${ports_to_deny[*]}"
    fi

    echo "--- Section 6 completed ---"
    echo
}
# --- End of UFW functions ---

# End of UFW functions

# --- Journald ---
configure_journald() {
    info "${C_BOLD}7. Configure Systemd-Journald Log Limit${C_RESET}" # Renumbered section
    if ! ask_yes_no "Execute this step (Journald Log Limit)?" "y"; then info "Step skipped."; echo; return 0; fi

    local config_file="/etc/systemd/journald.conf"; local param_key="SystemMaxUse"; local desired_value="${JOURNALD_MAX_USE}"
    info "Checking Journald disk usage limit..."
    local current_value; if [[ -f "$config_file" ]]; then current_value=$(grep -E "^\s*$param_key=" "$config_file" | tail -n 1 | cut -d'=' -f2 | sed 's/^[ \t]*//;s/[ \t]*$//'); else warn "Journald config '$config_file' not found."; current_value=""; fi

    if [[ "$current_value" == "$desired_value" ]]; then
        success "Journald $param_key already set to '$desired_value'."
    else
        if [[ -n "$current_value" ]]; then warn "Journald $param_key is '$current_value' (or default)."; else warn "Journald $param_key not explicitly set."; fi
        info "Recommended: $desired_value"
        if ask_yes_no "Set $param_key to '$desired_value' in '$config_file'?" "y"; then
            backup_file "$config_file" || return 1
            local temp_journal_conf; temp_journal_conf=$(mktemp)
            cp "$config_file" "$temp_journal_conf"

            # Modify or add the parameter robustly in temp file
            if grep -qE "^\s*#?\s*$param_key=" "$temp_journal_conf"; then
                 sed -i -E "s|^\s*#?\s*($param_key)\s*=.*|$param_key=$desired_value|" "$temp_journal_conf"
            else
                 if grep -q "^\s*\[Journal\]" "$temp_journal_conf"; then sed -i "/^\s*\[Journal\]/a $param_key=$desired_value" "$temp_journal_conf";
                 else warn "No [Journal] section found. Appending."; echo "" >> "$temp_journal_conf"; echo "[Journal]" >> "$temp_journal_conf"; echo "$param_key=$desired_value" >> "$temp_journal_conf"; fi
            fi
            info "Set '$param_key=$desired_value' in temporary journald config."
            # DRY-RUN Handling for applying journald changes
            if $DRY_RUN; then
                dry_run_echo "mv \"$temp_journal_conf\" \"$config_file\""
                dry_run_echo "chmod 644 \"$config_file\"" # Though mv usually preserves
                dry_run_echo "systemctl restart systemd-journald"
                success "DRY-RUN: Would set $param_key to '$desired_value' and restart journald."
                rm -f "$temp_journal_conf" 2>/dev/null
            else # Actual Execution
                 if mv "$temp_journal_conf" "$config_file"; then
                      chmod 644 "$config_file"
                      success "$param_key set to '$desired_value' in '$config_file'."
                      log_change "MODIFIED_PARAM:$param_key:$desired_value:$config_file"
                      info "Restarting systemd-journald service..."
                      if systemctl restart systemd-journald; then success "systemd-journald restarted."; log_change "SERVICE_RESTARTED:systemd-journald"; else error "Failed to restart systemd-journald."; fi
                 else
                      error "Failed to move temp journald config."; rm -f "$temp_journal_conf" 2>/dev/null; restore_file "$config_file"; return 1;
                 fi
            fi # End dry run check for journald apply
        else info "$param_key remains unchanged."; fi
    fi
    echo "--- Section 7 completed ---"; echo # Renumbered section
}
# --- End Journald ---

# --- ClamAV ---
configure_clamav() {
    info "${C_BOLD}8. ClamAV Antivirus Setup${C_RESET}" # Renumbered section
    if ! ask_yes_no "Execute this step (ClamAV Setup)?" "y"; then info "Step skipped."; echo; return 0; fi

    local clamav_pkg="clamav" clamav_daemon_pkg="clamav-daemon"; local freshclam_service="clamav-freshclam" clamd_service="clamav-daemon"
    local clamav_db_dir="/var/lib/clamav"; local main_db_file="${clamav_db_dir}/main.cvd"; local daily_db_file="${clamav_db_dir}/daily.cvd"; local bytecode_db_file="${clamav_db_dir}/bytecode.cvd"
    local initial_freshclam_success=false

    info "Checking ClamAV package status..."
    local install_clamav=false pkgs_to_install=""
    if ! is_package_installed "$clamav_pkg"; then warn "'$clamav_pkg' not installed."; install_clamav=true; pkgs_to_install+="$clamav_pkg "; else success "'$clamav_pkg' installed."; fi
    if ! is_package_installed "$clamav_daemon_pkg"; then warn "'$clamav_daemon_pkg' not installed."; install_clamav=true; pkgs_to_install+="$clamav_daemon_pkg "; else success "'$clamav_daemon_pkg' installed."; fi

    if $install_clamav && [[ -n "$pkgs_to_install" ]]; then
        if ask_yes_no "Install ClamAV packages ($pkgs_to_install)?" "y"; then
            if ! $SCRIPT_APT_UPDATED; then info "Running 'apt update'..."; execute_command "APT_UPDATE" "apt update" && SCRIPT_APT_UPDATED=true || { error "'apt update' failed."; return 1; }; fi
            if execute_command "INSTALLED_CLAMAV_PKGS" "apt install -y $pkgs_to_install"; then success "Packages installed."; else error "ClamAV installation failed."; return 1; fi
            # Log individual packages if successful and not dry run
            if ! $DRY_RUN; then
                [[ "$pkgs_to_install" =~ "$clamav_pkg" ]] && log_change "INSTALLED:$clamav_pkg"
                [[ "$pkgs_to_install" =~ "$clamav_daemon_pkg" ]] && log_change "INSTALLED:$clamav_daemon_pkg"
            fi
        else info "ClamAV skipped."; echo "--- Section 8 completed ---"; echo; return 0; fi # Renumbered section
    fi

    # Initial Freshclam Run
    info "Attempting initial ClamAV definition download..."
    if systemctl is-active --quiet "$freshclam_service"; then
        info "Stopping $freshclam_service temporarily..."
        # DRY-RUN Handling for stop
        execute_command "SERVICE_STOPPED:$freshclam_service (temp)" "systemctl stop \"$freshclam_service\"" || warn "Could not stop $freshclam_service."
        if ! $DRY_RUN; then sleep 2; fi # Pause only if actually stopped
    fi

    if ask_yes_no "Run 'freshclam' manually now (may take time)?" "y"; then
        info "Running freshclam..."
        local freshclam_cmd="freshclam"; [[ "$SCRIPT_DEBUG" != "true" ]] && freshclam_cmd="freshclam --quiet"
        # DRY-RUN Handling for freshclam command
        if execute_command "COMMAND_RUN:freshclam (Initial)" "$freshclam_cmd"; then
            success "Freshclam finished successfully."
            initial_freshclam_success=true
            if ! $DRY_RUN; then sleep 3; fi
        else
            error "Initial freshclam failed. Check '/var/log/clamav/freshclam.log'."
            initial_freshclam_success=false
        fi
    else
        warn "Skipped initial freshclam run."
        # Check if files exist anyway (read-only)
        if [[ -f "$main_db_file" && -f "$daily_db_file" ]] || [[ -f "${clamav_db_dir}/main.cld" && -f "${clamav_db_dir}/daily.cld" ]]; then info "Definition files seem to exist already."; initial_freshclam_success=true; fi
    fi

    # Configure freshclam service
    info "Configuring '$freshclam_service'..."
    if systemctl list-unit-files | grep -q "^${freshclam_service}\.service"; then
        local needs_freshclam_start=false needs_freshclam_enable=false
        if ! systemctl is-active --quiet "$freshclam_service"; then needs_freshclam_start=true; fi
        if ! systemctl is-enabled --quiet "$freshclam_service"; then needs_freshclam_enable=true; fi

        if $needs_freshclam_start; then
            if ask_yes_no "Start '$freshclam_service' now?" "y"; then
                 # DRY-RUN Handling for start
                 execute_command "SERVICE_STARTED:$freshclam_service" "systemctl start \"$freshclam_service\"" && success "'$freshclam_service' started." || error "Failed to start '$freshclam_service'."
            fi
        else success "'$freshclam_service' service seems active."; fi
        if $needs_freshclam_enable; then
            if ask_yes_no "Enable '$freshclam_service' for startup?" "y"; then
                 # DRY-RUN Handling for enable
                 execute_command "SERVICE_ENABLED:$freshclam_service" "systemctl enable \"$freshclam_service\"" && success "'$freshclam_service' enabled." || error "Failed to enable '$freshclam_service'."
            fi
        else success "'$freshclam_service' service is already enabled."; fi
    else warn "Could not find '$freshclam_service'. Verify automatic updates manually.";
    fi

    # Configure clamd service
    info "Checking status of '$clamd_service'..."
    if systemctl list-unit-files | grep -q "^${clamd_service}\.service"; then
        local needs_clamd_start=false needs_clamd_enable=false
        if ! systemctl is-active --quiet "$clamd_service"; then needs_clamd_start=true; fi
        if ! systemctl is-enabled --quiet "$clamd_service"; then needs_clamd_enable=true; fi

        if $needs_clamd_start; then
            if $initial_freshclam_success; then
                 info "Verifying definition files for clamd..."
                 local definitions_ok=false
                 if [[ -f "$main_db_file" && -f "$daily_db_file" ]] || [[ -f "${clamav_db_dir}/main.cld" && -f "${clamav_db_dir}/daily.cld" ]]; then definitions_ok=true; success "Definition files found."; else error "Required definition files not found."; fi

                 if $definitions_ok; then
                     if ask_yes_no "Start '$clamd_service' now?" "y"; then
                          # DRY-RUN Handling for start
                          if execute_command "SERVICE_STARTED:$clamd_service" "systemctl start \"$clamd_service\""; then
                              if ! $DRY_RUN; then sleep 2; fi
                              if systemctl is-active --quiet "$clamd_service" || $DRY_RUN; then success "'$clamd_service' started successfully."; else error "Failed to start '$clamd_service' or it stopped. Check logs."; fi
                          else error "Systemctl command to start '$clamd_service' failed."; fi
                     fi
                 else warn "Cannot start '$clamd_service' - definitions missing."; fi
            else warn "Cannot start '$clamd_service' - freshclam failed or skipped."; fi
        else success "'$clamd_service' service is already active."; fi

        if $needs_clamd_enable; then
            if ask_yes_no "Enable '$clamd_service' for startup?" "y"; then
                 # DRY-RUN Handling for enable
                 execute_command "SERVICE_ENABLED:$clamd_service" "systemctl enable \"$clamd_service\"" && success "'$clamd_service' enabled." || error "Failed to enable '$clamd_service'."
            fi
        else success "'$clamd_service' service is already enabled."; fi
    else warn "Could not find '$clamd_service'."; fi

    echo "--- Section 8 completed ---"; echo # Renumbered section
}
# --- End ClamAV ---


# --- Main Script Execution ---
echo "=== Interactive Linux Server Security Script v1.7.3 ===" # Version Bump
echo "Checks and configures security settings."
echo "Log file: $SCRIPT_LOG_FILE"
echo "Backups: Files ending with '$BACKUP_SUFFIX'"
# DRY_RUN message is shown earlier after parsing args
warn "Use at your own risk! Create backups beforehand!"
echo

if ! ask_yes_no "Proceed?" "y"; then info "Exiting."; exit 0; fi

# Root check done earlier
# Bash version check
if (( BASH_VERSINFO[0] < 4 )); then error "Bash version 4+ required."; exit 1; fi

# Ensure log file directory exists and file is writable (only if not dry run)
if ! $DRY_RUN; then
    log_dir=$(dirname "$SCRIPT_LOG_FILE")
    if [[ ! -d "$log_dir" ]]; then mkdir -p "$log_dir" || { error "Cannot create log directory: $log_dir"; exit 1; }; fi
    if ! touch "$SCRIPT_LOG_FILE" &>/dev/null; then error "Cannot write to log file: $SCRIPT_LOG_FILE"; exit 1; fi
    log_change "SCRIPT_STARTED Version=1.7.3" # Log start only if not dry run
else
    info "DRY-RUN: Logging to $SCRIPT_LOG_FILE is disabled."
fi


# Determine SSH Service Name
if [[ -z "$SSH_SERVICE" ]]; then warn "Could not determine SSH service name, assuming 'sshd'."; SSH_SERVICE="sshd"; fi
info "Using SSH Service Name: $SSH_SERVICE"


# --- Call Functions ---
# Reset apt update tracker
SCRIPT_APT_UPDATED=false

# Define the order of operations
declare -a function_calls=(
    "configure_ssh_key_and_users"       # 1. Keys first
    "configure_unattended_upgrades"     # 2. Updates
    "configure_msmtp"                   # 3. Notifications
    "configure_ssh_hardening"           # 4a. SSH config (needs keys/AllowUsers potentially)
    "configure_google_2fa"              # 4b. 2FA (modifies SSH/PAM)
    "configure_fail2ban"                # 5a. Intrusion Prevention
    "configure_sshguard"                # 5b. Intrusion Prevention
    "configure_ufw"                     # 6. Firewall (needs SSH port open)
    "configure_journald"                # 7. Logging
    "configure_clamav"                  # 8. Antivirus
)

# Execute functions in order
for func in "${function_calls[@]}"; do
    if declare -f "$func" > /dev/null; then
        "$func" # Call the function
        # Optional: Check exit status if needed
        # local status=$?
        # if [[ $status -ne 0 ]]; then
        #     error "Function '$func' failed with status $status. Aborting further steps."
        #     # Decide whether to exit or continue
        #     # exit $status
        # fi
    else
        warn "Function '$func' is not defined. Skipping."
    fi
done


# --- End of Script ---
success "=== Script finished ==="
info "Please review the output."
if ! $DRY_RUN; then
    info "Review changes in the log file ($SCRIPT_LOG_FILE)."
    info "Backups, if created, have the suffix '$BACKUP_SUFFIX'."
    info "In case of issues: Check log file, UFW status ('sudo ufw status'), service statuses."
    info "A system reboot may be recommended to ensure all changes are effective."
    log_change "SCRIPT_FINISHED"
else
    warn "*** DRY-RUN MODE was active. No changes were made to the system. ***"
fi

exit 0
