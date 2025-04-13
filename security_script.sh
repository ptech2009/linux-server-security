#!/bin/bash
# === Interaktives Linux Server Security Skript (V1.0) ===
# Version: 1.0
# Autor: Paul Schumacher
# Zweck: Überprüfung und Härtung von Debian/Ubuntu-Servern.
# Lizenz: Frei verwendbar, aber auf eigene Gefahr. KEINE GARANTIE.
#
# Backup and Recovery:
# - Vor jeder Änderung wird automatisch ein Backup der betroffenen Konfigurationsdatei erstellt.
# - Bei Fehlern wird versucht, das Backup wiederherzustellen.
# - Betroffene Dienste werden nach Bedarf automatisch neu gestartet.
#
# Fail2ban Protection:
# - Automatisches Whitelisting aller nicht-Loopback IPv4-Adressen (z.B. 192.168.x.x) im [sshd]-Jail.

# --- Konfiguration ---
: ${JOURNALD_MAX_USE:="1G"}
SCRIPT_LOG_FILE="/var/log/security_script_changes.log"
BACKUP_SUFFIX=".security_script_backup"
MSMTP_CONFIG_CHOICE="user"  # 'user' (~/.msmtprc) oder 'system' (/etc/msmtprc)
SYSCTL_CONFIG_FILE="/etc/sysctl.d/99-security-script.conf"
SUDOERS_TTY_FILE="/etc/sudoers.d/tty_tickets"
# AllowUsers wird direkt in /etc/ssh/sshd_config konfiguriert

# --- Bestimme den SSH-Dienstnamen ---
if systemctl list-unit-files | grep -q "^ssh\.service"; then
    SSH_SERVICE="ssh"
elif systemctl list-unit-files | grep -q "^sshd\.service"; then
    SSH_SERVICE="sshd"
else
    SSH_SERVICE="sshd"
fi

# --- Farben für die Ausgabe ---
C_RESET='\e[0m'
C_RED='\e[0;31m'
C_GREEN='\e[0;32m'
C_YELLOW='\e[0;33m'
C_BLUE='\e[0;34m'
C_BOLD='\e[1m'

# --- Helper Funktionen ---
info() { echo -e "${C_BLUE}INFO:${C_RESET} $1"; }
success() { echo -e "${C_GREEN}ERFOLG:${C_RESET} $1"; }
warn() { echo -e "${C_YELLOW}WARNUNG:${C_RESET} $1"; }
error() { echo -e "${C_RED}FEHLER:${C_RESET} $1" >&2; }

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
            [YyJj]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) warn "Ungültige Eingabe. Bitte 'y' oder 'n' eingeben." ;;
        esac
    done
}

is_package_installed() { dpkg -s "$1" &>/dev/null; return $?; }
log_change() { echo "$(date '+%Y-%m-%d %H:%M:%S') | $1" >> "$SCRIPT_LOG_FILE"; }

backup_file() {
    local file="$1" backup_path="${file}${BACKUP_SUFFIX}"
    if [[ -f "$file" ]] && [[ ! -f "$backup_path" ]]; then
        if cp -a "$file" "$backup_path"; then
            info "Backup von '$file' erstellt: '$backup_path'"
            log_change "BACKUP_CREATED:$file:$backup_path"
            return 0
        else
            error "Backup von '$file' konnte nicht erstellt werden."
            return 1
        fi
    elif [[ -f "$backup_path" ]]; then
        info "Backup '$backup_path' existiert bereits."
        return 0
    elif [[ ! -f "$file" ]]; then
        return 0
    fi
    return 1
}

restore_file() {
    local file="$1" backup_path="${file}${BACKUP_SUFFIX}"
    if [[ -f "$backup_path" ]]; then
        if mv "$backup_path" "$file"; then
            success "Datei '$file' aus Backup '$backup_path' wiederhergestellt."
            return 0
        else
            error "Wiederherstellung von '$file' aus Backup '$backup_path' fehlgeschlagen."
            return 1
        fi
    else
        if grep -q "ADDED_FILE:$file" "$SCRIPT_LOG_FILE"; then
            if [[ -f "$file" ]]; then
                info "Kein Backup für '$file' gefunden, aber als ADDED_FILE geloggt. Entferne Datei..."
                if rm "$file"; then
                    success "Datei '$file' entfernt."
                    return 0
                else
                    error "Konnte Datei '$file' nicht entfernen."
                    return 1
                fi
            fi
        else
            warn "Kein Backup '$backup_path' für '$file' gefunden. Kann nicht wiederherstellen."
        fi
        return 0
    fi
}

validate_email() { [[ "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && return 0 || return 1; }
validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ] && return 0 || return 1; }

get_effective_sshd_config() {
    local parameter="$1"
    if command -v sshd >/dev/null; then
        sshd -T -C user=root -C host=localhost -C addr=127.0.0.1 2>/dev/null | grep -i "^${parameter}[[:space:]]" | head -n 1 | awk '{print $2}'
    else
        echo "sshd_not_found"
    fi
}

get_effective_sysctl_config() {
    local parameter="$1"
    if sysctl "$parameter" >/dev/null 2>&1; then
        sysctl -n "$parameter"
    else
        echo "not_set"
    fi
}

is_sudo_tty_tickets_active() {
    if sudo grep -rPh --include=\* '^\s*Defaults\s+([^#]*,\s*)?tty_tickets' /etc/sudoers /etc/sudoers.d/ > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

is_fail2ban_jail_enabled() {
    local jail_name="$1" jail_local="/etc/fail2ban/jail.local"
    if [[ ! -f "$jail_local" ]]; then return 1; fi
    local status
    status=$(awk -v jail="[$jail_name]" '
        $0 == jail {in_section=1; enabled_status="false"; next}
        /^\s*\[/ && in_section { exit }
        in_section && /^\s*enabled\s*=\s*true\s*(#.*)?$/ { enabled_status="true"; exit }
        in_section && /^\s*enabled\s*=\s*false\s*(#.*)?$/ { enabled_status="false"; next }
        END { print enabled_status }
    ' "$jail_local")
    [[ "$status" == "true" ]]
}

# --- Funktionsdefinitionen für einzelne Abschnitte ---

configure_ssh_key_and_users() {
    info "${C_BOLD}1. SSH-Schlüsselpaar (Ed25519) erstellen${C_RESET}"
    if ! ask_yes_no "Diesen Schritt (SSH-Key) ausführen?" "y"; then
        info "Schritt wird übersprungen."; echo; return 0
    fi
    local current_user
    if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
        current_user="$SUDO_USER"
    else
        current_user=$(whoami)
    fi
    local user_home; user_home=$(eval echo "~$current_user")
    local existing_ed25519_count=0
    if [[ -d "$user_home/.ssh" ]]; then
        existing_ed25519_count=$(find "$user_home/.ssh" -type f -name "*.pub" -exec grep -Ei "ssh-ed25519" {} + 2>/dev/null | wc -l)
        if [[ -f "$user_home/.ssh/authorized_keys" ]]; then
            local auth_count
            auth_count=$(grep -Ei "ssh-ed25519" "$user_home/.ssh/authorized_keys" | wc -l)
            existing_ed25519_count=$((existing_ed25519_count + auth_count))
        fi
    fi
    if (( existing_ed25519_count > 0 )); then
        success "Mindestens ein Ed25519-Schlüssel in '$user_home/.ssh' gefunden."
    else
        warn "Kein Ed25519-Schlüsselpaar in '$user_home/.ssh' gefunden."
    fi
    if ask_yes_no "Neues Ed25519-SSH-Schlüsselpaar für '$current_user' erstellen?" "n"; then
        local new_key_name; read -p "Dateiname für neuen Schlüssel (z.B. id_ed25519_new): " new_key_name
        new_key_name=${new_key_name:-id_ed25519_new}
        local key_path="$user_home/.ssh/$new_key_name"
        local passphrase passphrase_confirm
        while true; do
            read -sp "Passphrase (leer = keine): " passphrase; echo
            read -sp "Passphrase bestätigen: " passphrase_confirm; echo
            [[ "$passphrase" == "$passphrase_confirm" ]] && break || warn "Passphrasen stimmen nicht überein."
        done
        mkdir -p "$user_home/.ssh"
        chmod 700 "$user_home/.ssh"
        chown "$current_user":"$current_user" "$user_home/.ssh"
        sudo -u "$current_user" ssh-keygen -q -t ed25519 -f "$key_path" -N "$passphrase"
        if [[ $? -eq 0 ]]; then
            success "SSH-Schlüsselpaar '${key_path}' erstellt."
            chmod 600 "$key_path"; chmod 644 "${key_path}.pub"
            chown "$current_user":"$current_user" "$key_path" "${key_path}.pub"
            info "Öffentlicher Schlüssel: ${key_path}.pub"
            info "Bitte in ~/.ssh/authorized_keys der Zielserver einfügen."
            [[ -n "$passphrase" ]] && warn "Passphrase sicher speichern!"
            log_change "SSH_KEY_GENERATED:${key_path}"
        else
            error "Fehler bei der Schlüsselerstellung (als '$current_user')."
        fi
    fi
    echo "--- Abschnitt 1 abgeschlossen ---"
    echo
}

configure_unattended_upgrades() {
    info "${C_BOLD}2. Unattended Upgrades konfigurieren${C_RESET}"
    if ! ask_yes_no "Diesen Schritt (Unattended Upgrades) ausführen?" "y"; then
        info "Schritt wird übersprungen."; echo; return 0
    fi
    local pkg="unattended-upgrades" config_file="/etc/apt/apt.conf.d/50unattended-upgrades" periodic_config_file="/etc/apt/apt.conf.d/20auto-upgrades"
    if ! is_package_installed "$pkg"; then
        warn "'$pkg' nicht installiert."
        if ask_yes_no "Soll '$pkg' installiert werden?" "y"; then
            apt update && apt install -y "$pkg" && log_change "INSTALLED:$pkg" && success "'$pkg' installiert." || { error "Installation fehlgeschlagen."; return 1; }
        else
            info "Unattended Upgrades werden übersprungen."; echo "--- Abschnitt 2 abgeschlossen ---"; echo; return 0
        fi
    else
        success "Paket '$pkg' ist bereits installiert."
    fi
    info "Prüfe Konfiguration von Unattended Upgrades..."
    local apply_changes=false periodic_correct=true
    if [[ ! -f "$periodic_config_file" ]]; then
        warn "'$periodic_config_file' existiert nicht."; periodic_correct=false
    else
        if ! grep -qE '^\s*APT::Periodic::Update-Package-Lists\s*"1"\s*;' "$periodic_config_file"; then
            warn "APT::Periodic::Update-Package-Lists nicht auf \"1\" gesetzt."; periodic_correct=false
        fi
        if ! grep -qE '^\s*APT::Periodic::Unattended-Upgrade\s*"1"\s*;' "$periodic_config_file"; then
            warn "APT::Periodic::Unattended-Upgrades nicht auf \"1\" gesetzt."; periodic_correct=false
        fi
    fi
    [[ "$periodic_correct" = false ]] && apply_changes=true || success "Automatische Ausführung in '$periodic_config_file' korrekt."
    if [[ ! -f "$config_file" ]]; then
        error "Konfigurationsdatei '$config_file' nicht gefunden!"; echo "--- Abschnitt 2 abgeschlossen ---"; echo; return 1
    fi
    local config_correct=true
    local security_origin_pattern='^\s*"\${distro_id}:\${distro_codename}-security";'
    local updates_origin_pattern='^\s*"\${distro_id}:\${distro_codename}-updates";'
    if ! grep -qE "$security_origin_pattern" "$config_file"; then
        warn "Sicherheits-Updatequelle nicht aktiv."; config_correct=false
    fi
    if ! grep -qE "$updates_origin_pattern" "$config_file"; then
        warn "Standard-Updatequelle nicht aktiv (empfohlen)."; config_correct=false
    fi
    local proposed_active_pattern='^\s*"\${distro_id}:\${distro_codename}-proposed";'
    local backports_active_pattern='^\s*"\${distro_id}:\${distro_codename}-backports";'
    if grep -qE "$proposed_active_pattern" "$config_file"; then
        warn "Updatequelle 'proposed' aktiv (nicht empfohlen)."; config_correct=false
    fi
    if grep -qE "$backports_active_pattern" "$config_file"; then
        warn "Updatequelle 'backports' aktiv (nicht empfohlen)."; config_correct=false
    fi
    local remove_unused_deps_pattern='^\s*Unattended-Upgrade::Remove-Unused-Dependencies\s*"true"\s*;'
    local autofix_dpkg_pattern='^\s*Unattended-Upgrade::AutoFixInterruptedDpkg\s*"true"\s*;'
    if ! grep -qE "$remove_unused_deps_pattern" "$config_file"; then
        warn "Remove-Unused-Dependencies nicht auf \"true\"."; config_correct=false
    fi
    if ! grep -qE "$autofix_dpkg_pattern" "$config_file"; then
        warn "AutoFixInterruptedDpkg nicht auf \"true\"."; config_correct=false
    fi
    [[ "$config_correct" = false ]] && apply_changes=true || success "Unattended Upgrades Konfiguration entspricht den Empfehlungen."
    if [[ "$apply_changes" = true ]]; then
        warn "Einige Einstellungen weichen ab."
        if ask_yes_no "Empfohlene Einstellungen jetzt anwenden?" "y"; then
            backup_file "$config_file" || return 1
            backup_file "$periodic_config_file" || return 1
            sed -i -E 's|^//(\s*"\${distro_id}:\${distro_codename}-security";)|\1|' "$config_file"
            sed -i -E 's|^//(\s*"\${distro_id}ESMApps:\${distro_codename}-apps-security";)|\1|' "$config_file"
            sed -i -E 's|^//(\s*"\${distro_id}ESM:\${distro_codename}-infra-security";)|\1|' "$config_file"
            sed -i -E 's|^//(\s*"\${distro_id}:\${distro_codename}-updates";)|\1|' "$config_file"
            sed -i -E 's|^([[:space:]]*"\${distro_id}:\${distro_codename}-proposed";)|//\1|' "$config_file"
            sed -i -E 's|^([[:space:]]*"\${distro_id}:\${distro_codename}-backports";)|//\1|' "$config_file"
            local params_to_set=( 'Unattended-Upgrade::Remove-Unused-Dependencies "true";'
                                    'Unattended-Upgrade::AutoFixInterruptedDpkg "true";'
                                    'Unattended-Upgrade::Automatic-Reboot "false";' )
            for param_line in "${params_to_set[@]}"; do
                local param_key; param_key=$(echo "$param_line" | cut -d' ' -f1)
                if grep -q "$param_key" "$config_file"; then
                    sed -i -E "s|^//?\s*($param_key\s*).*|\t$param_line|" "$config_file"
                else
                    echo -e "\t$param_line" >> "$config_file"
                fi
            done
            mkdir -p "$(dirname "$periodic_config_file")"
            echo "// Generated by security_script.sh" > "$periodic_config_file"
            echo "APT::Periodic::Update-Package-Lists \"1\";" >> "$periodic_config_file"
            echo "APT::Periodic::Unattended-Upgrade \"1\";" >> "$periodic_config_file"
            success "Unattended Upgrades konfiguriert und aktiviert."
            log_change "MODIFIED:$config_file"
            log_change "ADDED_FILE:$periodic_config_file"
        fi
    fi
    echo "--- Abschnitt 2 abgeschlossen ---"
    echo
}

configure_msmtp() {
    info "${C_BOLD}3. MSMTP Einrichtung für Systembenachrichtigungen${C_RESET}"
    if ! ask_yes_no "Diesen Schritt (MSMTP) ausführen?" "y"; then
        info "Schritt (MSMTP) wird übersprungen."; echo; return 0
    fi
    local msmtp_pkg="msmtp" mta_pkg="msmtp-mta" mailutils_pkg="mailutils"
    local config_file_path config_owner user_home
    if [[ "$MSMTP_CONFIG_CHOICE" == "user" ]]; then
        local target_user=$USER
        read -p "Für welchen Benutzer MSMTP-Konfiguration erstellen? [$target_user]: " config_owner
        config_owner=${config_owner:-$target_user}
        user_home=$(eval echo "~$config_owner")
        if [[ -z "$user_home" ]] || [[ ! -d "$user_home" ]]; then
            error "Home-Verzeichnis für '$config_owner' nicht gefunden."; echo "--- Abschnitt 3 abgeschlossen ---"; echo; return 1
        fi
        config_file_path="$user_home/.msmtprc"
        info "MSMTP wird für '$config_owner' in '$config_file_path' konfiguriert."
    else
        config_file_path="/etc/msmtprc"; config_owner="root"; user_home="/root"
        info "MSMTP wird systemweit in '$config_file_path' konfiguriert."
    fi
    local install_pkgs=false
    if ! is_package_installed "$msmtp_pkg" || ! is_package_installed "$mta_pkg"; then
        warn "'$msmtp_pkg' und/oder '$mta_pkg' nicht installiert."
        if ask_yes_no "Pakete installieren?" "y"; then install_pkgs=true; else info "MSMTP wird übersprungen."; echo "--- Abschnitt 3 abgeschlossen ---"; echo; return 0; fi
    else
        success "Pakete '$msmtp_pkg' und '$mta_pkg' sind installiert."
    fi
    if ! is_package_installed "$mailutils_pkg"; then
        warn "Paket '$mailutils_pkg' (für 'mail') nicht installiert."
        if ask_yes_no "Soll '$mailutils_pkg' installiert werden?" "y"; then install_pkgs=true; fi
    fi
    if [[ "$install_pkgs" = true ]]; then
        info "Installiere Pakete: $msmtp_pkg $mta_pkg $mailutils_pkg..."
        local pkgs_to_install=""
        if ! is_package_installed "$msmtp_pkg"; then pkgs_to_install+="$msmtp_pkg "; fi
        if ! is_package_installed "$mta_pkg"; then pkgs_to_install+="$mta_pkg "; fi
        if ! is_package_installed "$mailutils_pkg" && ask_yes_no "Soll 'mailutils' mitinstalliert werden?" "y"; then pkgs_to_install+="$mailutils_pkg "; fi
        if [[ -n "$pkgs_to_install" ]]; then
            apt update && apt install -y $pkgs_to_install && success "Pakete installiert." || { error "Installation fehlgeschlagen."; return 1; }
            [[ "$pkgs_to_install" =~ "$msmtp_pkg" ]] && log_change "INSTALLED:$msmtp_pkg"
            [[ "$pkgs_to_install" =~ "$mta_pkg" ]] && log_change "INSTALLED:$mta_pkg"
            [[ "$pkgs_to_install" =~ "$mailutils_pkg" ]] && log_change "INSTALLED:$mailutils_pkg"
        fi
    fi
    local configure_msmtp=false
    if [[ -f "$config_file_path" ]]; then
        warn "MSMTP-Konfiguration in '$config_file_path' gefunden."
        if ask_yes_no "Soll die Konfiguration neu erstellt werden?" "n"; then configure_msmtp=true; else info "Bestehende Konfiguration wird beibehalten."; fi
    else
        info "Keine Konfiguration in '$config_file_path' gefunden."
        if ask_yes_no "MSMTP jetzt einrichten?" "y"; then configure_msmtp=true; fi
    fi
    if [[ "$configure_msmtp" = true ]]; then
        info "Bitte SMTP-Daten eingeben:"
        local smtp_host smtp_port smtp_tls smtp_trust_file smtp_from smtp_user smtp_password smtp_aliases
        while true; do read -p "SMTP Host: " smtp_host; [[ -n "$smtp_host" ]] && break || warn "Host darf nicht leer sein."; done
        while true; do read -p "SMTP Port [587]: " smtp_port; smtp_port=${smtp_port:-587}; validate_port "$smtp_port" && break || warn "Ungültiger Port."; done
        while true; do read -p "TLS (on/off) [on]: " smtp_tls; smtp_tls=${smtp_tls:-on}; [[ "$smtp_tls" == "on" || "$smtp_tls" == "off" ]] && break || warn "Ungültige Eingabe."; done
        read -p "CA-Zertifikatdatei [/etc/ssl/certs/ca-certificates.crt]: " smtp_trust_file; smtp_trust_file=${smtp_trust_file:-/etc/ssl/certs/ca-certificates.crt}
        while true; do read -p "Absender (From): " smtp_from; validate_email "$smtp_from" && break || warn "Ungültige E-Mail-Adresse."; done
        while true; do read -p "SMTP Benutzername [$smtp_from]: " smtp_user; smtp_user=${smtp_user:-$smtp_from}; validate_email "$smtp_user" && break || warn "Ungültige E-Mail-Adresse."; done
        while true; do read -sp "SMTP Passwort: " smtp_password; echo; [[ -n "$smtp_password" ]] && break || warn "Passwort darf nicht leer sein."; done
        read -p "Alias-Datei [/etc/aliases]: " smtp_aliases; smtp_aliases=${smtp_aliases:-/etc/aliases}
        info "--- Beispielkonfiguration ---"
        echo -e "defaults\nport $smtp_port\ntls $smtp_tls\ntls_trust_file $smtp_trust_file\nlogfile ${user_home}/.msmtp.log\n\naccount root\nhost $smtp_host\nfrom $smtp_from\nauth on\nuser $smtp_user\npassword ********\n\naccount default : root\naliases $smtp_aliases"
        echo "--------------------------------"
        if ask_yes_no "Diese Einstellungen in '$config_file_path' speichern?" "y"; then
            backup_file "$config_file_path" || return 1
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

account default : root

aliases $smtp_aliases
EOF
            chmod 600 "$config_file_path"
            chown "$config_owner":"$config_owner" "$config_file_path"
            success "MSMTP-Konfiguration in '$config_file_path' gespeichert."
            log_change "ADDED_FILE:$config_file_path"
            if is_package_installed "$mailutils_pkg"; then
                if ask_yes_no "Test-E-Mail an '$smtp_from' senden?" "y"; then
                    echo "Dies ist eine Test-E-Mail vom Linux Security Script." | mail -s "MSMTP Test $(date)" "$smtp_from"
                    [[ $? -eq 0 ]] && success "Test-E-Mail versandt." || warn "Test-E-Mail konnte nicht gesendet werden."
                fi
            else
                warn "Paket 'mailutils' nicht gefunden, Test entfällt."
            fi
        fi
    fi
    echo "--- Abschnitt 3 abgeschlossen ---"
    echo
}

# Abschnitt 4a: SSH-Härtung (Bearbeitung von /etc/ssh/sshd_config, inkl. AllowUsers)
configure_ssh_hardening() {
    info "${C_BOLD}4a. SSH-Konfiguration härten (Bearbeitung von /etc/ssh/sshd_config)${C_RESET}"
    if ! ask_yes_no "Diesen Schritt (SSH-Härtung) ausführen?" "y"; then
        info "Schritt (SSH-Härtung) wird übersprungen."; echo; return 0
    fi

    # Optional: AllowUsers-Konfiguration
    if ask_yes_no "Soll die AllowUsers-Einstellung in /etc/ssh/sshd_config angepasst werden?" "n"; then
        local effective_allow_users; effective_allow_users=$(get_effective_sshd_config "allowusers")
        local target_users; local apply_allowusers=false; local suggested_user
        suggested_user=$(awk -F: '$3 >= 1000 && $3 < 65534 { print $1; exit }' /etc/passwd)
        [[ -z "$suggested_user" ]] && suggested_user="admin"
        warn "Empfehlung: SSH-Zugriffe auf Admin-Benutzer (nicht root) beschränken."
        read -p "Welche Benutzer sollen SSH-Zugriff haben? (Vorschlag: $suggested_user, Leer = überspringen): " target_users
        if [[ -n "$target_users" ]]; then
            local all_users_exist=true
            for user in $target_users; do
                if ! id "$user" &>/dev/null; then
                    error "Benutzer '$user' existiert nicht."
                    all_users_exist=false
                fi
            done
            if $all_users_exist; then
                if [[ -n "$effective_allow_users" ]]; then
                    if [[ "$effective_allow_users" == "$target_users" ]]; then
                        success "AllowUsers ist bereits korrekt gesetzt ($effective_allow_users)."
                    else
                        if ask_yes_no "AllowUsers von '$effective_allow_users' auf '$target_users' ändern?" "y"; then
                            apply_allowusers=true
                        fi
                    fi
                else
                    if ask_yes_no "AllowUsers auf '$target_users' setzen?" "y"; then
                        apply_allowusers=true
                    fi
                fi
                if $apply_allowusers; then
                    backup_file "/etc/ssh/sshd_config" || return 1
                    if grep -qE "^\s*AllowUsers" /etc/ssh/sshd_config; then
                        sed -i -E "s|^\s*AllowUsers\s+.*|AllowUsers $target_users|" /etc/ssh/sshd_config
                    else
                        echo "AllowUsers $target_users" >> /etc/ssh/sshd_config
                    fi
                    if sshd -t; then
                        if systemctl restart "$SSH_SERVICE" && systemctl is-active --quiet "$SSH_SERVICE"; then
                            success "SSH-Dienst neu gestartet und AllowUsers gesetzt."
                            log_change "SERVICE_RESTARTED:$SSH_SERVICE"
                        else
                            error "SSH-Dienst nach Neustart inaktiv. Änderungen werden rückgängig gemacht."
                            restore_file "/etc/ssh/sshd_config" && systemctl try-restart "$SSH_SERVICE"
                            return 1
                        fi
                    else
                        error "SSH-Konfigurationstest fehlgeschlagen. Änderungen werden nicht übernommen."
                        restore_file "/etc/ssh/sshd_config"
                        return 1
                    fi
                fi
            else
                info "AllowUsers-Konfiguration wird übersprungen."
            fi
        else
            info "AllowUsers-Konfiguration wird übersprungen."
        fi
    else
        info "AllowUsers-Konfiguration wird übersprungen."
    fi

    # Weitere SSH-Härtung (individuelle Parameter)
    declare -A ssh_recommendations=(
        ["PermitRootLogin"]="prohibit-password"
        ["ChallengeResponseAuthentication"]="no"
        ["PasswordAuthentication"]="no"
        ["UsePAM"]="yes"
        ["X11Forwarding"]="no"
        ["PrintLastLog"]="yes"
    )
    local current_value recommended_value
    declare -A changes_to_apply
    local current_user; if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then current_user="$SUDO_USER"; else current_user=$(whoami); fi
    local user_home; user_home=$(eval echo "~$current_user")
    local ed25519_count=0
    if [[ -d "$user_home/.ssh" ]]; then
        ed25519_count=$(find "$user_home/.ssh" -type f -name "*.pub" -exec grep -Ei "ssh-ed25519" {} + 2>/dev/null | wc -l)
        if [[ -f "$user_home/.ssh/authorized_keys" ]]; then
            local auth_count
            auth_count=$(grep -Ei "ssh-ed25519" "$user_home/.ssh/authorized_keys" | wc -l)
            ed25519_count=$((ed25519_count + auth_count))
        fi
    fi
    for param in "${!ssh_recommendations[@]}"; do
        current_value=$(get_effective_sshd_config "$param")
        if [[ -z "$current_value" && "$param" == "ChallengeResponseAuthentication" ]]; then
            current_value="no"
        fi
        recommended_value="${ssh_recommendations[$param]}"
        if [[ "$param" == "PermitRootLogin" ]]; then
            if [[ "$current_value" == "without-password" || "$current_value" == "prohibit-password" ]]; then
                success "PermitRootLogin ist bereits korrekt ($current_value)."
                continue
            fi
        fi
        if [[ "$current_value" != "$recommended_value" ]]; then
            echo -e "\nParameter: $param"
            echo "Aktuell: $current_value"
            echo "Empfohlen: $recommended_value"
            case "$param" in
                "PermitRootLogin")
                    echo "Erklärung: Direkter Root-Login wird vermieden, um Angriffe zu erschweren." ;;
                "ChallengeResponseAuthentication")
                    echo "Erklärung: Passwortbasierte Challenge/Response-Methoden sind weniger sicher." ;;
                "PasswordAuthentication")
                    echo "Erklärung: Schlüsselbasierte Authentifizierung ist sicherer. ACHTUNG: Ohne SSH-Key können Sie sich aussperren."
                    if [[ $ed25519_count -eq 0 ]]; then
                        warn "Keine SSH-Schlüssel gefunden! Bitte erstellen Sie zuerst ein Schlüsselpaar."
                        continue
                    fi
                    ;;
                "UsePAM")
                    echo "Erklärung: PAM ermöglicht zusätzliche Authentifizierungsprüfungen." ;;
                "X11Forwarding")
                    echo "Erklärung: X11-Weiterleitung bietet potenzielle Angriffsflächen." ;;
                "PrintLastLog")
                    echo "Erklärung: Anzeige des letzten Logins hilft, verdächtige Aktivitäten zu erkennen." ;;
            esac
            if ask_yes_no "Soll $param von '$current_value' auf '$recommended_value' geändert werden?" "y"; then
                changes_to_apply["$param"]="$recommended_value"
            else
                info "$param bleibt unverändert."
            fi
        else
            success "$param ist bereits korrekt ($current_value)."
        fi
    done
    if [ ${#changes_to_apply[@]} -eq 0 ]; then
        info "Keine weiteren Änderungen an der SSH-Härtung ausgewählt."
    else
        info "Folgende Änderungen werden übernommen:"
        for key in "${!changes_to_apply[@]}"; do
            echo "  $key -> ${changes_to_apply[$key]}"
        done
        if ask_yes_no "Änderungen in '/etc/ssh/sshd_config' speichern und SSH neu starten?" "y"; then
            backup_file "/etc/ssh/sshd_config" || return 1
            for key in "${!changes_to_apply[@]}"; do
                if grep -qE "^\s*$key" /etc/ssh/sshd_config; then
                    sed -i -E "s|^\s*$key\s+.*|$key ${changes_to_apply[$key]}|" /etc/ssh/sshd_config
                else
                    echo "$key ${changes_to_apply[$key]}" >> /etc/ssh/sshd_config
                fi
                log_change "MODIFIED_PARAM:$key:${changes_to_apply[$key]}"
            done
            if sshd -t; then
                if systemctl restart "$SSH_SERVICE"; then
                    if systemctl is-active --quiet "$SSH_SERVICE"; then
                        success "SSH-Dienst neu gestartet. Änderungen in /etc/ssh/sshd_config übernommen."
                        log_change "SERVICE_RESTARTED:$SSH_SERVICE"
                    else
                        error "SSH-Dienst nach Neustart inaktiv. Änderungen werden rückgängig gemacht."
                        restore_file "/etc/ssh/sshd_config" && systemctl try-restart "$SSH_SERVICE"
                        return 1
                    fi
                else
                    error "SSH-Dienst konnte nicht neu gestartet werden. Änderungen werden rückgängig gemacht."
                    restore_file "/etc/ssh/sshd_config" && systemctl try-restart "$SSH_SERVICE"
                    return 1
                fi
            else
                error "SSH-Konfigurationstest ('sshd -t') fehlgeschlagen. Änderungen werden nicht übernommen."
                restore_file "/etc/ssh/sshd_config"
                return 1
            fi
        else
            info "Keine Änderungen an der SSH-Härtung übernommen."
        fi
    fi
    echo "--- Abschnitt 4a abgeschlossen ---"
    echo
}

configure_sshguard() {
    info "${C_BOLD}4b. SSHGuard installieren und aktivieren${C_RESET}"
    if ! ask_yes_no "Diesen Schritt (SSHGuard) ausführen?" "y"; then
        info "Schritt (SSHGuard) wird übersprungen."; echo; return 0
    fi
    local pkg="sshguard" installed_now=false
    if is_package_installed "$pkg"; then
        success "Paket '$pkg' ist bereits installiert."
    else
        warn "Paket '$pkg' nicht installiert."
        if ask_yes_no "Soll '$pkg' installiert werden?" "y"; then
            if ! $SCRIPT_APT_UPDATED; then
                info "Führe 'apt update' aus..."
                apt update
                SCRIPT_APT_UPDATED=true
            fi
            if apt install -y "$pkg"; then
                success "'$pkg' erfolgreich installiert."
                log_change "INSTALLED:$pkg"
                installed_now=true
            else
                error "Installation von '$pkg' fehlgeschlagen."
                return 1
            fi
        else
            info "SSHGuard wird übersprungen."; return 0
        fi
    fi
    if is_package_installed "$pkg"; then
        info "Prüfe SSHGuard Dienststatus..."
        local needs_start=false needs_enable=false
        if ! systemctl is-active --quiet "$pkg"; then
            warn "SSHGuard Dienst ist nicht aktiv."; needs_start=true
        else
            success "SSHGuard Dienst ist aktiv."
        fi
        if ! systemctl is-enabled --quiet "$pkg"; then
            warn "SSHGuard Dienst ist nicht für den Systemstart aktiviert."; needs_enable=true
        else
            success "SSHGuard Dienst ist für den Systemstart aktiviert."
        fi
        if [[ "$needs_start" = true ]]; then
            systemctl start "$pkg" && success "SSHGuard Dienst gestartet." && log_change "SERVICE_RESTARTED:$pkg" || error "Fehler beim Starten von SSHGuard."
        fi
        if [[ "$needs_enable" = true ]]; then
            systemctl enable "$pkg" && success "SSHGuard dauerhaft aktiviert." && log_change "SERVICE_ENABLED:$pkg" || error "Fehler beim Aktivieren von SSHGuard."
        fi
    fi
    echo "--- Abschnitt 4b abgeschlossen ---"
    echo
}

configure_journald() {
    info "${C_BOLD}4c. Systemd-Journald Log Limit konfigurieren${C_RESET}"
    if ! ask_yes_no "Diesen Schritt (Journald Log Limit) ausführen?" "y"; then
        info "Schritt (Journald Log Limit) wird übersprungen."; echo; return 0
    fi
    local config_file="/etc/systemd/journald.conf"
    local limit_key="SystemMaxUse" limit_value="$JOURNALD_MAX_USE"
    local limit_line="${limit_key}=${limit_value}"
    info "Prüfe '$config_file' auf '$limit_key'..."
    local current_setting_line
    current_setting_line=$(grep -E "^${limit_key}=" "$config_file" 2>/dev/null | tr -d '[:space:]')
    local expected_line; expected_line=$(echo "$limit_line" | tr -d '[:space:]')
    local apply_change=false
    if [[ -n "$current_setting_line" ]] && [[ "$current_setting_line" == "$expected_line" ]]; then
        success "Journald Log Limit ist bereits auf '$limit_value' gesetzt."
    elif [[ -n "$current_setting_line" ]]; then
        warn "Aktuelle Einstellung: '$current_setting_line'. Empfohlen: '$expected_line'."
        if ask_yes_no "Soll auf '$expected_line' geändert werden?" "y"; then
            apply_change=true
        fi
    else
        warn "Keine explizite Einstellung für '$limit_key' gefunden."
        if ask_yes_no "Soll '$expected_line' gesetzt werden?" "y"; then
            apply_change=true
        fi
    fi
    if [[ "$apply_change" = true ]]; then
        backup_file "$config_file" || return 1
        if grep -qE "^#?\s*${limit_key}=" "$config_file"; then
            sed -i -E "s|^#?\s*${limit_key}=.*|$limit_line|" "$config_file"
        else
            if grep -q "\[Journal\]" "$config_file"; then
                sed -i "/\[Journal\]/a $limit_line" "$config_file"
            else
                echo "" >> "$config_file"
                echo "[Journal]" >> "$config_file"
                echo "$limit_line" >> "$config_file"
            fi
        fi
        if [[ $? -eq 0 ]]; then
            success "Journald Log Limit auf '$limit_value' gesetzt."
            log_change "MODIFIED:$config_file"
            info "Starte systemd-journald neu..."
            if systemctl try-restart systemd-journald; then
                success "systemd-journald neu gestartet."
                log_change "SERVICE_RESTARTED:systemd-journald"
            else
                warn "Neustart von systemd-journald fehlgeschlagen oder nicht nötig."
            fi
        else
            error "Fehler beim Aktualisieren von '$config_file'."
            restore_file "$config_file"
            return 1
        fi
    fi
    echo "--- Abschnitt 4c abgeschlossen ---"
    echo
}

configure_sysctl() {
    info "${C_BOLD}4d. Sysctl Konfiguration (Netzwerksicherheit)${C_RESET}"
    if ! ask_yes_no "Diesen Schritt (Sysctl-Netzwerksicherheit) ausführen?" "y"; then
        info "Schritt (Sysctl) wird übersprungen."; echo; return 0
    fi
    declare -A sysctl_recommendations=(
        ["net.ipv4.tcp_syncookies"]="1"                     # SYN Flood Schutz
        ["net.ipv4.conf.default.rp_filter"]="1"             # Reverse-Path-Filter (Default)
        ["net.ipv4.conf.all.rp_filter"]="1"                 # Reverse-Path-Filter (alle Interfaces)
        ["net.ipv4.conf.all.accept_redirects"]="0"          # Keine ICMP Redirects akzeptieren
        ["net.ipv4.conf.all.send_redirects"]="0"            # Keine ICMP Redirects senden
        ["net.ipv4.conf.all.accept_source_route"]="0"       # Kein Source Routing
        ["net.ipv4.conf.all.log_martians"]="1"              # Log Martian Packets
    )
    local sysctl_config_file="$SYSCTL_CONFIG_FILE"
    local changes_needed=false
    local proposed_settings_lines=()
    info "Prüfe sysctl-Werte..."
    for param in "${!sysctl_recommendations[@]}"; do
        local current_value; current_value=$(get_effective_sysctl_config "$param")
        local recommended_value="${sysctl_recommendations[$param]}"
        if [[ "$current_value" == "not_set" ]]; then
            continue
        fi
        if [[ "$current_value" != "$recommended_value" ]]; then
            warn "- $param aktuell '$current_value', empfohlen '$recommended_value'."
            proposed_settings_lines+=("$param = $recommended_value")
            changes_needed=true
        else
            success "- $param korrekt ($current_value)."
        fi
    done
    if [[ "$changes_needed" = true ]]; then
        echo "Vorgeschlagene sysctl-Änderungen für '$sysctl_config_file':"
        for setting in "${proposed_settings_lines[@]}"; do
            echo "  $setting"
        done
        if ask_yes_no "Änderungen anwenden (schreibt '$sysctl_config_file' und lädt neu)?" "y"; then
            backup_file "$sysctl_config_file" || return 1
            echo "# Optimierte sysctl Konfiguration für Ubuntu Server 22.04.4" > "$sysctl_config_file"
            for p in "${!sysctl_recommendations[@]}"; do
                echo "$p = ${sysctl_recommendations[$p]}" >> "$sysctl_config_file"
            done
            chmod 644 "$sysctl_config_file"
            success "Sysctl-Konfigurationsdatei '$sysctl_config_file' aktualisiert."
            log_change "ADDED_FILE:$sysctl_config_file"
            info "Wende sysctl-Änderungen an..."
            if sysctl -p "$sysctl_config_file"; then
                success "Sysctl-Werte angewendet."
                log_change "SYSCTL_APPLIED:$sysctl_config_file"
            else
                error "Fehler beim Anwenden der sysctl-Werte."
            fi
        fi
    else
        info "Alle sysctl-Einstellungen entsprechen den Empfehlungen."
    fi
    echo "--- Abschnitt 4d abgeschlossen ---"
    echo
}

configure_sudo() {
    info "${C_BOLD}4e. Sudo-Sicherheit verbessern (tty_tickets)${C_RESET}"
    if ! ask_yes_no "Diesen Schritt (Sudo tty_tickets) ausführen?" "y"; then
        info "Schritt (Sudo tty_tickets) wird übersprungen."; echo; return 0
    fi
    local sudo_config_file="$SUDOERS_TTY_FILE"
    info "Prüfe, ob 'tty_tickets' aktiv ist..."
    if is_sudo_tty_tickets_active; then
        success "Sudo tty_tickets ist bereits aktiv."
    else
        warn "Sudo tty_tickets ist nicht aktiv."
        if ask_yes_no "Soll 'tty_tickets' in '$sudo_config_file' aktiviert werden?" "y"; then
            backup_file "$sudo_config_file"
            echo "# Enabled by security_script.sh" > "$sudo_config_file"
            echo "Defaults    tty_tickets" >> "$sudo_config_file"
            chmod 0440 "$sudo_config_file"
            if visudo -c -f "$sudo_config_file"; then
                success "Sudo tty_tickets in '$sudo_config_file' aktiviert."
                log_change "ADDED_FILE:$sudo_config_file"
            else
                error "Syntaxfehler in '$sudo_config_file'. Änderung wird rückgängig gemacht."
                if [[ -f "${sudo_config_file}${BACKUP_SUFFIX}" ]]; then
                    restore_file "$sudo_config_file"
                else
                    rm "$sudo_config_file"
                fi
                return 1
            fi
        fi
    fi
    echo "--- Abschnitt 4e abgeschlossen ---"
    echo
}

configure_fail2ban() {
    info "${C_BOLD}4f. Fail2Ban installieren und konfigurieren${C_RESET}"
    if ! ask_yes_no "Diesen Schritt (Fail2Ban) ausführen?" "y"; then
        info "Schritt (Fail2Ban) wird übersprungen."; echo; return 0
    fi
    local pkg="fail2ban" jail_conf="/etc/fail2ban/jail.conf" jail_local="/etc/fail2ban/jail.local" ssh_jail_name="sshd"
    local installed_now=false changes_applied=false
    if is_package_installed "$pkg"; then
        success "Paket '$pkg' ist bereits installiert."
    else
        warn "Paket '$pkg' ist nicht installiert."
        if ask_yes_no "Soll '$pkg' installiert werden?" "y"; then
            if ! $SCRIPT_APT_UPDATED; then
                info "Führe 'apt update' aus..."
                apt update
                SCRIPT_APT_UPDATED=true
            fi
            if apt install -y "$pkg"; then
                success "'$pkg' erfolgreich installiert."
                log_change "INSTALLED:$pkg"
                installed_now=true
            else
                error "Installation von '$pkg' fehlgeschlagen."
                echo "--- Abschnitt 4f abgeschlossen ---"
                echo; return 1
            fi
        else
            info "Fail2Ban wird übersprungen."
            echo "--- Abschnitt 4f abgeschlossen ---"
            echo; return 0
        fi
    fi
    if is_package_installed "$pkg"; then
        local service_active=false
        if systemctl is-active --quiet "$pkg"; then
            success "Fail2Ban Dienst ist aktiv."
            service_active=true
        else
            warn "Fail2Ban Dienst ist installiert, aber nicht aktiv."
            if [[ "$installed_now" = true ]] || ask_yes_no "Soll der Dienst gestartet werden?" "y"; then
                if systemctl start "$pkg"; then
                    success "Fail2Ban Dienst gestartet."
                    log_change "SERVICE_RESTARTED:$pkg"
                    service_active=true
                else
                    error "Fehler beim Starten von Fail2Ban."
                fi
            fi
        fi
        if ! systemctl is-enabled --quiet "$pkg"; then
            warn "Fail2Ban Dienst ist nicht für den Systemstart aktiviert."
            if [[ "$installed_now" = true ]] || ask_yes_no "Soll Fail2Ban dauerhaft aktiviert werden?" "y"; then
                if systemctl enable "$pkg"; then
                    success "Fail2Ban dauerhaft aktiviert."
                    log_change "SERVICE_ENABLED:$pkg"
                else
                    error "Fehler beim Aktivieren von Fail2Ban."
                fi
            fi
        else
            success "Fail2Ban ist für den Systemstart aktiviert."
        fi
        info "Prüfe Fail2Ban Konfiguration in '$jail_local'..."
        if [[ ! -f "$jail_local" ]]; then
            warn "Keine lokale Konfiguration '$jail_local' gefunden."
            if ask_yes_no "Soll '$jail_local' durch Kopieren von '$jail_conf' erstellt werden?" "y"; then
                if cp "$jail_conf" "$jail_local"; then
                    success "'$jail_local' wurde erstellt."
                    log_change "ADDED_FILE:$jail_local"
                    changes_applied=true
                else
                    error "Fehler beim Kopieren von '$jail_conf'."
                    echo "--- Abschnitt 4f abgeschlossen ---"
                    echo; return 1
                fi
            else
                info "Konfiguration bleibt unverändert."
            fi
        else
            success "Lokale Konfiguration '$jail_local' vorhanden."
        fi
        if [[ -f "$jail_local" ]]; then
            if is_fail2ban_jail_enabled "$ssh_jail_name"; then
                success "Fail2Ban Jail '$ssh_jail_name' ist aktiviert."
            else
                warn "Fail2Ban Jail '$ssh_jail_name' ist nicht aktiviert."
                if ask_yes_no "Soll das Jail '$ssh_jail_name' aktiviert werden?" "y"; then
                    backup_file "$jail_local" || return 1
                    if grep -qE "^\s*\[$ssh_jail_name\]" "$jail_local"; then
                        if grep -A 10 "^\s*\[$ssh_jail_name\]" "$jail_local" | grep -qE '^\s*enabled\s*='; then
                            sed -i "/^\s*\[$ssh_jail_name\]/,/^\s*\[/ s/^\(\s*enabled\s*=\s*\)false/\1true/" "$jail_local"
                            sed -i "/^\s*\[$ssh_jail_name\]/,/^\s*\[/ s/^#\(\s*enabled\s*=\s*\)false/\1true/" "$jail_local"
                        else
                            sed -i "/^\s*\[$ssh_jail_name\]/a enabled = true" "$jail_local"
                        fi
                    else
                        echo "" >> "$jail_local"
                        echo "[$ssh_jail_name]" >> "$jail_local"
                        echo "enabled = true" >> "$jail_local"
                    fi
                    if is_fail2ban_jail_enabled "$ssh_jail_name"; then
                        success "SSH-Jail '$ssh_jail_name' in '$jail_local' aktiviert."
                        log_change "MODIFIED:$jail_local"
                        changes_applied=true
                    else
                        error "SSH-Jail '$ssh_jail_name' konnte nicht aktiviert werden."
                        restore_file "$jail_local"
                    fi
                fi
            fi
        fi

        # Whitelisting: Alle nicht-Loopback IPv4-Adressen hinzufügen
        local server_ips
        server_ips=$(ip -4 addr show | awk '/inet / {print $2}' | cut -d/ -f1 | grep -v "^127\.")
        for ip in $server_ips; do
            if grep -A 5 "^\[sshd\]" "$jail_local" | grep -qi "ignoreip"; then
                if ! grep -A 5 "^\[sshd\]" "$jail_local" | grep -q "$ip"; then
                    sed -i "/^\[sshd\]/,/^\[/{s/^\(ignoreip[[:space:]]*=[[:space:]]*\)/\1$ip /}" "$jail_local"
                    info "Server-IP $ip zur ignoreip Liste in Fail2ban Jail [sshd] hinzugefügt."
                    log_change "MODIFIED_FAIL2BAN_IGNOREIP:$ip"
                fi
            else
                sed -i "/^\[sshd\]/a ignoreip = 127.0.0.1/8 $ip" "$jail_local"
                info "ignoreip = 127.0.0.1/8 $ip in Fail2ban Jail [sshd] hinzugefügt."
                log_change "ADDED_FAIL2BAN_IGNOREIP:$ip"
            fi
        done

        if [[ "$changes_applied" = true && "$service_active" = true ]]; then
            info "Lade Fail2Ban-Konfiguration neu..."
            if fail2ban-client reload; then
                success "Fail2Ban-Konfiguration neu geladen."
            else
                error "Fehler beim Neuladen der Fail2Ban-Konfiguration."
            fi
        fi
    fi
    echo "--- Abschnitt 4f abgeschlossen ---"
    echo
}

summary_report() {
    echo -e "\n${C_BOLD}=== Zusammenfassung der Sicherheitskonfiguration ===${C_RESET}"
    local current_user;
    if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
        current_user="$SUDO_USER";
    else
        current_user=$(whoami);
    fi
    local user_home; user_home=$(eval echo "~$current_user")
    local existing_count=0
    if [[ -d "$user_home/.ssh" ]]; then
        existing_count=$(find "$user_home/.ssh" -type f -name "*.pub" -exec grep -Ei "ssh-ed25519" {} + 2>/dev/null | wc -l)
        if [[ -f "$user_home/.ssh/authorized_keys" ]]; then
            local auth_count
            auth_count=$(grep -Ei "ssh-ed25519" "$user_home/.ssh/authorized_keys" | wc -l)
            existing_count=$((existing_count + auth_count))
        fi
    fi
    if (( existing_count > 0 )); then
        echo -e "${C_GREEN}SSH-Schlüssel:${C_RESET} $existing_count Ed25519-Schlüssel in $user_home/.ssh gefunden."
    else
        echo -e "${C_RED}SSH-Schlüssel:${C_RESET} Keine Ed25519-Schlüssel in $user_home/.ssh gefunden."
    fi
    local allowusers_setting; allowusers_setting=$(get_effective_sshd_config "allowusers")
    if [[ -n "$allowusers_setting" ]]; then
        echo -e "${C_GREEN}AllowUsers:${C_RESET} $allowusers_setting"
    else
        echo -e "${C_YELLOW}AllowUsers:${C_RESET} Keine spezifische Einstellung gefunden."
    fi
    if [[ -f "/etc/apt/apt.conf.d/20auto-upgrades" ]]; then
        echo -e "${C_GREEN}Unattended Upgrades:${C_RESET} Konfiguration vorhanden."
    else
        echo -e "${C_RED}Unattended Upgrades:${C_RESET} Konfigurationsdatei fehlt."
    fi
    if [[ "$MSMTP_CONFIG_CHOICE" == "user" ]]; then
        local msmtp_file; msmtp_file=$(eval echo "~$current_user/.msmtprc")
        if [[ -f "$msmtp_file" ]]; then
            echo -e "${C_GREEN}MSMTP:${C_RESET} Konfiguration in $msmtp_file vorhanden."
        else
            echo -e "${C_RED}MSMTP:${C_RESET} Keine Konfiguration in $msmtp_file gefunden."
        fi
    else
        if [[ -f "/etc/msmtprc" ]]; then
            echo -e "${C_GREEN}MSMTP:${C_RESET} Systemweite Konfiguration vorhanden."
        else
            echo -e "${C_RED}MSMTP:${C_RESET} Keine systemweite Konfiguration gefunden."
        fi
    fi
    if [[ -f "/etc/ssh/sshd_config" ]]; then
        echo -e "${C_GREEN}SSH Hardening:${C_RESET} Optimierte Konfiguration in /etc/ssh/sshd_config vorhanden."
    else
        echo -e "${C_YELLOW}SSH Hardening:${C_RESET} /etc/ssh/sshd_config nicht gefunden."
    fi
    if is_package_installed "sshguard"; then
        if systemctl is-active --quiet sshguard; then
            echo -e "${C_GREEN}SSHGuard:${C_RESET} Aktiv."
        else
            echo -e "${C_YELLOW}SSHGuard:${C_RESET} Installiert, aber nicht aktiv."
        fi
    else
        echo -e "${C_RED}SSHGuard:${C_RESET} Nicht installiert."
    fi
    local journald_setting; journald_setting=$(grep -E "^\s*SystemMaxUse=" /etc/systemd/journald.conf | head -n 1)
    if [[ -n "$journald_setting" ]]; then
        echo -e "${C_GREEN}Journald Log Limit:${C_RESET} $journald_setting"
    else
        echo -e "${C_YELLOW}Journald Log Limit:${C_RESET} Nicht gesetzt."
    fi
    local sysctl_tcp_syncookies; sysctl_tcp_syncookies=$(get_effective_sysctl_config "net.ipv4.tcp_syncookies")
    if [[ "$sysctl_tcp_syncookies" == "1" ]]; then
        echo -e "${C_GREEN}Sysctl (tcp_syncookies):${C_RESET} Aktiv (1)."
    else
        echo -e "${C_RED}Sysctl (tcp_syncookies):${C_RESET} Nicht aktiv (Wert: $sysctl_tcp_syncookies)."
    fi
    if is_sudo_tty_tickets_active; then
        echo -e "${C_GREEN}Sudo tty_tickets:${C_RESET} Aktiv."
    else
        echo -e "${C_YELLOW}Sudo tty_tickets:${C_RESET} Nicht aktiv."
    fi
    if is_package_installed "fail2ban"; then
        if systemctl is-active --quiet fail2ban; then
            echo -e "${C_GREEN}Fail2Ban:${C_RESET} Aktiv."
        else
            echo -e "${C_YELLOW}Fail2Ban:${C_RESET} Installiert, aber nicht aktiv."
        fi
    else
        echo -e "${C_RED}Fail2Ban:${C_RESET} Nicht installiert."
    fi
    echo -e "${C_BOLD}=== Zusammenfassung abgeschlossen ===${C_RESET}\n"
}

uninstall_changes() {
    warn "${C_BOLD}=== Deinstallationsroutine wird gestartet ===${C_RESET}"
    if [[ ! -f "$SCRIPT_LOG_FILE" ]]; then
        error "Log-Datei '$SCRIPT_LOG_FILE' nicht gefunden. Deinstallation nicht möglich."
        return 1
    fi
    if ! ask_yes_no "${C_RED}Alle durch dieses Skript vorgenommene Änderungen rückgängig machen?${C_RESET}" "n"; then
        info "Deinstallation abgebrochen."
        return 0
    fi
    info "Lese Log-Datei '$SCRIPT_LOG_FILE' in umgekehrter Reihenfolge..."
    local IFS_BAK=$IFS; IFS=$'\n'
    local lines=($(tac "$SCRIPT_LOG_FILE" | grep .)); IFS=$IFS_BAK
    local restart_services=() reload_sysctl=false
    for line in "${lines[@]}"; do
        info "Verarbeite: $line"
        local timestamp=$(echo "$line" | cut -d'|' -f1 | sed 's/^ *//;s/ *$//')
        local action_full=$(echo "$line" | cut -d'|' -f2- | sed 's/^ *//;s/ *$//')
        local type=$(echo "$action_full" | cut -d':' -f1)
        local param=$(echo "$action_full" | cut -d':' -f2)
        local extra=$(echo "$action_full" | cut -d':' -f3-)
        case "$type" in
            INSTALLED)
                if is_package_installed "$param"; then
                    warn "Entferne Paket '$param'..."
                    apt remove --purge --auto-remove -y "$param" && success "Paket '$param' entfernt." || error "Fehler beim Entfernen von '$param'."
                else
                    info "Paket '$param' bereits deinstalliert."
                fi
                ;;
            BACKUP_CREATED)
                info "Backup für '$param' erstellt (Info)."
                ;;
            ADDED_FILE)
                if [[ -f "$param" ]]; then
                    warn "Entferne Datei '$param'..."
                    if rm "$param"; then
                        success "Datei '$param' entfernt."
                        case "$param" in
                            *sshd_config*) restart_services+=("$SSH_SERVICE");;
                            *sysctl.d*) reload_sysctl=true;;
                            *sudoers.d*) info "Sudo-Konfigurationsdatei entfernt.";;
                            *fail2ban/jail.local*) restart_services+=("fail2ban");;
                            *apt.conf.d/20auto-upgrades*) info "APT Auto-Upgrade Konfig entfernt.";;
                            *.msmtprc*) info "MSMTP-Konfiguration entfernt.";;
                        esac
                    else
                        error "Fehler beim Entfernen von '$param'."
                    fi
                else
                    info "Datei '$param' existiert nicht."
                fi
                ;;
            MODIFIED)
                info "Stelle '$param' aus Backup wieder her..."
                if restore_file "$param"; then
                    case "$param" in
                        *sshd_config*) restart_services+=("$SSH_SERVICE");;
                        *journald.conf*) restart_services+=("systemd-journald");;
                        *sysctl.conf*) reload_sysctl=true;;
                        *fail2ban*) restart_services+=("fail2ban");;
                        *50unattended-upgrades*) info "Unattended Upgrades Konfig wiederhergestellt.";;
                    esac
                else
                    warn "Konnte '$param' nicht wiederherstellen."
                fi
                ;;
            ADDED_LINE)
                warn "Entfernen von Zeile '$extra' in '$param' wird übersprungen."
                ;;
            SERVICE_RESTARTED|SERVICE_ENABLED)
                info "Dienst '$param' wurde gestartet/aktiviert (Info)."
                ;;
            SYSCTL_APPLIED)
                reload_sysctl=true; info "Sysctl-Werte wurden angewendet (Info)."
                ;;
            SSH_KEY_GENERATED)
                warn "SSH-Schlüssel '$param' wurde generiert. Bitte manuell entfernen, falls gewünscht."
                echo "  rm -i \"$param\" \"${param}.pub\""
                ;;
            *)
                warn "Unbekannter Log-Typ '$type' in: $line"
                ;;
        esac
    done
    if [[ "$reload_sysctl" = true ]]; then
        info "Lade sysctl-Standardeinstellungen neu (sysctl --system)..."
        if sysctl --system > /dev/null; then
            success "sysctl-Einstellungen neu geladen."
        else
            warn "Fehler beim Neuladen der sysctl-Einstellungen."
        fi
    fi
    local unique_services
    unique_services=$(echo "${restart_services[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    if [[ -n "$unique_services" ]]; then
        info "Starte Dienste neu: $unique_services"
        for service in $unique_services; do
            if systemctl list-unit-files | grep -q "^${service}.service"; then
                if systemctl try-restart "$service"; then
                    success "Dienst '$service' neu gestartet."
                else
                    warn "Fehler beim Neustart von '$service'."
                fi
            else
                warn "Dienst '$service' existiert nicht. Überspringe Neustart."
            fi
        done
    fi
    if ask_yes_no "Soll die Log-Datei '$SCRIPT_LOG_FILE' gelöscht werden?" "y"; then
        if rm "$SCRIPT_LOG_FILE"; then
            success "Log-Datei '$SCRIPT_LOG_FILE' entfernt."
        else
            error "Fehler beim Entfernen der Log-Datei '$SCRIPT_LOG_FILE'."
        fi
    fi
    success "${C_BOLD}Deinstallationsroutine abgeschlossen.${C_RESET}"
}

# --- Hauptskriptablauf ---
SCRIPT_APT_UPDATED=false
if [[ $EUID -ne 0 ]]; then
    error "Dieses Skript muss mit Root-Rechten (sudo) ausgeführt werden."
    exit 1
fi
if [[ "$1" == "--uninstall" ]]; then
    uninstall_changes
    exit $?
fi
echo -e "${C_BOLD}Willkommen beim interaktiven Linux Server Security Skript V2.2${C_RESET}"
echo "Dieses Skript prüft Ihre Einstellungen, gibt Empfehlungen und wendet Änderungen nach Bestätigung an."
echo "Backups werden mit der Endung '${BACKUP_SUFFIX}' erstellt und alle Aktionen in '${SCRIPT_LOG_FILE}' protokolliert."
echo "Änderungen können mit 'sudo bash $0 --uninstall' rückgängig gemacht werden."
echo -e "${C_YELLOW}WARNUNG: Führen Sie dieses Skript nur mit einem aktuellen System-Backup aus!${C_RESET}"
echo
if ! ask_yes_no "Möchten Sie mit der Sicherheitsüberprüfung fortfahren?" "y"; then
    info "Skript abgebrochen."
    exit 0
fi
if [[ -f "$SCRIPT_LOG_FILE" ]]; then
    warn "Vorhandene Log-Datei '$SCRIPT_LOG_FILE' wird überschrieben."
fi
> "$SCRIPT_LOG_FILE"
chmod 600 "$SCRIPT_LOG_FILE"
log_change "SCRIPT_STARTED:V2.2:$(date)"
configure_ssh_key_and_users
configure_unattended_upgrades
configure_msmtp
configure_ssh_hardening
configure_sshguard
configure_journald
configure_sysctl
configure_sudo
configure_fail2ban
summary_report
echo
success "${C_BOLD}=== Interaktives Security Skript V2.2 abgeschlossen ===${C_RESET}"
echo "Die Konfiguration ist beendet. Eine Zusammenfassung finden Sie in '${SCRIPT_LOG_FILE}'."
echo
info "Zum Rückgängigmachen: ${C_BOLD}sudo bash $0 --uninstall${C_RESET}"
if grep -q -E ':(SERVICE_RESTARTED|SYSCTL_APPLIED)' "$SCRIPT_LOG_FILE"; then
    warn "Einige Dienste wurden neu gestartet oder Einstellungen sofort angewendet."
    info "Systemneustart empfohlen: ${C_BOLD}sudo reboot${C_RESET}"
fi
exit 0

