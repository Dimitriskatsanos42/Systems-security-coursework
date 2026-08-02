#!/usr/bin/env bash
#
# user_management.sh
# --------------------
# Linux User Management Automation
#
# Αυτοματοποιεί κοινές εργασίες διαχείρισης χρηστών σε Linux:
#   - Δημιουργία/διαγραφή χρηστών (μεμονωμένα ή μαζικά από CSV)
#   - Δημιουργία groups και ανάθεση χρηστών σε αυτά
#   - Ρύθμιση δικαιωμάτων (permissions) σε φακέλους/αρχεία
#   - Χορήγηση/ανάκληση περιορισμένης πρόσβασης sudo (μέσω sudoers.d)
#   - Επιβολή πολιτικής κωδικών (password aging via chage, pwquality)
#   - Έλεγχος (audit) της τρέχουσας κατάστασης χρηστών
#
# Σχεδιάστηκε ρητά για περιβάλλον Linux (Ubuntu/Debian-based· οι εντολές
# useradd/usermod/chage/passwd είναι POSIX-συμβατές αλλά τα paths των
# packages -π.χ. sudoers.d- υποθέτουν Debian/Ubuntu).
#
# ΑΣΦΑΛΕΙΑ: Το script τρέχει προνομιούχες ενέργειες (δημιουργία χρηστών,
# αλλαγή sudoers). Απαιτεί root. Υποστηρίζει --dry-run ώστε να μπορεί
# κανείς να δει τι ΘΑ έκανε το script χωρίς να αλλάξει τίποτα.
#
# Χρήση:
#   sudo ./user_management.sh create-user   --username alice --shell /bin/bash --groups developers
#   sudo ./user_management.sh delete-user   --username alice --remove-home
#   sudo ./user_management.sh create-group  --groupname developers
#   sudo ./user_management.sh grant-sudo    --username alice --commands "/usr/bin/systemctl restart nginx"
#   sudo ./user_management.sh revoke-sudo   --username alice
#   sudo ./user_management.sh set-policy    --username alice --max-days 90 --warn-days 7
#   sudo ./user_management.sh set-perms     --path /srv/webapp --owner alice --group developers --mode 750
#   sudo ./user_management.sh bulk-create   --file config/users.csv
#   sudo ./user_management.sh audit
#   sudo ./user_management.sh --dry-run create-user --username bob
#
set -euo pipefail

# ──────────────────────────────────────────────────────────────
# Σταθερές / Ρυθμίσεις
# ──────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs"
LOG_FILE="${LOG_DIR}/user_management.log"
SUDOERS_DIR="/etc/sudoers.d"
DEFAULT_SHELL="/bin/bash"
DRY_RUN=0

mkdir -p "${LOG_DIR}"

# ──────────────────────────────────────────────────────────────
# Βοηθητικές συναρτήσεις: logging & χρώματα
# ──────────────────────────────────────────────────────────────
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_BLUE='\033[0;34m'
COLOR_RESET='\033[0m'

log() {
    # log <level> <message>
    local level="$1"; shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}"
}

info()  { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*";  log "INFO"  "$*"; }
ok()    { echo -e "${COLOR_GREEN}[ OK ]${COLOR_RESET} $*"; log "OK"    "$*"; }
warn()  { echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"; log "WARN" "$*"; }
error() { echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} $*" >&2; log "ERROR" "$*"; }

# Εκτελεί μια εντολή, ή απλώς την εμφανίζει αν είναι ενεργό το --dry-run.
run() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo -e "${COLOR_YELLOW}[DRY-RUN]${COLOR_RESET} $*"
        log "DRY-RUN" "$*"
    else
        log "EXEC" "$*"
        "$@"
    fi
}

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "Αυτή η ενέργεια απαιτεί δικαιώματα root. Τρέξτε με sudo."
        exit 1
    fi
}

usage() {
    cat <<'EOF'
Linux User Management Automation

Χρήση: user_management.sh [--dry-run] <εντολή> [επιλογές]

Εντολές:
  create-user   --username NAME [--shell PATH] [--groups g1,g2] [--no-home]
  delete-user   --username NAME [--remove-home]
  create-group  --groupname NAME
  add-to-group  --username NAME --groupname NAME
  grant-sudo    --username NAME [--commands "cmd1,cmd2" | --full]
  revoke-sudo   --username NAME
  set-policy    --username NAME [--max-days N] [--min-days N] [--warn-days N]
  set-perms     --path PATH --owner NAME --group NAME --mode OCTAL
  bulk-create   --file CSV_PATH
  audit         [--username NAME]
  help

Γενικές επιλογές:
  --dry-run     Εμφανίζει τις ενέργειες χωρίς να τις εκτελέσει.

Παραδείγματα:
  sudo ./user_management.sh create-user --username alice --groups developers,docker
  sudo ./user_management.sh grant-sudo --username alice --commands "/usr/bin/systemctl restart nginx"
  sudo ./user_management.sh set-policy --username alice --max-days 90 --warn-days 7
  sudo ./user_management.sh bulk-create --file config/users.csv
  sudo ./user_management.sh audit
EOF
}

# ──────────────────────────────────────────────────────────────
# Ανάλυση named arguments (π.χ. --username alice)
# Χρησιμοποιείται από κάθε υπο-εντολή.
# ──────────────────────────────────────────────────────────────
parse_named_args() {
    # Γεμίζει το global associative array ARGS[] από τα υπόλοιπα ορίσματα.
    declare -gA ARGS=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --*)
                local key="${1#--}"
                if [[ $# -ge 2 && "$2" != --* ]]; then
                    ARGS["$key"]="$2"
                    shift 2
                else
                    ARGS["$key"]="true"   # boolean flag, π.χ. --no-home
                    shift 1
                fi
                ;;
            *)
                shift 1
                ;;
        esac
    done
}

user_exists() { id "$1" &>/dev/null; }
group_exists() { getent group "$1" &>/dev/null; }

# ──────────────────────────────────────────────────────────────
# create-user
# ──────────────────────────────────────────────────────────────
cmd_create_user() {
    parse_named_args "$@"
    local username="${ARGS[username]:-}"
    local shell="${ARGS[shell]:-$DEFAULT_SHELL}"
    local groups="${ARGS[groups]:-}"
    local no_home="${ARGS[no-home]:-false}"

    if [[ -z "${username}" ]]; then
        error "Απαιτείται --username"
        exit 1
    fi

    if user_exists "${username}"; then
        warn "Ο χρήστης '${username}' υπάρχει ήδη — παραλείπεται η δημιουργία."
        return 0
    fi

    local useradd_cmd=(useradd -m -s "${shell}")
    [[ "${no_home}" == "true" ]] && useradd_cmd=(useradd -M -s "${shell}")

    if [[ -n "${groups}" ]]; then
        # Δημιουργούμε τα groups αν δεν υπάρχουν, πριν τα αναθέσουμε
        IFS=',' read -ra group_array <<< "${groups}"
        for g in "${group_array[@]}"; do
            if ! group_exists "${g}"; then
                info "Το group '${g}' δεν υπάρχει — δημιουργείται αυτόματα."
                run groupadd "${g}"
            fi
        done
        useradd_cmd+=(-G "${groups}")
    fi

    useradd_cmd+=("${username}")
    run "${useradd_cmd[@]}"

    # Κλείδωμα κωδικού μέχρι να οριστεί ρητά (ασφαλής προεπιλογή: καμία
    # κενή/προβλέψιμη password δεν δημιουργείται αυτόματα).
    run passwd -l "${username}"

    ok "Ο χρήστης '${username}' δημιουργήθηκε (shell=${shell}, groups=${groups:-καμία}). Ο κωδικός είναι κλειδωμένος έως ότου οριστεί."
}

# ──────────────────────────────────────────────────────────────
# delete-user
# ──────────────────────────────────────────────────────────────
cmd_delete_user() {
    parse_named_args "$@"
    local username="${ARGS[username]:-}"
    local remove_home="${ARGS[remove-home]:-false}"

    if [[ -z "${username}" ]]; then
        error "Απαιτείται --username"
        exit 1
    fi
    if ! user_exists "${username}"; then
        warn "Ο χρήστης '${username}' δεν υπάρχει."
        return 0
    fi

    local userdel_cmd=(userdel)
    [[ "${remove_home}" == "true" ]] && userdel_cmd+=(-r)
    userdel_cmd+=("${username}")

    run "${userdel_cmd[@]}"

    # Καθαρισμός τυχόν αρχείου sudoers που αφορούσε αυτόν τον χρήστη
    local sudoers_file="${SUDOERS_DIR}/90-${username}"
    if [[ -f "${sudoers_file}" ]]; then
        run rm -f "${sudoers_file}"
    fi

    ok "Ο χρήστης '${username}' διαγράφηκε."
}

# ──────────────────────────────────────────────────────────────
# create-group / add-to-group
# ──────────────────────────────────────────────────────────────
cmd_create_group() {
    parse_named_args "$@"
    local groupname="${ARGS[groupname]:-}"
    [[ -z "${groupname}" ]] && { error "Απαιτείται --groupname"; exit 1; }

    if group_exists "${groupname}"; then
        warn "Το group '${groupname}' υπάρχει ήδη."
        return 0
    fi
    run groupadd "${groupname}"
    ok "Το group '${groupname}' δημιουργήθηκε."
}

cmd_add_to_group() {
    parse_named_args "$@"
    local username="${ARGS[username]:-}"
    local groupname="${ARGS[groupname]:-}"

    if [[ -z "${username}" || -z "${groupname}" ]]; then
        error "Απαιτούνται --username και --groupname"
        exit 1
    fi
    if ! user_exists "${username}"; then
        error "Ο χρήστης '${username}' δεν υπάρχει."
        exit 1
    fi
    if ! group_exists "${groupname}"; then
        info "Το group '${groupname}' δεν υπάρχει — δημιουργείται."
        run groupadd "${groupname}"
    fi
    run usermod -aG "${groupname}" "${username}"
    ok "Ο χρήστης '${username}' προστέθηκε στο group '${groupname}'."
}

# ──────────────────────────────────────────────────────────────
# grant-sudo / revoke-sudo
#
# Αντί να προσθέτουμε τον χρήστη απευθείας στο group 'sudo' (πλήρη
# δικαιώματα), δημιουργούμε ένα αρχείο στο /etc/sudoers.d/ με ρητά
# περιορισμένες εντολές — αρχή του ελάχιστου προνομίου (least privilege).
# Η χρήση --full παραμένει διαθέσιμη όταν πραγματικά χρειάζεται πλήρες sudo.
# ──────────────────────────────────────────────────────────────
cmd_grant_sudo() {
    parse_named_args "$@"
    local username="${ARGS[username]:-}"
    local commands="${ARGS[commands]:-}"
    local full="${ARGS[full]:-false}"

    if [[ -z "${username}" ]]; then
        error "Απαιτείται --username"
        exit 1
    fi
    if ! user_exists "${username}"; then
        error "Ο χρήστης '${username}' δεν υπάρχει."
        exit 1
    fi

    local sudoers_file="${SUDOERS_DIR}/90-${username}"
    local tmp_file
    tmp_file="$(mktemp)"

    if [[ "${full}" == "true" ]]; then
        echo "${username} ALL=(ALL:ALL) ALL" > "${tmp_file}"
        warn "Χορηγείται ΠΛΗΡΕΣ sudo στον '${username}' — χρησιμοποιήστε το μόνο όταν είναι πραγματικά απαραίτητο."
    elif [[ -n "${commands}" ]]; then
        IFS=',' read -ra cmd_array <<< "${commands}"
        local cmd_list=""
        for c in "${cmd_array[@]}"; do
            cmd_list+="${c}, "
        done
        cmd_list="${cmd_list%, }"
        echo "${username} ALL=(root) NOPASSWD: ${cmd_list}" > "${tmp_file}"
    else
        error "Απαιτείται είτε --commands \"cmd1,cmd2\" είτε --full"
        rm -f "${tmp_file}"
        exit 1
    fi

    # ΚΡΙΣΙΜΟ: κάθε αλλαγή στο sudoers πρέπει να επικυρώνεται με visudo -c
    # πριν εφαρμοστεί — ένα λάθος syntax στο sudoers μπορεί να κλειδώσει
    # την πρόσβαση root σε όλο το σύστημα.
    if command -v visudo &>/dev/null; then
        if ! visudo -c -f "${tmp_file}" &>/dev/null; then
            error "Μη έγκυρο sudoers syntax — η αλλαγή ΔΕΝ εφαρμόστηκε."
            rm -f "${tmp_file}"
            exit 1
        fi
    else
        warn "Το visudo δεν βρέθηκε — παραλείπεται ο έλεγχος syntax (μη ιδανικό)."
    fi

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo -e "${COLOR_YELLOW}[DRY-RUN]${COLOR_RESET} Θα δημιουργούνταν το ${sudoers_file} με περιεχόμενο:"
        cat "${tmp_file}"
        rm -f "${tmp_file}"
    else
        install -m 440 "${tmp_file}" "${sudoers_file}"
        rm -f "${tmp_file}"
        log "EXEC" "grant-sudo -> ${sudoers_file}"
    fi

    ok "Δικαιώματα sudo ρυθμίστηκαν για τον '${username}' (${sudoers_file})."
}

cmd_revoke_sudo() {
    parse_named_args "$@"
    local username="${ARGS[username]:-}"
    [[ -z "${username}" ]] && { error "Απαιτείται --username"; exit 1; }

    local sudoers_file="${SUDOERS_DIR}/90-${username}"
    if [[ -f "${sudoers_file}" ]]; then
        run rm -f "${sudoers_file}"
        ok "Δικαιώματα sudo ανακλήθηκαν για τον '${username}'."
    else
        warn "Δεν βρέθηκε αρχείο sudoers για τον '${username}'."
    fi

    # Αφαίρεση και από το group sudo, αν ήταν μέλος
    if user_exists "${username}" && id -nG "${username}" 2>/dev/null | grep -qw sudo; then
        run gpasswd -d "${username}" sudo
        ok "Ο '${username}' αφαιρέθηκε από το group 'sudo'."
    fi
}

# ──────────────────────────────────────────────────────────────
# set-policy — πολιτική λήξης κωδικού (password aging) μέσω chage
# ──────────────────────────────────────────────────────────────
cmd_set_policy() {
    parse_named_args "$@"
    local username="${ARGS[username]:-}"
    local max_days="${ARGS[max-days]:-90}"
    local min_days="${ARGS[min-days]:-1}"
    local warn_days="${ARGS[warn-days]:-7}"

    if [[ -z "${username}" ]]; then
        error "Απαιτείται --username"
        exit 1
    fi
    if ! user_exists "${username}"; then
        error "Ο χρήστης '${username}' δεν υπάρχει."
        exit 1
    fi

    run chage -M "${max_days}" -m "${min_days}" -W "${warn_days}" "${username}"
    ok "Πολιτική κωδικού για '${username}': max=${max_days}d, min=${min_days}d, warn=${warn_days}d πριν τη λήξη."
}

# ──────────────────────────────────────────────────────────────
# set-perms — δικαιώματα αρχείων/φακέλων
# ──────────────────────────────────────────────────────────────
cmd_set_perms() {
    parse_named_args "$@"
    local path="${ARGS[path]:-}"
    local owner="${ARGS[owner]:-}"
    local group="${ARGS[group]:-}"
    local mode="${ARGS[mode]:-750}"

    if [[ -z "${path}" ]]; then
        error "Απαιτείται --path"
        exit 1
    fi
    if [[ ! -e "${path}" ]]; then
        error "Το path '${path}' δεν υπάρχει."
        exit 1
    fi

    if [[ -n "${owner}" || -n "${group}" ]]; then
        run chown "${owner:-.}:${group:-.}" "${path}"
    fi
    run chmod "${mode}" "${path}"

    ok "Δικαιώματα για '${path}': owner=${owner:-αμετάβλητο}, group=${group:-αμετάβλητο}, mode=${mode}"
}

# ──────────────────────────────────────────────────────────────
# bulk-create — μαζική δημιουργία χρηστών από CSV
# Μορφή CSV: username,shell,groups   (χωρίς κεφαλίδα, ένα header επιτρέπεται)
# ──────────────────────────────────────────────────────────────
cmd_bulk_create() {
    parse_named_args "$@"
    local file="${ARGS[file]:-}"

    if [[ -z "${file}" || ! -f "${file}" ]]; then
        error "Απαιτείται έγκυρο --file (CSV)"
        exit 1
    fi

    local line_number=0
    local created=0
    local skipped=0

    while IFS=',' read -r username shell groups || [[ -n "${username}" ]]; do
        line_number=$((line_number + 1))
        # Παράλειψη κενών γραμμών και της κεφαλίδας (αν η πρώτη στήλη είναι "username")
        [[ -z "${username}" ]] && continue
        if [[ "${username}" == "username" && "${line_number}" -eq 1 ]]; then
            continue
        fi
        # Αφαίρεση πιθανών κενών/carriage returns (CSV από Windows)
        username="$(echo "${username}" | tr -d '[:space:]')"
        shell="$(echo "${shell:-$DEFAULT_SHELL}" | tr -d '[:space:]')"
        groups="$(echo "${groups:-}" | tr -d '[:space:]')"

        info "Γραμμή ${line_number}: δημιουργία χρήστη '${username}'..."
        if user_exists "${username}"; then
            warn "  -> Ο χρήστης '${username}' υπάρχει ήδη, παραλείπεται."
            skipped=$((skipped + 1))
            continue
        fi

        if [[ -n "${groups}" ]]; then
            cmd_create_user --username "${username}" --shell "${shell}" --groups "${groups}"
        else
            cmd_create_user --username "${username}" --shell "${shell}"
        fi
        created=$((created + 1))
    done < "${file}"

    ok "Μαζική δημιουργία ολοκληρώθηκε: ${created} νέοι χρήστες, ${skipped} παραλείφθηκαν (ήδη υπήρχαν)."
}

# ──────────────────────────────────────────────────────────────
# audit — έλεγχος τρέχουσας κατάστασης χρηστών/δικαιωμάτων
# ──────────────────────────────────────────────────────────────
cmd_audit() {
    parse_named_args "$@"
    local target_user="${ARGS[username]:-}"

    if [[ -n "${target_user}" ]]; then
        if ! user_exists "${target_user}"; then
            error "Ο χρήστης '${target_user}' δεν υπάρχει."
            exit 1
        fi
        echo "── Audit για τον χρήστη: ${target_user} ──"
        echo "UID/GID:      $(id "${target_user}")"
        echo "Groups:       $(id -nG "${target_user}")"
        echo "Shell:        $(getent passwd "${target_user}" | cut -d: -f7)"
        echo "Home:         $(getent passwd "${target_user}" | cut -d: -f6)"
        echo "Password aging (chage -l):"
        chage -l "${target_user}" | sed 's/^/  /'
        local sudoers_file="${SUDOERS_DIR}/90-${target_user}"
        if [[ -f "${sudoers_file}" ]]; then
            echo "Sudo (custom): ${sudoers_file}"
            sed 's/^/  /' "${sudoers_file}"
        elif id -nG "${target_user}" 2>/dev/null | grep -qw sudo; then
            echo "Sudo:          Πλήρες (μέλος του group 'sudo')"
        else
            echo "Sudo:          Κανένα"
        fi
        return 0
    fi

    echo "── Χρήστες συστήματος με UID >= 1000 (κανονικοί χρήστες, όχι system accounts) ──"
    printf "%-20s %-8s %-30s %-20s\n" "USERNAME" "UID" "GROUPS" "SUDO"
    while IFS=: read -r username _ uid _ _ home shell; do
        if [[ "${uid}" -ge 1000 && "${username}" != "nobody" ]]; then
            local groups sudo_status
            groups="$(id -nG "${username}" 2>/dev/null | tr ' ' ',')"
            if [[ -f "${SUDOERS_DIR}/90-${username}" ]]; then
                sudo_status="custom"
            elif echo "${groups}" | grep -qw sudo; then
                sudo_status="full"
            else
                sudo_status="none"
            fi
            printf "%-20s %-8s %-30s %-20s\n" "${username}" "${uid}" "${groups}" "${sudo_status}"
        fi
    done < /etc/passwd
}

# ──────────────────────────────────────────────────────────────
# Main — δρομολόγηση εντολών
# ──────────────────────────────────────────────────────────────
main() {
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    # Έλεγχος για global flags (--dry-run) πριν την υπο-εντολή
    local args=()
    for arg in "$@"; do
        if [[ "${arg}" == "--dry-run" ]]; then
            DRY_RUN=1
        else
            args+=("${arg}")
        fi
    done
    set -- "${args[@]}"

    local command="${1:-help}"
    shift || true

    case "${command}" in
        create-user)  require_root; cmd_create_user "$@" ;;
        delete-user)  require_root; cmd_delete_user "$@" ;;
        create-group) require_root; cmd_create_group "$@" ;;
        add-to-group) require_root; cmd_add_to_group "$@" ;;
        grant-sudo)   require_root; cmd_grant_sudo "$@" ;;
        revoke-sudo)  require_root; cmd_revoke_sudo "$@" ;;
        set-policy)   require_root; cmd_set_policy "$@" ;;
        set-perms)    require_root; cmd_set_perms "$@" ;;
        bulk-create)  require_root; cmd_bulk_create "$@" ;;
        audit)        cmd_audit "$@" ;;   # read-only, δεν απαιτεί root
        help|--help|-h) usage ;;
        *)
            error "Άγνωστη εντολή: ${command}"
            usage
            exit 1
            ;;
    esac
}

main "$@"
