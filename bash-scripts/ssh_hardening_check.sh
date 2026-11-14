#!/usr/bin/env bash
#
# Cybersecurity Toolkit
# Tool: SSH Hardening Check
#
# Audits an OpenSSH server configuration and flags risky settings.
# Read-only: it never changes any file or setting.
#
# Usage:
#   ./ssh_hardening_check.sh                  check this machine (use sudo for
#                                             the most accurate result)
#   ./ssh_hardening_check.sh --file PATH      check a specific sshd_config file
#   ./ssh_hardening_check.sh --help
#
# Exit codes: 0 = no failures, 1 = at least one FAIL, 2 = error.

set -uo pipefail

if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "Error: bash 4 or newer is required." >&2
    exit 2
fi

CONFIG_FILE=""
SSH_DIR="/etc/ssh"
declare -A CFG=()
PASS=0; WARN=0; FAIL=0

usage() { sed -n '3,15p' "$0" | sed 's/^# \{0,1\}//'; }
have()  { command -v "$1" >/dev/null 2>&1; }

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    printf '%s' "${s%"${s##*[![:space:]]}"}"
}

# Read config lines from stdin. In sshd the FIRST value of a keyword wins,
# and settings inside "Match" blocks only apply to some connections, so we
# stop reading a file at its first Match line.
parse_lines() {
    local line key val in_match=0
    while IFS= read -r line || [ -n "$line" ]; do
        line=$(trim "${line%%#*}")
        [ -z "$line" ] && continue
        key="${line%%[[:space:]]*}"
        val=$(trim "${line#"$key"}")
        key="${key,,}"
        [ "$key" = "match" ] && in_match=1
        [ "$in_match" -eq 1 ] && continue
        if [ "$key" = "include" ]; then
            local pattern f
            for pattern in $val; do
                [[ "$pattern" = /* ]] || pattern="$SSH_DIR/$pattern"
                for f in $pattern; do
                    [ -f "$f" ] && [ -r "$f" ] && parse_lines < "$f"
                done
            done
            continue
        fi
        [ -z "${CFG[$key]+x}" ] && CFG[$key]="$val"
    done
}

get() { local v="${CFG[$1]:-}"; printf '%s' "${v,,}"; }
getval() { local v="${CFG[$1]:-}"; printf '%s' "${v:-$2}"; }

pass() { PASS=$((PASS+1)); printf '[PASS] %-24s %s\n' "$1" "$2"; }
warn() { WARN=$((WARN+1)); printf '[WARN] %-24s %s\n' "$1" "$2"; }
fail() { FAIL=$((FAIL+1)); printf '[FAIL] %-24s %s\n' "$1" "$2"; }
info() { printf '[INFO] %-24s %s\n' "$1" "$2"; }

is_number() { [[ "$1" =~ ^[0-9]+$ ]]; }

# ---------- argument parsing ----------
while [ $# -gt 0 ]; do
    case "$1" in
        --file)
            [ $# -ge 2 ] || { echo "Error: --file needs a path." >&2; exit 2; }
            CONFIG_FILE="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
    shift
done

echo "================================"
echo "      SSH HARDENING CHECK"
echo "================================"

# ---------- load configuration ----------
if [ -n "$CONFIG_FILE" ]; then
    [ -r "$CONFIG_FILE" ] || { echo "Error: cannot read $CONFIG_FILE" >&2; exit 2; }
    SSH_DIR=$(dirname "$CONFIG_FILE")
    echo "Source : file $CONFIG_FILE"
    parse_lines < "$CONFIG_FILE"
elif [ "$(id -u)" -eq 0 ] && have sshd && sshd -T >/dev/null 2>&1; then
    echo "Source : effective config (sshd -T)"
    parse_lines < <(sshd -T 2>/dev/null)
elif [ -r "$SSH_DIR/sshd_config" ]; then
    echo "Source : file $SSH_DIR/sshd_config"
    echo "Note   : run with sudo for the effective config (sshd -T)."
    parse_lines < "$SSH_DIR/sshd_config"
else
    echo "Error: no sshd_config found. Is OpenSSH server installed?" >&2
    echo "       Use --file PATH to check a specific file." >&2
    exit 2
fi
echo

# ---------- checks (defaults are OpenSSH defaults when unset) ----------
v=$(get permitrootlogin); v=${v:-prohibit-password}
case "$v" in
    yes)  fail "PermitRootLogin" "root can log in with a password. Set to 'no'." ;;
    no)   pass "PermitRootLogin" "root login disabled" ;;
    *)    pass "PermitRootLogin" "'$v' (root only with keys). 'no' is stricter." ;;
esac

v=$(get passwordauthentication); v=${v:-yes}
if [ "$v" = "yes" ]; then
    warn "PasswordAuthentication" "passwords allowed. Prefer keys, then set to 'no'."
else
    pass "PasswordAuthentication" "password login disabled"
fi

v=$(get permitemptypasswords); v=${v:-no}
if [ "$v" = "yes" ]; then
    fail "PermitEmptyPasswords" "accounts with empty passwords can log in."
else
    pass "PermitEmptyPasswords" "empty passwords not allowed"
fi

v=$(get pubkeyauthentication); v=${v:-yes}
if [ "$v" = "no" ]; then
    warn "PubkeyAuthentication" "key login is off. Keys are safer than passwords."
else
    pass "PubkeyAuthentication" "key login enabled"
fi

v=$(get x11forwarding); v=${v:-no}
if [ "$v" = "yes" ]; then
    warn "X11Forwarding" "enabled. Set to 'no' unless you need GUI forwarding."
else
    pass "X11Forwarding" "disabled"
fi

v=$(get permituserenvironment); v=${v:-no}
if [ "$v" = "yes" ]; then
    warn "PermitUserEnvironment" "users can set environment variables. Set to 'no'."
else
    pass "PermitUserEnvironment" "disabled"
fi

v=$(getval maxauthtries 6)
if is_number "$v" && [ "$v" -gt 4 ]; then
    warn "MaxAuthTries" "$v attempts per connection. Consider 3 or 4."
else
    pass "MaxAuthTries" "$v"
fi

v=$(getval logingracetime 120)
if is_number "$v"; then
    if [ "$v" -eq 0 ]; then
        warn "LoginGraceTime" "0 = no time limit for login."
    elif [ "$v" -gt 60 ]; then
        warn "LoginGraceTime" "${v}s is long. Consider 30 to 60 seconds."
    else
        pass "LoginGraceTime" "${v}s"
    fi
else
    info "LoginGraceTime" "$v (time format, check manually)"
fi

v=$(getval clientaliveinterval 0)
if [ "$v" = "0" ]; then
    info "ClientAliveInterval" "0: idle sessions are never checked. Consider 300."
else
    pass "ClientAliveInterval" "$v"
fi

if [ -z "${CFG[allowusers]:-}" ] && [ -z "${CFG[allowgroups]:-}" ]; then
    info "AllowUsers/AllowGroups" "not set: any valid account may log in. Restrict if possible."
else
    pass "AllowUsers/AllowGroups" "login restricted to listed users/groups"
fi

v=$(getval port 22)
if [ "$v" = "22" ]; then
    info "Port" "22 (default). Changing it only reduces log noise, it is not real security."
else
    info "Port" "$v"
fi

# ---------- summary ----------
echo
echo "--------------------------------"
echo "Passed: $PASS   Warnings: $WARN   Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo "[-] Fix the FAIL items first."
elif [ "$WARN" -gt 0 ]; then
    echo "[*] No critical issues, but review the warnings."
else
    echo "[+] Looks good."
fi
echo "Tip: after editing sshd_config, run 'sudo sshd -t' to test it, then reload SSH."
echo "     Keep one session open while testing so you do not lock yourself out."
[ "$FAIL" -gt 0 ] && exit 1
exit 0
