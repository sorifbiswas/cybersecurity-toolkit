
#!/usr/bin/env bash
#
# Cybersecurity Toolkit
# Tool: System Information
#
# Shows basic details about the current system: user, OS, kernel,
# hardware resources and uptime.
#
# Usage:
#   ./system_info.sh            basic info
#   ./system_info.sh --all      also show logged-in users and top processes
#   ./system_info.sh --help

set -uo pipefail

SHOW_ALL=0

usage() {
    sed -n '3,12p' "$0" | sed 's/^# \{0,1\}//'
}

section() {
    echo
    echo "--- $1 ---"
}

have() { command -v "$1" >/dev/null 2>&1; }

for arg in "$@"; do
    case "$arg" in
        --all)     SHOW_ALL=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; usage; exit 1 ;;
    esac
done

echo "================================"
echo "       SYSTEM INFORMATION"
echo "================================"

section "User and Host"
echo "Username : $(whoami)"
echo "Hostname : $(hostname)"
echo "Shell    : ${SHELL:-unknown}"
if [ "$(id -u)" -eq 0 ]; then
    echo "Privilege: running as root"
fi

section "Operating System"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "OS       : ${PRETTY_NAME:-unknown}"
else
    echo "OS       : $(uname -s)"
fi
echo "Kernel   : $(uname -r)"
echo "Arch     : $(uname -m)"

section "Time and Uptime"
echo "Date     : $(date '+%Y-%m-%d %H:%M:%S %Z')"
if have uptime; then
    echo "Uptime   : $(uptime -p 2>/dev/null || uptime)"
fi

section "CPU"
if [ -r /proc/cpuinfo ]; then
    model=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs)
    echo "Model    : ${model:-unknown}"
fi
if have nproc; then
    echo "Cores    : $(nproc)"
fi
if [ -r /proc/loadavg ]; then
    echo "Load avg : $(cut -d' ' -f1-3 /proc/loadavg)"
fi

section "Memory"
if have free; then
    free -h | awk 'NR==1 || /^Mem:|^Swap:/'
else
    echo "'free' command not found, skipping"
fi

section "Disk Usage"
if have df; then
    df -h --output=source,size,used,avail,pcent,target -x tmpfs -x devtmpfs \
        2>/dev/null || df -h
fi

if [ "$SHOW_ALL" -eq 1 ]; then
    section "Logged-in Users"
    if have who; then
        who || true
    else
        echo "'who' command not found, skipping"
    fi

    section "Top 5 Processes by Memory"
    if have ps; then
        ps -eo pid,user,%mem,%cpu,comm --sort=-%mem | head -n 6
    else
        echo "'ps' command not found, skipping"
    fi
fi

echo
echo "================================"
