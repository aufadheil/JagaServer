#!/bin/bash
# Path: /usr/local/bin/port-trapper.sh

# ================= KONFIGURASI =================
MAX_RETRY=1                    # Batas percobaan port tidak aktif
BLOCK_TIME=172800              # Durasi pemblokiran dalam DETIK
                               # 86400=24 jam | 3600=1 jam | 0=Permanen (csf -d)
DENY_FILE="/etc/csf/csf.deny"
LOCKFILE="/tmp/port_trapper.lock"
# ===============================================

if [ -f "$LOCKFILE" ]; then exit 0; fi
touch "$LOCKFILE"
trap 'rm -f "$LOCKFILE"' EXIT

block_ip() {
    local ip="$1"
    local proto="$2"
    local target_info="$3"

    local reason="Auto-trap: Hit non-existent ports >= ${MAX_RETRY}x (${proto} - ${target_info})"

    # Cek apakah IP sudah terdaftar di csf.deny agar tidak terduplikasi
    if ! grep -qF "$ip" "$DENY_FILE" 2>/dev/null; then
        if [ "$BLOCK_TIME" -gt 0 ]; then
            csf -td "$ip" "$BLOCK_TIME" "$reason" >/dev/null 2>&1
        else
            csf -d "$ip" "$reason" >/dev/null 2>&1
        fi
    fi
}

# 1. Cek IPv4 dari Kernel Recent Tracker
if [ -f /proc/net/xt_recent/BAD_IP4 ]; then
    awk -v limit="$MAX_RETRY" '$4 >= limit {print $1}' /proc/net/xt_recent/BAD_IP4 2>/dev/null \
        | cut -d'=' -f2 | while read -r ip; do
        if [ -n "$ip" ]; then
            block_ip "$ip" "IPv4" "unauthorized port scan"
            echo "-$ip" > /proc/net/xt_recent/BAD_IP4
        fi
    done
fi

# 2. Cek IPv6 dari Kernel Recent Tracker
if [ -f /proc/net/if_inet6 ] && [ -f /proc/net/xt_recent/BAD_IP6 ]; then
    awk -v limit="$MAX_RETRY" '$4 >= limit {print $1}' /proc/net/xt_recent/BAD_IP6 2>/dev/null \
        | cut -d'=' -f2 | while read -r ip; do
        if [ -n "$ip" ]; then
            block_ip "$ip" "IPv6" "unauthorized port scan"
            echo "-$ip" > /proc/net/xt_recent/BAD_IP6
        fi
    done
fi
