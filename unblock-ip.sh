#!/bin/bash
# Path: /usr/local/bin/unblock-ip.sh

if [ -z "$1" ]; then
    echo "Penggunaan: sudo unblock-ip <ALAMAT_IP_IPv4_atau_IPv6>"
    exit 1
fi

TARGET_IP="$1"

echo "Membebaskan IP: $TARGET_IP ..."

# 1. Unblock via CSF (Otomatis menangani IPv4 & IPv6)
csf -dr "$TARGET_IP" >/dev/null 2>&1
csf -ar "$TARGET_IP" >/dev/null 2>&1

# 2. Hapus dari Memory Tracker Kernel
if [[ "$TARGET_IP" =~ : ]]; then
    # IPv6
    [ -f /proc/net/xt_recent/BAD_IP6 ] && echo "-$TARGET_IP" > /proc/net/xt_recent/BAD_IP6 2>/dev/null
else
    # IPv4
    [ -f /proc/net/xt_recent/BAD_IP4 ] && echo "-$TARGET_IP" > /proc/net/xt_recent/BAD_IP4 2>/dev/null
fi

# 3. Reload CSF agar Rule Bersih Total
csf -r >/dev/null 2>&1

echo "Berhasil! IP $TARGET_IP telah di-unblock dari CSF dan memori kernel."
