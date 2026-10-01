#!/bin/bash
# Path: /usr/local/bin/unblock-ip.sh

if [ -z "$1" ]; then
    echo "Penggunaan: sudo unblock-ip <ALAMAT_IP_IPv4_atau_IPv6>"
    exit 1
fi

TARGET_IP="$1"
echo "Membebaskan IP: $TARGET_IP ..."

# 1. Unblock via CSF (menangani Temporary & Permanent Deny)
csf -dr "$TARGET_IP" >/dev/null 2>&1
csf -tr "$TARGET_IP" >/dev/null 2>&1

# 2. Hapus dari Memory Tracker Kernel
if [[ "$TARGET_IP" == *:* ]]; then
    [ -f /proc/net/xt_recent/BAD_IP6 ] && echo "-$TARGET_IP" > /proc/net/xt_recent/BAD_IP6 2>/dev/null
else
    [ -f /proc/net/xt_recent/BAD_IP4 ] && echo "-$TARGET_IP" > /proc/net/xt_recent/BAD_IP4 2>/dev/null
fi

# 3. Reload CSF agar rule bersih total (relatif berat; tidak wajib tiap kali)
csf -r >/dev/null 2>&1

echo "Berhasil! IP $TARGET_IP telah di-unblock dari CSF dan memori kernel."
