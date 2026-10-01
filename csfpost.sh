#!/bin/bash
# Path: /etc/csf/csfpost.sh

# ---- IPv4 ----
iptables -N PORT_SCAN_TRAP4 2>/dev/null
iptables -F PORT_SCAN_TRAP4
iptables -A PORT_SCAN_TRAP4 -m recent --set --name BAD_IP4 --rsource -j DROP

# Hapus SEMUA kemunculan rule lama (hindari tumpukan saat csf -r berulang),
# lalu tambahkan tepat satu.
while iptables -D LOCALINPUT -m state --state NEW -j PORT_SCAN_TRAP4 2>/dev/null; do :; done
iptables -A LOCALINPUT -m state --state NEW -j PORT_SCAN_TRAP4

# ---- IPv6 (jika aktif) ----
if [ -f /proc/net/if_inet6 ]; then
    ip6tables -N PORT_SCAN_TRAP6 2>/dev/null
    ip6tables -F PORT_SCAN_TRAP6
    ip6tables -A PORT_SCAN_TRAP6 -m recent --set --name BAD_IP6 --rsource -j DROP

    while ip6tables -D LOCALINPUT -m state --state NEW -j PORT_SCAN_TRAP6 2>/dev/null; do :; done
    ip6tables -A LOCALINPUT -m state --state NEW -j PORT_SCAN_TRAP6
fi
