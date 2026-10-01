#!/bin/bash
# Path: /etc/csf/csfpost.sh

# IPv4 Setup
iptables -N PORT_SCAN_TRAP4 2>/dev/null
iptables -F PORT_SCAN_TRAP4
iptables -A PORT_SCAN_TRAP4 -m recent --set --name BAD_IP4 --rsource -j DROP
iptables -D INPUT -m state --state NEW -j PORT_SCAN_TRAP4 2>/dev/null
iptables -A INPUT -m state --state NEW -j PORT_SCAN_TRAP4

# IPv6 Setup (jika IPv6 aktif di sistem)
if [ -f /proc/net/if_inet6 ]; then
    ip6tables -N PORT_SCAN_TRAP6 2>/dev/null
    ip6tables -F PORT_SCAN_TRAP6
    ip6tables -A PORT_SCAN_TRAP6 -m recent --set --name BAD_IP6 --rsource -j DROP
    ip6tables -D INPUT -m state --state NEW -j PORT_SCAN_TRAP6 2>/dev/null
    ip6tables -A INPUT -m state --state NEW -j PORT_SCAN_TRAP6
fi
