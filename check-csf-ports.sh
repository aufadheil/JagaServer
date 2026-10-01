#!/bin/bash
# Path: /usr/local/bin/check-csf-ports.sh

CSF_CONF="/etc/csf/csf.conf"

echo "=================================================="
echo "      AUDIT PORT LISTENING VS CSF FIREWALL        "
echo "=================================================="

# Ambil port TCP & UDP aktif di sistem
LISTEN_TCP=$(ss -tulpn46 | awk 'NR>1 {print $5}' | rgrep -oP ':\K[0-9]+$' | sort -n -u | xargs | tr ' ' ',')
LISTEN_UDP=$(ss -tulpn46 | awk 'NR>1 && $1 ~ /udp/ {print $5}' | rgrep -oP ':\K[0-9]+$' | sort -n -u | xargs | tr ' ' ',')

# Ambil konfigurasi CSF
CSF_TCP_IN=$(grep -E "^TCP_IN =" "$CSF_CONF" | cut -d'"' -f2)
CSF_UDP_IN=$(grep -E "^UDP_IN =" "$CSF_CONF" | cut -d'"' -f2)
CSF_TCP6_IN=$(grep -E "^TCP6_IN =" "$CSF_CONF" | cut -d'"' -f2)
CSF_UDP6_IN=$(grep -E "^UDP6_IN =" "$CSF_CONF" | cut -d'"' -f2)

echo "[+] Port TCP Listening di OS : ${LISTEN_TCP:-Tidak Ada}"
echo "[+] CSF TCP_IN (IPv4)        : ${CSF_TCP_IN:-Kosong}"
echo "[+] CSF TCP6_IN (IPv6)       : ${CSF_TCP6_IN:-Kosong}"
echo "--------------------------------------------------"
echo "[+] Port UDP Listening di OS : ${LISTEN_UDP:-Tidak Ada}"
echo "[+] CSF UDP_IN (IPv4)        : ${CSF_UDP_IN:-Kosong}"
echo "[+] CSF UDP6_IN (IPv6)       : ${CSF_UDP6_IN:-Kosong}"
echo "=================================================="

# Peringatan Drop Logging (Aetherinox CSF Variable)
DROP_LOGGING=$(grep -E "^DROP_LOGGING =" "$CSF_CONF" | cut -d'"' -f2)
DROP_NOLOG=$(grep -E "^DROP_NOLOG =" "$CSF_CONF" | cut -d'"' -f2)

if [ "$DROP_LOGGING" != "0" ] || [ "$DROP_NOLOG" != "0:65535" ]; then
    echo "[WARNING] Pastikan DROP_LOGGING=\"0\" dan DROP_NOLOG=\"0:65535\" di csf.conf agar vCPU hemat!"
else
    echo "[OK] Logging drop dimatikan total (vCPU Aman dari Logging Storm)."
fi
