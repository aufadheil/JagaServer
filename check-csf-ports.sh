#!/bin/bash
# Path: /usr/local/bin/check-csf-ports.sh

CSF_CONF="/etc/csf/csf.conf"
WARN=0

echo "=================================================="
echo "      AUDIT PORT LISTENING VS CSF FIREWALL        "
echo "=================================================="

# Port TCP & UDP aktif di sistem (IPv4+IPv6). CATATAN: pakai `grep -oP`
# (GNU grep) — `rgrep` TIDAK ada di Debian.
LISTEN_TCP=$(ss -tulpn46 2>/dev/null | awk 'NR>1 {print $5}' \
  | grep -oP ':\K[0-9]+$' | sort -n -u | paste -sd, -)
LISTEN_UDP=$(ss -tulpn46 2>/dev/null | awk 'NR>1 && $1 ~ /udp/ {print $5}' \
  | grep -oP ':\K[0-9]+$' | sort -n -u | paste -sd, -)

# Konfigurasi CSF
CSF_TCP_IN=$(grep -E "^TCP_IN =" "$CSF_CONF" 2>/dev/null | cut -d'"' -f2)
CSF_UDP_IN=$(grep -E "^UDP_IN =" "$CSF_CONF" 2>/dev/null | cut -d'"' -f2)
CSF_TCP6_IN=$(grep -E "^TCP6_IN =" "$CSF_CONF" 2>/dev/null | cut -d'"' -f2)
CSF_UDP6_IN=$(grep -E "^UDP6_IN =" "$CSF_CONF" 2>/dev/null | cut -d'"' -f2)

echo "[+] Port TCP Listening di OS : ${LISTEN_TCP:-Tidak Ada}"
echo "[+] CSF TCP_IN (IPv4)        : ${CSF_TCP_IN:-Kosong}"
echo "[+] CSF TCP6_IN (IPv6)       : ${CSF_TCP6_IN:-Kosong}"
echo "--------------------------------------------------"
echo "[+] Port UDP Listening di OS : ${LISTEN_UDP:-Tidak Ada}"
echo "[+] CSF UDP_IN (IPv4)        : ${CSF_UDP_IN:-Kosong}"
echo "[+] CSF UDP6_IN (IPv6)       : ${CSF_UDP6_IN:-Kosong}"
echo "=================================================="

# Bandingkan: port yang LISTENING tapi TIDAK ada di CSF *_IN -> kemungkinan terblokir.
# (Gabungkan TCP_IN dan TCP6_IN sebagai daftar port yang diizinkan.)
allowed_has() {
    # $1 = port, $2 = daftar CSF (mis. "22022,80,443")
    local p="$1" list=",$2,"
    [[ "$list" == *",$p,"* ]] && return 0
    # dukung rentang "10000:10500"
    local rng
    for rng in $(tr ',' ' ' <<<"$2"); do
        if [[ "$rng" == *:* ]]; then
            local lo="${rng%%:*}" hi="${rng##*:}"
            [ "$p" -ge "$lo" ] 2>/dev/null && [ "$p" -le "$hi" ] 2>/dev/null && return 0
        fi
    done
    return 1
}

echo
echo "== Perbandingan (port listening vs CSF) =="
ALLOWED_TCP="${CSF_TCP_IN},${CSF_TCP6_IN}"
ALLOWED_UDP="${CSF_UDP_IN},${CSF_UDP6_IN}"

for p in $(tr ',' ' ' <<<"$LISTEN_TCP"); do
    if ! allowed_has "$p" "$ALLOWED_TCP"; then
        echo "[WARN] TCP port $p listening tapi TIDAK terdaftar di TCP_IN/TCP6_IN (bisa terblokir)."
        WARN=1
    fi
done
for p in $(tr ',' ' ' <<<"$LISTEN_UDP"); do
    if ! allowed_has "$p" "$ALLOWED_UDP"; then
        echo "[WARN] UDP port $p listening tapi TIDAK terdaftar di UDP_IN/UDP6_IN (bisa terblokir)."
        WARN=1
    fi
done
[ "$WARN" -eq 0 ] && echo "[OK] Semua port listening sudah terdaftar di CSF."

# Peringatan Drop Logging (variabel Aetherinox CSF)
echo "--------------------------------------------------"
DROP_LOGGING=$(grep -E "^DROP_LOGGING =" "$CSF_CONF" 2>/dev/null | cut -d'"' -f2)
DROP_NOLOG=$(grep -E "^DROP_NOLOG =" "$CSF_CONF" 2>/dev/null | cut -d'"' -f2)
if [ "$DROP_LOGGING" != "0" ] || [ "$DROP_NOLOG" != "0:65535" ]; then
    echo "[WARNING] Set DROP_LOGGING=\"0\" & DROP_NOLOG=\"0:65535\" agar vCPU hemat (anti logging storm)."
else
    echo "[OK] Logging drop dimatikan total (vCPU aman dari logging storm)."
fi

exit "$WARN"
