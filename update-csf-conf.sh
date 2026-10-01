#!/bin/bash
# Path: /usr/local/bin/update-csf-conf.sh

CONF_FILE="/etc/csf/csf.conf"
BACKUP_FILE="/etc/csf/csf.conf.bak.$(date +%F_%H%M%S)"

# Pastikan dijalankan sebagai root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Skrip ini harus dijalankan dengan sudo / root!"
    exit 1
fi

if [ ! -f "$CONF_FILE" ]; then
    echo "[ERROR] File $CONF_FILE tidak ditemukan!"
    exit 1
fi

# 1. Buat Backup File Asli
cp "$CONF_FILE" "$BACKUP_FILE"
echo "[+] Backup berhasil dibuat di: $BACKUP_FILE"

# Daftar key dan value baru yang ingin diterapkan
declare -A CONFIGS=(
    ["TESTING"]="0"
    ["DENY_TEMP_IP_LIMIT"]="0"
    ["DROP_LOGGING"]="0"
    ["DROP_NOLOG"]="0:65535"
    ["PS_INTERVAL"]="0"
    ["PS_LIMIT"]="0"
    ["PS_EMAIL_ALERT"]="0"
    ["LOGFLOOD_ALERT"]="0"
    ["LF_TRIGGER"]="3"
    ["LF_TRIGGER_PERM"]="1"
    ["LF_SSHD"]="3"
    ["LF_SSHD_PERM"]="1"
)

echo "[+] Memproses pembaruan konfigurasi di $CONF_FILE ..."

for KEY in "${!CONFIGS[@]}"; do
    NEW_VAL="${CONFIGS[$KEY]}"
    
    # Cek apakah variabel sudah ada dan belum di-comment
    if grep -qE "^[[:space:]]*${KEY}[[:space:]]*=" "$CONF_FILE"; then
        # 1. Comment baris asli yang cocok
        # 2. Sisipkan baris baru tepat di bawahnya
        sed -i -E "s/^[[:space:]]*(${KEY}[[:space:]]*=.*)/# \1\n${KEY} = \"${NEW_VAL}\"/" "$CONF_FILE"
        echo "  [UPDATE] ${KEY} -> Diberikan comment pada variabel asli & di-set ke \"${NEW_VAL}\""
    else
        # Jika kunci tidak ditemukan sama sekali di file, tambahkan ke paling bawah
        echo "${KEY} = \"${NEW_VAL}\"" >> "$CONF_FILE"
        echo "  [ADDED] ${KEY} -> Ditambahkan baru dengan nilai \"${NEW_VAL}\""
    fi
done

echo "=================================================="
echo "[SUCCESS] Konfigurasi csf.conf berhasil diperbarui!"
echo "Menjalankan reload CSF..."
echo "=================================================="

# Reload CSF agar konfigurasi baru aktif
csf -r
