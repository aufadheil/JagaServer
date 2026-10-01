
# AutoBlock Penyerang IP (Khusus CSF Aetherinox Fork)

Berikut adalah kumpulan script Bash yang efisien, hemat vCPU, dan mendukung dual-stack (**IPv4 & IPv6**).

Rangkaian script ini dirancang khusus agar **tidak memicu *logging storm*** saat server diserang *port scan* acak, serta telah disesuaikan penuh dengan variabel konfigurasi milik repositori **[Aetherinox/csf-firewall](https://github.com/Aetherinox/csf-firewall)**. Pemindaian eksekusi berkala ditangani secara modern menggunakan **Systemd Timer** (pengganti Cron).

---

### 0. Konfigurasi Wajib CSF (`/etc/csf/csf.conf`)

Untuk mencegah eth0 menyala saat persiapan, ada baiknya kita matikan dulu. Ini langkah preventif apabila ternyata sebelumnya IP sudah "bocor" (**Wajib `sudo**`):

```bash
sudo ip link set eth0 down

```

Untuk menyalakannya kembali nanti setelah konfigurasi selesai (**Wajib `sudo**`):

```bash
sudo ip link set eth0 up

```

Sebelum memasang script, buka `/etc/csf/csf.conf` (**Wajib `sudo**`):

```bash
sudo nano /etc/csf/csf.conf

```

Pastikan variabel berikut telah diset di dalam file tersebut untuk mencegah *vCPU storm*:

```ini

# 1. Matikan mode testing & atur blokir permanen
TESTING = "0"
DENY_TEMP_IP_LIMIT = "0"

# 2. Hemat vCPU & Serahkan port scan sepenuhnya ke skrip port-trapper.sh
DROP_LOGGING = "0"
DROP_NOLOG = "0:65535"   # CRITICAL: Wajib agar paket jatuh ke rule csfpost.sh
PS_INTERVAL = "0"        # Matikan port scan bawaan CSF (pake skrip kita saja)
PS_LIMIT = "0"
PS_EMAIL_ALERT = "0"
LOGFLOOD_ALERT = "0"

# 3. Tetap AKTIFKAN pengaman Gagal Login (Brute Force SSH/FTP dll)
LF_TRIGGER = "3"
LF_TRIGGER_PERM = "1"
LF_SSHD = "3"
LF_SSHD_PERM = "1"

```

---

### 1. Script Penangkap & Auto-Block IP (`/usr/local/bin/port-trapper.sh`)

Buat file script penangkap dengan akses root (**Wajib `sudo**`):

```bash
sudo nano /usr/local/bin/port-trapper.sh

```

Script ini membaca penangkapan *port scan* dari modul kernel `xt_recent` (IPv4 & IPv6), lalu mendaftarkannya ke `/etc/csf/csf.deny` dengan menyertakan alasan detail port yang di-scan jika mencoba mengakses port tertutup melebihi batas yang ditentukan.

```bash
#!/bin/bash
# Path: /usr/local/bin/port-trapper.sh

# ================= KONFIGURASI =================
MAX_RETRY=1                  # Batas percobaan port tidak aktif
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
    
    local reason="Auto-blocked: Hit non-existent ports >= ${MAX_RETRY}x (${proto}"
    if [ -n "$target_info" ]; then
        reason="${reason} - ${target_info})"
    else
        reason="${reason} - random/closed ports)"
    fi

    # Cek apakah IP sudah ada di csf.deny agar tidak terduplikasi
    if ! grep -qF "$ip" "$DENY_FILE"; then
        csf -d "$ip" "$reason" >/dev/null 2>&1
    fi
}

# 1. Cek IPv4 dari Kernel Recent Tracker
if [ -f /proc/net/xt_recent/BAD_IP4 ]; then
    awk -v limit="$MAX_RETRY" '$4 >= limit {print $1}' /proc/net/xt_recent/BAD_IP4 2>/dev/null | cut -d'=' -f2 | while read -r ip; do
        if [ -n "$ip" ]; then
            block_ip "$ip" "IPv4" "unauthorized port scan"
            echo "-$ip" > /proc/net/xt_recent/BAD_IP4
        fi
    done
fi

# 2. Cek IPv6 dari Kernel Recent Tracker
if [ -f /proc/net/if_inet6 ] && [ -f /proc/net/xt_recent/BAD_IP6 ]; then
    awk -v limit="$MAX_RETRY" '$4 >= limit {print $1}' /proc/net/xt_recent/BAD_IP6 2>/dev/null | cut -d'=' -f2 | while read -r ip; do
        if [ -n "$ip" ]; then
            block_ip "$ip" "IPv6" "unauthorized port scan"
            echo "-$ip" > /proc/net/xt_recent/BAD_IP6
        fi
    done
fi

```

---

### 2. Integration Hook CSF (`/etc/csf/csfpost.sh`)

Buat atau ubah file hook CSF ini dengan akses root (**Wajib `sudo**`):

```bash
sudo nano /etc/csf/csfpost.sh

```

Script ini **otomatis dijalankan oleh CSF** setiap kali CSF di-restart (`csf -r`). Script ini yang bertugas mengurus aturan `iptables` & `ip6tables` di baris paling bawah secara otomatis, sehingga Anda tidak perlu memikirkan urutan port manual lagi.

```bash
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

```

---

### 3. Script Unblock IP untuk Testing (`/usr/local/bin/unblock-ip.sh`)

Buat file utility pembebas IP dengan akses root (**Wajib `sudo**`):

```bash
sudo nano /usr/local/bin/unblock-ip.sh

```

Gunakan script ini saat testing aplikasi internal untuk menghapus IP (IPv4 maupun IPv6) dari `csf.deny`, membebaskannya dari memori kernel tracker, serta menghapusnya dari rantai *temporary block*.

```bash
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

```

---

### 4. Script Auto-Check & Audit Port CSF (`/usr/local/bin/check-csf-ports.sh`)

Buat file audit port dengan akses root (**Wajib `sudo**`):

```bash
sudo nano /usr/local/bin/check-csf-ports.sh

```

Script ini secara otomatis memeriksa port yang sedang *listening* di sistem (via `ss`) dan membandingkannya dengan konfigurasi `TCP_IN` & `UDP_IN` di `/etc/csf/csf.conf` milik Aetherinox CSF.

```bash
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

```

---

### 5. Konfigurasi Systemd Service & Timer (Pengganti Cron)

Sebagai pengganti Cron, kita gunakan **Systemd Timer** untuk mengeksekusi script `port-trapper.sh` setiap 1 menit secara terisolasi dan aman di tingkat sistem.

#### Step A: Buat File Unit Service (**Wajib `sudo**`)

```bash
sudo nano /etc/systemd/system/port-trapper.service

```

Tempelkan unit konfigurasi service berikut:

```ini
[Unit]
Description=Port Trapper Auto-Block Service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/port-trapper.sh

```

#### Step B: Buat File Unit Timer (**Wajib `sudo**`)

```bash
sudo nano /etc/systemd/system/port-trapper.timer

```

Tempelkan unit konfigurasi timer berikut:

```ini
[Unit]
Description=Run Port Trapper every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Unit=port-trapper.service

[Install]
WantedBy=timers.target

```

---

### CARA INSTALLASI & EKSEKUSI

1. **Beri Hak Akses Eksekusi Script (**Wajib `sudo**`):**
```bash
sudo chmod +x /usr/local/bin/port-trapper.sh
sudo chmod +x /etc/csf/csfpost.sh
sudo chmod +x /usr/local/bin/unblock-ip.sh
sudo chmod +x /usr/local/bin/check-csf-ports.sh

```


2. **Aktifkan & Jalankan Systemd Timer (**Wajib `sudo**`):**
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now port-trapper.timer

```


*Untuk memastikan timer sudah berjalan dengan benar:*
```bash
sudo systemctl status port-trapper.timer

```


3. **Terapkan CSF Pertama Kali (**Wajib `sudo**`):**
```bash
sudo csf -r

```



---

### CARA PENGGUNAAN SEHARI-HARI

* **Menambah Port Aktif Baru (**Wajib `sudo**`):** Cukup masukkan port baru ke `TCP_IN`/`UDP_IN` di `/etc/csf/csf.conf` (`sudo nano /etc/csf/csf.conf`) lalu jalankan:
```bash
sudo csf -r

```


* **Membuka IP yang Terblokir / Testing (**Wajib `sudo**`):**
```bash
sudo unblock-ip 192.168.1.50
# Atau IPv6
sudo unblock-ip 2001:db8::1

```


* **Mengecek Status Port (**Wajib `sudo**`):**
```bash
sudo check-csf-ports.sh

```


* **Mengecek Log Eksekusi Daemon Auto-Block (**Wajib `sudo**`):**
```bash
sudo journalctl -u port-trapper.service -n 20

```
