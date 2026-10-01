# (v2) AutoBlock Penyerang IP (Khusus CSF Aetherinox Fork)

Kumpulan script Bash yang efisien, hemat vCPU, dan mendukung dual-stack
(**IPv4 & IPv6**), ditargetkan untuk **Debian 13 (trixie)**.

Rangkaian script ini dirancang agar **tidak memicu *logging storm*** saat
server diserang *port scan* acak, serta disesuaikan dengan variabel konfigurasi
milik repositori **[Aetherinox/csf-firewall](https://github.com/Aetherinox/csf-firewall)**.
Eksekusi berkala ditangani secara modern menggunakan **Systemd Timer**
(pengganti Cron).

**Daftar isi**

- [0. Prasyarat (Debian 13)](#0-prasyarat-debian-13)
- [1. Konfigurasi Wajib CSF](#1-konfigurasi-wajib-csf-etccsfcsfconf)
- [2. Script Penangkap & Auto-Block IP](#2-script-penangkap--auto-block-ip-usrlocalbinport-trappersh)
- [3. Integration Hook CSF (iptables)](#3-integration-hook-csf-etccsfcsfpostsh)
- [3b. Varian Hook nft Native (opsional)](#3b-varian-hook-nft-native-opsional)
- [4. Script Unblock IP](#4-script-unblock-ip-untuk-testing-usrlocalbinunblock-ipsh)
- [5. Script Auto-Check & Audit Port CSF](#5-script-auto-check--audit-port-csf-usrlocalbincheck-csf-portssh)
- [6. Systemd Service & Timer](#6-konfigurasi-systemd-service--timer-pengganti-cron)
- [7. Cara Instalasi & Eksekusi](#cara-instalasi--eksekusi)
- [8. Penggunaan Sehari-hari](#cara-penggunaan-sehari-hari)
- [Lampiran — Kustomisasi & Catatan Risiko](#lampiran--kustomisasi--catatan-risiko)

---

## 0. Prasyarat (Debian 13)

CSF (fork Aetherinox) di Debian 13 membutuhkan paket & modul kernel berikut.

```bash
sudo apt-get update
sudo apt-get install -y iptables ipset perl postfix libwww-perl \
  libcrypt-ssleay-perl libio-socket-ssl-perl libio-socket-inet6-perl \
  libsocket6-perl libnet-libidn-perl
```

Pastikan modul kernel **`xt_recent`** tersedia (dipakai `iptables -m recent`):

```bash
sudo modprobe xt_recent
ls -l /proc/net/xt_recent/ || echo "Belum ada tabel recent (normal bila belum ada rule --set)"
```

> `iptables` disertakan karena di Debian 13 ia menjadi front-end nftables
> (default dipakai CSF). Bila Anda memakai CSF dengan `nft` native, lihat §0.1.

### 0.1 Backend firewall (default Debian 13)

Fork Aetherinox **mendukung `iptables` maupun `nftables`**. Yang wajib: hook
(§3) harus memakai **backend yang sama** dengan CSF, sebab jika berbeda, rantai
`LOCALINPUT` dan tabel `recent` tidak akan sinkron.

**Default praktis di Debian 13 (dokumen ini):** pakai **`iptables`**. Perintah
`iptables`/`ip6tables` di Debian 13 sudah menjadi front-end nftables
(`iptables-nft`), dan paket **`nftables` (binary `nft`) sering tidak terpasang**.
Jadi:

- Selama CSF memakai `iptables`, hook §3 (`iptables` mentah) **sudah benar**.
- Anda **tidak perlu** memasang `nft`/`nftables`.

Cek yang tersedia & backend CSF:

```bash
command -v iptables ip6tables nft   # nft biasanya tidak ada -> abaikan
grep -E '^\s*(IPTABLES|IP6TABLES)\s*=' /etc/csf/csf.conf || echo "(default CSF)"
```

Verifikasi hook benar-benar aktif (setelah §3 & `csf -r`):

```bash
sudo iptables -L LOCALINPUT -n 2>/dev/null | grep -q PORT_SCAN_TRAP4 \
  && echo "OK: hook terpasang di LOCALINPUT (iptables)"
```

> **Jangan mencampur** `iptables-legacy` dengan CSF yang memakai `iptables-nft`
> — rantai `LOCALINPUT` akan tampak kosong di backend lain. Bila (kasus khusus)
> CSF dikonfigurasi **`nft` native**, baru pakai **varian hook `nft`** di §3b
> (perlu memasang paket `nftables`).

---

## 1. Rekomendasi `csf.conf` (hardened — port scan via skrip)

> **PERINGATAN (wadah / SSH jarak jauh):** Jangan memutus interface jaringan
> (`eth0`) saat mengelola server via SSH — sesi akan langsung terputus. Ini
> hanya untuk akses **KVM / Serial Console**. Dokumen ini **tidak** meminta
> Anda memutus interface apa pun.

**Backup dulu**, lalu edit **hanya baris** yang dimaksud (jangan menimpa
seluruh file):

```bash
sudo cp /etc/csf/csf.conf /etc/csf/csf.conf.bak-$(date +%F)
sudo nano /etc/csf/csf.conf
```

Ubah/set baris berikut (sisanya biarkan apa adanya):

```ini
# ===== 1. Mode produksi & batas ban sementara =====
TESTING = "0"
# 0 = HILANGKAN batas ban sementara (unlimited). Ini BUKAN "mode permanen".
DENY_TEMP_IP_LIMIT = "0"

# ===== 2. Hemat vCPU & serahkan deteksi port scan ke port-trapper.sh =====
# Matikan logging drop (anti logging storm). Ini HANYA mengatur pencatatan,
# BUKAN syarat agar paket masuk ke hook csfpost.sh (yang menentukan adalah
# posisi rantai LOCALINPUT, lihat §3).
DROP_LOGGING = "0"
DROP_NOLOG = "0:65535"
# PS_INTERVAL="0" = NONAKTIFKAN Port Scan Tracking bawaan CSF (default "0").
# Inilah saklar on/off-nya; kita pakai port-trapper.sh sebagai gantinya.
PS_INTERVAL = "0"
# PS_LIMIT tidak berpengaruh saat PS_INTERVAL="0" (default aslinya "10").
PS_LIMIT = "0"
PS_EMAIL_ALERT = "0"
LOGFLOOD_ALERT = "0"

# ===== 3. Proteksi banjir koneksi per-port (karena port scan bawaan mati) =====
# Format: "port;proto;connections;seconds". Butuh modul ipt_recent (umum ada
# di Debian). JANGAN pasang pada port RTP (media ±100 pkt/detik -> false-positive).
PORTFLOOD = "25213;udp;20;5"

# ===== 4. Proteksi gagal login (brute force) — mode KUMULATIF =====
# LF_TRIGGER > 0 -> mode kumulatif: nilai LF_SSHD menjadi on/off (bukan jumlah).
# Total kegagalan (lintas aplikasi) yang men-trigger = LF_TRIGGER.
LF_TRIGGER = "3"        # 3 kegagalan kumulatif -> blokir
LF_TRIGGER_PERM = "1"   # 1 = BLOKIR PERMANEN (agar "langsung permanen")
LF_SSHD = "1"           # 1 = sshd diaktifkan dalam mode kumulatif
LF_SSHD_PERM = "1"      # 1 = permanen
```

> **Catatan mode LF.** Karena `LF_TRIGGER="3"` (> 0), CSF masuk **mode
> kumulatif**: nilai `LF_SSHD` hanyalah **on/off** (di sini `"1"` = aktif),
> dan ambang pemblokiran ditentukan `LF_TRIGGER`. Hasil: **3 kegagalan
> (kumulatif) → blokir permanen**. Bila kelak ingin ambang **khusus** SSH
> terpisah, gunakan mode per-aplikasi (`LF_TRIGGER="0"`, `LF_SSHD="3"`).

> **Catatan `PORTFLOOD`.** Melindungi port tertentu dari banjir koneksi: di
> atas `20` koneksi baru per `5` detik ke UDP `25213` akan ditangani. Ini
> pelengkap penting karena **Port Scan Tracking bawaan CSF dimatikan**.
> Verifikasi dukungan: `sudo /etc/csf/csftest.pl` (cari `ipt_recent`).

> **Catatan risiko (sengaja, "tangkap awal"):** `DROP_LOGGING="0"` +
> `DROP_NOLOG="0:65535"` mematikan **seluruh** log paket yang di-drop,
> **termasuk SSH**. Keuntungan: hemat vCPU/disk (anti logging storm). Konsekuensi:
> jejak drop tidak tercatat, sehingga diagnosis serangan lebih sulit. Bila
> kelak perlu audit SSH, ganti sementara menjadi `DROP_NOLOG = "22"`.

### 1.1 VERIFIKASI (wajib — PS bawaan CSF dimatikan)

Karena `PS_INTERVAL="0"` menonaktifkan deteksi port scan bawaan CSF, maka
**`port-trapper.sh` + hook §3 menjadi satu-satunya penangkap**. Pastikan hook
benar-benar aktif:

```bash
# 1) Hook csfpost terpasang di LOCALINPUT (harus tampil).
sudo iptables -L LOCALINPUT -n 2>/dev/null | grep PORT_SCAN_TRAP4 \
  || echo "GAGAL: hook tidak terpasang -> cek §3 / backend CSF"

# 2) Uji dari mesin LAIN: konek ke port tertutup server, lalu di server:
#    (tabel xt_recent terbentuk setelah ada hit)
ls -l /proc/net/xt_recent/BAD_IP4
sudo csf -t        # daftar temporary block
```

> **Trade-off penting:** bila hook gagal (mis. backend CSF ≠ backend hook),
> maka **tidak ada** deteksi port scan sama sekali. Jalankan verifikasi di atas
> setiap kali `csf.conf`/hook diubah.

---

## 2. Script Penangkap & Auto-Block IP (`/usr/local/bin/port-trapper.sh`)

Buat file script penangkap dengan akses root (**wajib `sudo`**):

```bash
sudo nano /usr/local/bin/port-trapper.sh
```

Script ini membaca penangkapan *port scan* dari modul kernel `xt_recent`
(IPv4 & IPv6), lalu mendaftarkannya ke CSF. Parameter `BLOCK_TIME` menentukan
**Sementara (Temporary)** atau **Permanen**.

```bash
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
```

> **Peringatan `MAX_RETRY=1`:** satu hit ke port tak aktif langsung memicu
> blokir 48 jam. Ini **agresif & sengaja** untuk menangkap penyerang sejak
> awal, namun berisiko *false-positive* (klien sah yang salah port/retransmisi).
> Lihat [Lampiran](#lampiran--kustomisasi--catatan-risiko) untuk penyesuaian.

---

## 3. Integration Hook CSF (`/etc/csf/csfpost.sh`)

Buat atau ubah file hook CSF ini dengan akses root (**wajib `sudo`**):

```bash
sudo nano /etc/csf/csfpost.sh
```

Script ini **otomatis dijalankan CSF** setiap `csf -r`. Rule dicantolkan ke
rantai `LOCALINPUT` (paling bawah, setelah rule ALLOW CSF) agar **port
resmi/terbuka (SSH/80/443) tidak ikut terblokir**. Hook dibuat **idempoten**
(rule lama dihapus lebih dulu, aman saat `csf -r` berulang).

```bash
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
```

> `while iptables -D ...` menghapus rule duplikat satu per satu hingga habis,
> sehingga `LOCALINPUT` tidak menumpuk walau `csf -r` dijalankan berkali-kali.

> **Script di atas ditujukan untuk CSF yang memakai `iptables`** — ini kondisi
> normal di Debian 13 (perintah `iptables` sudah front-end nft; paket `nft`
> biasanya tak terpasang). Verifikasi: `iptables -L LOCALINPUT -n` harus
> menampilkan `PORT_SCAN_TRAP4`. §3b di bawah hanya untuk kasus langka (CSF
> `nft` native, perlu paket `nftables`).

---

## 3b. Varian Hook `nft` Native (opsional)

> **Umumnya TIDAK diperlukan.** Pada instalasi biasa (termasuk Debian 13),
> perintah firewall yang tersedia adalah **`iptables`** dan paket `nftables`
> (binary `nft`) sering **tidak terpasang** → `nft: command not found`.
> Gunakan **§3**, bukan bagian ini.
>
> §3b hanya untuk kasus khusus: CSF dikonfigurasi memakai **`nft` native**.
> Prasyarat: pasang paket `nftables` dulu (`sudo apt-get install -y nftables`).
> Implementasi di bawah memakai fitur `nft` termasuk `ct state` dan `@bad_ip4`
> (named set dengan flag `dynamic`/`timeout`, meniru perilaku `xt_recent`).

**Cek dulu apakah `nft` memang ada:**

```bash
command -v nft || echo "nft tidak terpasang -> pakai §3 (iptables), bukan §3b"
```

```bash
#!/bin/bash
# Path: /etc/csf/csfpost.sh  (varian nft native)

# ---- IPv4 ----
nft list table inet csf_port_trap >/dev/null 2>&1 || nft add table inet csf_port_trap
nft delete chain inet csf_port_trap trap4 >/dev/null 2>&1
nft add chain inet csf_port_trap trap4
nft add set  inet csf_port_trap bad_ip4 '{ type ipv4_addr; flags dynamic,timeout; timeout 7d; }'
nft add rule inet csf_port_trap trap4 ct state new update @bad_ip4 { ip saddr } drop

# ---- IPv6 (jika aktif) ----
if [ -f /proc/net/if_inet6 ]; then
    nft delete chain inet csf_port_trap trap6 >/dev/null 2>&1
    nft add chain inet csf_port_trap trap6
    nft add set  inet csf_port_trap bad_ip6 '{ type ipv6_addr; flags dynamic,timeout; timeout 7d; }'
    nft add rule inet csf_port_trap trap6 ct state new update @bad_ip6 { ip6 saddr } drop
fi

# Cantolkan ke rantai yang dipakai CSF (nama dapat berbeda antar versi).
# Cek dulu: nft list ruleset | grep -i localinput
CHAIN4=$(nft -a list chains 2>/dev/null | grep -i 'LOCALINPUT' | head -n1)
# Bila CSF menyediakan chain khusus, sesuaikan nama di bawah:
#   nft add rule inet <table-csf> <chain-csf> jump trap4
```

> **Catatan penting:** nama tabel/rantai CSF berbeda antar instalasi. **Selalu
> verifikasi** dengan `nft list ruleset` dan sesuaikan nama chain. Bila CSF
> memakai `iptables`, **jangan** pakai §3b — cukup §3. Rebelot hook dijalankan
> otomatis tiap `csf -r`.
>
> Verifikasi: `nft list ruleset | grep -E 'csf_port_trap|bad_ip'`.

---

## 4. Script Unblock IP untuk Testing (`/usr/local/bin/unblock-ip.sh`)

Buat file utility pembebas IP dengan akses root (**wajib `sudo`**):

```bash
sudo nano /usr/local/bin/unblock-ip.sh
```

Gunakan saat testing untuk menghapus IP (IPv4/IPv6) dari `csf.deny`,
membebaskannya dari memori kernel tracker, dan membersihkan temporary block.

```bash
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
```

> Langkah `csf -r` di akhir **relatif berat** (menyusun ulang seluruh rule).
> Untuk pembebasan cepat berulang, langkah ini boleh dilewati.

---

## 5. Script Auto-Check & Audit Port CSF (`/usr/local/bin/check-csf-ports.sh`)

Buat file audit port dengan akses root (**wajib `sudo`**):

```bash
sudo nano /usr/local/bin/check-csf-ports.sh
```

Script memeriksa port yang sedang *listening* (via `ss`) dan
**membandingkannya** dengan `TCP_IN`/`UDP_IN` (+ varian IPv6) di
`/etc/csf/csf.conf`. Bila ada port yang listening namun **tidak terdaftar**,
ditandai `[WARN]` dan script keluar dengan kode **1** (bisa dipakai monitoring).

```bash
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
```

---

## 6. Konfigurasi Systemd Service & Timer (Pengganti Cron)

Timer mengeksekusi `port-trapper.sh` setiap 1 menit secara terisolasi.

### Step A: Unit Service (**wajib `sudo`**)

```bash
sudo nano /etc/systemd/system/port-trapper.service
```

```ini
[Unit]
Description=Port Trapper Auto-Block Service
Documentation=file:/etc/csf/csfpost.sh
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/port-trapper.sh
```

### Step B: Unit Timer (**wajib `sudo`**)

```bash
sudo nano /etc/systemd/system/port-trapper.timer
```

```ini
[Unit]
Description=Run Port Trapper every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
RandomizedDelaySec=5s
Unit=port-trapper.service

[Install]
WantedBy=timers.target
```

---

## Cara Instalasi & Eksekusi

1. **Beri hak akses eksekusi** (**wajib `sudo`**):

```bash
sudo chmod +x /usr/local/bin/port-trapper.sh
sudo chmod +x /etc/csf/csfpost.sh
sudo chmod +x /usr/local/bin/unblock-ip.sh
sudo chmod +x /usr/local/bin/check-csf-ports.sh
```

2. **Aktifkan systemd timer** (**wajib `sudo`**):

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now port-trapper.timer
sudo systemctl status port-trapper.timer
```

3. **Terapkan CSF pertama kali** (**wajib `sudo`**):

```bash
sudo csf -r
```

---

## Cara Penggunaan Sehari-hari

- **Menambah port aktif baru** (**wajib `sudo`**): edit `TCP_IN`/`UDP_IN` di
  `/etc/csf/csf.conf` (`sudo nano /etc/csf/csf.conf`), lalu:

```bash
sudo csf -r
```

- **Membuka IP yang terblokir / testing** (**wajib `sudo`**):

```bash
sudo unblock-ip 192.168.1.50
# atau IPv6
sudo unblock-ip 2001:db8::1
```

- **Mengecek status port** (**wajib `sudo`**):

```bash
sudo check-csf-ports.sh
echo "exit: $?"   # 1 = ada port listening yang belum terdaftar di CSF
```

- **Melihat log daemon auto-block** (**wajib `sudo`**):

```bash
sudo journalctl -u port-trapper.service -n 20
```

- **Daftar IP temporary block** (**wajib `sudo`**):

```bash
sudo csf -t
```

---

## Lampiran — Kustomisasi & Catatan Risiko

### `MAX_RETRY` dan `BLOCK_TIME` (`port-trapper.sh`)

| Nilai | Efek | Cocok untuk |
|-------|------|-------------|
| `MAX_RETRY=1` | Langsung blokir pada hit pertama — **agresif (tangkap awal)** | Server yang aktif diserang; risiko false-positive lebih tinggi |
| `MAX_RETRY=3` | Sedikit toleransi retransmisi | Seimbang |
| `MAX_RETRY=5` | Konservatif | Lingkungan banyak klien sah / sulit diprediksi |

`BLOCK_TIME` (detik): `172800` (48 jam) = default dokumen ini; `86400` (24 jam);
`3600` (1 jam); `0` = permanen (`csf -d`) — hati-hati, sulit dibatalkan massal.

Untuk IP dinamis/klien sah, mulai dari `MAX_RETRY=3` & `BLOCK_TIME=3600`,
naikkan bila serangan berlanjut.

### Referensi cepat setelan `csf.conf` (fork Aetherinox)

| Variabel | Default | Arti nilai `"0"` | Catatan |
|----------|---------|------------------|---------|
| `TESTING` | `"1"` | — | `0` = produksi (LFD & rule aktif). |
| `DENY_TEMP_IP_LIMIT` | `"100"` | Hilangkan batas ban **sementara** (unlimited) | Bukan "mode permanen". |
| `DROP_LOGGING` | `"1"` | Matikan log drop ke syslog | Memutus Port Scan Tracking bawaan. |
| `DROP_NOLOG` | daftar port | Bukan on/off (daftar port tak di-log) | `0:65535` = semua port tak di-log. |
| `PS_INTERVAL` | `"0"` | **Nonaktifkan** Port Scan Tracking bawaan | 60–300 untuk mengaktifkan. |
| `PS_LIMIT` | `"10"` | Tak berdampak saat `PS_INTERVAL=0` | Ambang blok dalam jendela PS. |
| `PS_EMAIL_ALERT` | `"1"` | Matikan email alert scan | Tracking tetap (bila aktif). |
| `PORTFLOOD` | `""` | Bukan nilai bermakna | Format `port;proto;connections;seconds`. |
| `LF_TRIGGER` | `"0"` | Mode per-aplikasi (tiap `LF_app` ambangnya) | `>0` = mode kumulatif. |
| `LF_TRIGGER_PERM` | `"1"` | — | `1`=permanen, `>1`=sementara (detik). Hanya berlaku bila `LF_TRIGGER>0`. |
| `LF_SSHD` | `"5"` | Matikan deteksi sshd | Di mode kumulatif = on/off. |
| `LF_SSHD_PERM` | `"1"` | — | `1`=permanen, `>1`=sementara. |

### Catatan `DROP_NOLOG`

`DROP_NOLOG="0:65535"` + `DROP_LOGGING="0"` = hemat vCPU (anti logging storm),
tetapi **seluruh** drop tidak tercatat (termasuk SSH). Bila butuh audit SSH,
set sementara `DROP_NOLOG="22"`.

### Backend firewall (Debian 13)

Fork Aetherinox mendukung `iptables` **atau** `nftables`. **Default Debian 13:**
Default pakai **`iptables`** (di Debian 13 sudah front-end nft); paket `nft`
umumnya tak terpasang, jadi `nft`/§3b biasanya **tidak perlu**. Hook §3 benar
selama CSF memakai `iptables`. §3b hanya untuk CSF ber-`nft` native (pasang
paket `nftables` dulu). Jangan mencampur `iptables-legacy` dengan CSF
`iptables-nft`.

Verifikasi: `sudo iptables -L LOCALINPUT -n | grep PORT_SCAN_TRAP4` (harus tampil).

### Opsional: IPSET Blocklist Resmi Aetherinox

Pelengkap hemat vCPU (bukan pengganti auto-block kita). Tambahkan ke
`/etc/csf/csf.blocklists`:

```bash
sudo tee -a /etc/csf/csf.blocklists >/dev/null <<'EOF'
CSF_MASTER|43200|400000|https://raw.githubusercontent.com/Aetherinox/csf-firewall/main/blocklists/master.ipset
CSF_HIGHRISK|43200|0|https://raw.githubusercontent.com/Aetherinox/csf-firewall/main/blocklists/highrisk.ipset
EOF
sudo csf -r
```

> `master.ipset` & `highrisk.ipset` = daftar IP abusive (port scan, brute force,
> DDoS) dengan tingkat keyakinan tinggi; diperbarui tiap 12 jam oleh CSF.
> Otomatis diblokir di level ipset (efisien, tanpa membebani aturan panjang).

### Idempotensi

- `csfpost.sh` menghapus rule lama sebelum menambah (aman saat `csf -r`
  berulang).
- `port-trapper.sh` memakai lockfile (`/tmp/port_trapper.lock`) agar eksekusi
  timer tidak tumpang-tindih.
- Cek `csf.deny` mencegah duplikasi entri.
