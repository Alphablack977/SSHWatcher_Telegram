SSHWatcher Pro

SSHWatcher Pro adalah alat keamanan otomatis berbasis Python untuk Termux yang digunakan untuk memantau login SSH, mendeteksi aktivitas mencurigakan, dan mengambil tindakan pertahanan seperti memblokir IP berbahaya atau menonaktifkan koneksi SSH secara otomatis.

Fitur Utama :

-Deteksi login SSH secara real-time dari file auth.log

-Notifikasi Telegram untuk login baru atau mencurigakan

-GeoIP Lookup dengan tautan Google Maps untuk lokasi IP

-Pemblokiran IP otomatis menggunakan iptables

-Deteksi aktivitas mencurigakan seperti login root, gagal login, port scanning

-Panic Mode: menonaktifkan SSH dan WiFi otomatis

-Remote control melalui Telegram: kirim perintah /panic atau /shutdown

-Fail2Ban ringan: blokir IP yang gagal login berkali-kali (default 5x)

-Auto-start di Termux saat terminal dibuka

-Otomatis simpan Telegram Bot Token & Chat ID saat pertama kali dijalankan


Instalasi

1. Unduh atau Kloning Repository

git clone https://github.com/Alphablack977/SSHWatcher_Telegram
cd sshwatcher-pro

2. Jalankan skrip Python langsung

python3 sshwatcher_pro.py

> Saat pertama kali dijalankan, kamu akan diminta memasukkan Telegram Bot Token dan Chat ID. Ini akan disimpan otomatis ke ~/.sshwatcher/config.txt.



3. Jalankan SSH agar log dapat dimonitor

sshd -E ~/.sshwatcher/logs/auth.log

Perintah Telegram

Struktur File

sshwatcher_pro.py — Script utama pemantau SSH

~/.sshwatcher/config.txt — Token & Chat ID Telegram

~/.sshwatcher/logs/auth.log — Log dari sshd

~/.sshwatcher/sshwatcher.log — Catatan semua aktivitas login dan blokir

~/.sshwatcher/known_ips.txt — Daftar IP yang sudah dikenal (whitelist)


Lisensi

Proyek ini berlisensi open-source. Silakan gunakan, modifikasi, dan bagikan kembali dengan mencantumkan kredit.

Kontribusi

Pull request dan masukan sangat diterima! Silakan fork dan kembangkan.

