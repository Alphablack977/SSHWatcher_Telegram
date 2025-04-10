#!/usr/bin/env python3
import os, re, time, requests, subprocess
from datetime import datetime
from collections import defaultdict

# === INPUT TELEGRAM CONFIG SAAT PERTAMA DIJALANKAN ===
def get_config():
    config_file = os.path.expanduser("~/.sshwatcher/config.txt")
    if os.path.exists(config_file):
        with open(config_file) as f:
            lines = f.read().splitlines()
            return lines[0], lines[1] if len(lines) >= 2 else ("", "")
    else:
        token = input("Masukkan Telegram Bot Token: ").strip()
        chat_id = input("Masukkan Chat ID Telegram: ").strip()
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        with open(config_file, 'w') as f:
            f.write(token + "\n" + chat_id)
        return token, chat_id

TELEGRAM_TOKEN, CHAT_ID = get_config()

# === KONFIGURASI ===
AUTH_LOG = os.path.expanduser("~/.sshwatcher/logs/auth.log")
KNOWN_IP_FILE = os.path.expanduser("~/.sshwatcher/known_ips.txt")
LOG_FILE = os.path.expanduser("~/.sshwatcher/sshwatcher.log")
AUTO_BLOCK = True
PANIC_MODE = True
SUSPICIOUS_KEYWORDS = ["root", "invalid", "failed", "disconnect", "scan"]

# Fail2Ban Mini
failed_attempts = defaultdict(int)
BAN_THRESHOLD = 5

# === FUNGSI-FUNGSI INTI ===
def send_telegram(msg):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={"chat_id": CHAT_ID, "text": msg, "disable_notification": True}
        )
    except:
        pass

def geoip_lookup(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,query,org,lat,lon,country,regionName,city", timeout=5)
        data = r.json()
        if data.get("status") == "success":
            text = f"{data['query']} | {data['org']} | {data['city']}, {data['regionName']}, {data['country']}"
            map_link = f"https://www.google.com/maps?q={data['lat']},{data['lon']}"
            return f"{text}\nMap: {map_link}"
        return "Lokasi tidak ditemukan"
    except:
        return "GeoIP error"

def kill_wifi():
    try:
        subprocess.run(["termux-wifi-enable", "false"], check=True)
        send_telegram("[SSHWatcher] WiFi dimatikan oleh sistem!")
    except:
        send_telegram("[SSHWatcher] Gagal mematikan WiFi.")

def check_commands():
    try:
        r = requests.get(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates")
        updates = r.json().get("result", [])
        for msg in reversed(updates):
            text = msg.get("message", {}).get("text", "")
            if text == "/shutdown":
                send_telegram("[SSHWatcher] Perintah /shutdown diterima.")
                subprocess.run(["pkill", "sshd"])
                return
            elif text == "/panic":
                send_telegram("[SSHWatcher] PANIC MODE DI-TRIGGER!")
                subprocess.run(["pkill", "sshd"])
                kill_wifi()
                return
    except:
        pass

def is_ip_known(ip):
    return os.path.exists(KNOWN_IP_FILE) and ip in open(KNOWN_IP_FILE).read()

def add_ip(ip):
    with open(KNOWN_IP_FILE, 'a') as f:
        f.write(ip + '\n')

def block_ip(ip):
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        send_telegram(f"[SSHWatcher]\nIP {ip} DIBLOKIR.")
        with open(LOG_FILE, 'a') as f:
            f.write(f"{datetime.now()} - BLOCKED IP: {ip}\n")
    except:
        pass

def trigger_panic(ip, reason):
    send_telegram(f"[PANIC MODE]\nIP: {ip}\nAlasan: {reason}")
    subprocess.run(["pkill", "sshd"])
    kill_wifi()
    with open(LOG_FILE, 'a') as f:
        f.write(f"{datetime.now()} - PANIC TRIGGERED: {ip} - {reason}\n")

def tail(log_file):
    with open(log_file, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            check_commands()
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(1)

def monitor():
    os.makedirs(os.path.dirname(KNOWN_IP_FILE), exist_ok=True)
    print("[*] SSHWatcher aktif...")
    for line in tail(AUTH_LOG):
        line_lower = line.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in line_lower:
                ip_match = re.search(r'from (\d{1,3}(?:\.\d{1,3}){3})', line)
                if ip_match:
                    ip = ip_match.group(1)
                    reason = f"Terdeteksi: {keyword}"
                    failed_attempts[ip] += 1
                    send_telegram(f"[SSHWatcher] Aktivitas mencurigakan:\nIP: {ip}\nPercobaan ke-{failed_attempts[ip]}\n{reason}")
                    if failed_attempts[ip] >= BAN_THRESHOLD:
                        send_telegram(f"[SSHWatcher] IP {ip} melebihi batas gagal login! Memblokir...")
                        block_ip(ip)
                        del failed_attempts[ip]
                    if PANIC_MODE:
                        trigger_panic(ip, reason)

        if "Accepted" in line:
            match = re.search(r'Accepted \w+ for (\w+) from ([\d\.]+)', line)
            if match:
                user, ip = match.groups()
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                geo = geoip_lookup(ip)
                log = f"[{timestamp}] Login: {user}@{ip} -> {geo}"
                send_telegram(f"[LOGIN]\nUser: {user}\nIP: {ip}\n{geo}")
                if not is_ip_known(ip):
                    add_ip(ip)
                    if AUTO_BLOCK:
                        block_ip(ip)
                    log += " (NEW IP)"
                with open(LOG_FILE, 'a') as f:
                    f.write(log + '\n')

if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        print("\n[!] Dihentikan oleh user.")
