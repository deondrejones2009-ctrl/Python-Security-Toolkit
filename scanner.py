import socket
import threading
from queue import Queue
from datetime import datetime
import ipaddress
import random
import time
import requests
import re
import subprocess
import sqlite3

GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

print_lock = threading.Lock()

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
output_file = f"scan_results_{timestamp}.txt"

def write_result(text):
    with open(output_file, "a") as f:
        f.write(text + "\n")
class DatabaseManager:
    def __init__(self, db_path="recon.db"):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self.create_tables()

    def create_tables(self):
        cur = self.conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            preset TEXT,
            target TEXT
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            first_seen TEXT,
            last_seen TEXT
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            port INTEGER,
            protocol TEXT,
            service TEXT,
            first_seen TEXT,
            last_seen TEXT,
            FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS banners (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port_id INTEGER,
            banner TEXT,
            version TEXT,
            timestamp TEXT,
            FOREIGN KEY(port_id) REFERENCES ports(id) ON DELETE CASCADE
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS web_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port_id INTEGER,
            status INTEGER,
            server TEXT,
            content_type TEXT,
            title TEXT,
            timestamp TEXT,
            FOREIGN KEY(port_id) REFERENCES ports(id) ON DELETE CASCADE
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS os_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            ttl INTEGER,
            guess TEXT,
            timestamp TEXT,
            FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS intel_placeholders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            intel_type TEXT,
            data TEXT,
            timestamp TEXT,
            FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
        );
        """)

        self.conn.commit()

    def create_scan(self, preset, target):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO scans (timestamp, preset, target) VALUES (?, ?, ?);",
            (timestamp, preset, target)
        )
        self.conn.commit()
        return cur.lastrowid

    def upsert_host(self, ip):
        cur = self.conn.cursor()
        now = datetime.now().isoformat(timespec="seconds")
        cur.execute("SELECT id FROM hosts WHERE ip = ?;", (ip,))
        row = cur.fetchone()
        if row:
            host_id = row[0]
            cur.execute("UPDATE hosts SET last_seen = ? WHERE id = ?;", (now, host_id))
        else:
            cur.execute(
                "INSERT INTO hosts (ip, first_seen, last_seen) VALUES (?, ?, ?);",
                (ip, now, now)
            )
            host_id = cur.lastrowid
        self.conn.commit()
        return host_id

    def upsert_port(self, host_id, port, protocol, service):
        cur = self.conn.cursor()
        now = datetime.now().isoformat(timespec="seconds")
        cur.execute(
            "SELECT id FROM ports WHERE host_id = ? AND port = ? AND protocol = ?;",
            (host_id, port, protocol)
        )
        row = cur.fetchone()
        if row:
            port_id = row[0]
            cur.execute(
                "UPDATE ports SET last_seen = ?, service = ? WHERE id = ?;",
                (now, service, port_id)
            )
        else:
            cur.execute(
                "INSERT INTO ports (host_id, port, protocol, service, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?);",
                (host_id, port, protocol, service, now, now)
            )
            port_id = cur.lastrowid
        self.conn.commit()
        return port_id

    def insert_banner(self, port_id, banner, version):
        cur = self.conn.cursor()
        now = datetime.now().isoformat(timespec="seconds")
        cur.execute(
            "INSERT INTO banners (port_id, banner, version, timestamp) VALUES (?, ?, ?, ?);",
            (port_id, banner, version, now)
        )
        self.conn.commit()

    def insert_web_info(self, port_id, status, server, content_type, title):
        cur = self.conn.cursor()
        now = datetime.now().isoformat(timespec="seconds")
        cur.execute(
            "INSERT INTO web_info (port_id, status, server, content_type, title, timestamp) VALUES (?, ?, ?, ?, ?, ?);",
            (port_id, status, server, content_type, title, now)
        )
        self.conn.commit()

    def insert_os_info(self, host_id, ttl, guess):
        cur = self.conn.cursor()
        now = datetime.now().isoformat(timespec="seconds")
        cur.execute(
            "INSERT INTO os_info (host_id, ttl, guess, timestamp) VALUES (?, ?, ?, ?);",
            (host_id, ttl, guess, now)
        )
        self.conn.commit()

    def insert_intel_placeholder(self, host_id, intel_type, data):
        cur = self.conn.cursor()
        now = datetime.now().isoformat(timespec="seconds")
        cur.execute(
            "INSERT INTO intel_placeholders (host_id, intel_type, data, timestamp) VALUES (?, ?, ?, ?);",
            (host_id, intel_type, data, now)
        )
        self.conn.commit()


db = DatabaseManager()
# =========================
# Service Map
# =========================
SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 514: "Syslog", 587: "SMTP-SSL",
    631: "IPP", 993: "IMAP-SSL", 995: "POP3-SSL",
    1900: "SSDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

def get_service(port):
    return SERVICES.get(port, "Unknown")


# =========================
# Version Extraction (Safe)
# =========================
def extract_version(banner):
    if not banner:
        return None

    patterns = [
        r"(OpenSSH[_/ ]\d[\w\.]*)",
        r"(nginx[/ ]\d[\w\.]*)",
        r"(Apache[/ ]\d[\w\.]*)",
        r"(OpenSSL[/ ]\d[\w\.]*)",
        r"(vsftpd[/ ]\d[\w\.]*)",
        r"(ProFTPD[/ ]\d[\w\.]*)",
        r"(Postfix[/ ]\d[\w\.]*)",
        r"(Dovecot[/ ]\d[\w\.]*)",
        r"(Microsoft-IIS[/ ]\d[\w\.]*)",
        r"(BIND[/ ]\d[\w\.]*)"
    ]

    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


# =========================
# Web Enumeration (HTTP/HTTPS)
# =========================
def enumerate_web(ip, port, port_id):
    scheme = "https" if port in [443, 8443] else "http"
    url = f"{scheme}://{ip}:{port}"

    try:
        r = requests.get(url, timeout=3, verify=False)

        text_lower = r.text.lower()
        title = ""
        if "<title>" in text_lower:
            start = text_lower.find("<title>") + 7
            end = text_lower.find("</title>")
            if end > start:
                title = r.text[start:end].strip()

        server = r.headers.get("Server", "Unknown")
        content_type = r.headers.get("Content-Type", "Unknown")

        with print_lock:
            print(f"    └─ {CYAN}HTTP Status:{RESET} {r.status_code}")
            print(f"    └─ {CYAN}Server:{RESET} {server}")
            print(f"    └─ {CYAN}Content-Type:{RESET} {content_type}")
            print(f"    └─ {CYAN}Title:{RESET} {title if title else 'None'}")

        write_result(f"    HTTP Status: {r.status_code}")
        write_result(f"    Server: {server}")
        write_result(f"    Content-Type: {content_type}")
        write_result(f"    Title: {title if title else 'None'}")

        db.insert_web_info(
            port_id,
            r.status_code,
            server,
            content_type,
            title if title else None
        )

    except Exception:
        with print_lock:
            print(f"    └─ {YELLOW}Web enumeration failed{RESET}")
        write_result("    Web enumeration failed")


# =========================
# Banner Grabbing
# =========================
def grab_banner_tcp(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(1.5)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner
    except Exception:
        return None


def grab_banner_udp(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.5)
        sock.sendto(b"\x00", (ip, port))
        try:
            data, _ = sock.recvfrom(1024)
            return data.decode(errors="ignore").strip()
        except Exception:
            return None
    except Exception:
        return None
# =========================
# OS Detection (Safe Heuristic)
# =========================
def guess_os_from_ttl(ttl):
    if ttl is None:
        return "Unknown"
    if ttl >= 200:
        return "Network device / Cisco-like"
    elif ttl >= 100:
        return "Windows-like"
    elif ttl >= 50:
        return "Linux/Unix-like"
    else:
        return "Unknown"


def detect_os_ping(ip, host_id=None):
    """
    Safe OS detection using ping TTL.
    No intrusive fingerprinting.
    """
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        out = proc.stdout.lower()
        ttl = None

        for part in out.split():
            if part.startswith("ttl="):
                try:
                    ttl = int(part.split("=")[1])
                except ValueError:
                    ttl = None
                break

        os_guess = guess_os_from_ttl(ttl)

        with print_lock:
            print(f"{CYAN}OS Detection for {ip}:{RESET}")
            print(f"    TTL: {ttl}")
            print(f"    OS Guess: {os_guess}")

        write_result(f"OS Detection for {ip}")
        write_result(f"TTL: {ttl}")
        write_result(f"OS Guess: {os_guess}")

        if host_id is not None:
            db.insert_os_info(host_id, ttl, os_guess)

        return ttl, os_guess

    except Exception:
        with print_lock:
            print(f"{YELLOW}OS detection failed for {ip}{RESET}")
        write_result(f"OS detection failed for {ip}")
        return None, "Unknown"


# =========================
# Advanced Intel Placeholders (Non-operational)
# =========================
def ssl_fingerprint(ip, port, host_id):
    """
    Placeholder: SSL/TLS fingerprinting (issuer, expiry, cipher).
    Non-operational. Stored in DB for architecture only.
    """
    db.insert_intel_placeholder(
        host_id,
        "ssl",
        f"ssl_fingerprint placeholder for {ip}:{port}"
    )


def geoip_lookup(ip, host_id):
    """
    Placeholder: GeoIP lookup (country, city, ISP).
    Non-operational. Stored in DB for architecture only.
    """
    db.insert_intel_placeholder(
        host_id,
        "geoip",
        f"geoip_lookup placeholder for {ip}"
    )


def asn_lookup(ip, host_id):
    """
    Placeholder: ASN lookup (autonomous system, org).
    Non-operational. Stored in DB for architecture only.
    """
    db.insert_intel_placeholder(
        host_id,
        "asn",
        f"asn_lookup placeholder for {ip}"
    )


def cve_lookup(version_string, host_id):
    """
    Placeholder: CVE correlation based on version.
    Non-operational. Stored in DB for architecture only.
    """
    db.insert_intel_placeholder(
        host_id,
        "cve",
        f"cve_lookup placeholder for version {version_string}"
    )


def dns_enumeration(domain, host_id):
    """
    Placeholder: DNS enumeration (A, MX, NS, TXT).
    Non-operational. Stored in DB for architecture only.
    """
    db.insert_intel_placeholder(
        host_id,
        "dns",
        f"dns_enumeration placeholder for {domain}"
    )


def web_screenshot(url, host_id):
    """
    Placeholder: Web screenshot capture.
    Non-operational. Stored in DB for architecture only.
    """
    db.insert_intel_placeholder(
        host_id,
        "screenshot",
        f"web_screenshot placeholder for {url}"
    )
# =========================
# TCP / UDP Scanning
# =========================
def scan_port_tcp(ip, port, stealth, scan_id):
    try:
        if stealth:
            time.sleep(random.uniform(0.05, 0.3))

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7 if stealth else 0.5)
        result = sock.connect_ex((ip, port))

        if result == 0:
            host_id = db.upsert_host(ip)
            service = get_service(port)
            port_id = db.upsert_port(host_id, port, "tcp", service)

            with print_lock:
                print(f"{GREEN}[TCP OPEN]{RESET} {ip}:{port} ({CYAN}{service}{RESET})")
                write_result(f"[TCP OPEN] {ip}:{port} ({service})")

            banner = grab_banner_tcp(ip, port)
            if banner:
                with print_lock:
                    print(f"    └─ {CYAN}Banner:{RESET} {banner}")
                write_result(f"    Banner: {banner}")

                version = extract_version(banner)
                if version:
                    with print_lock:
                        print(f"    └─ {CYAN}Version:{RESET} {version}")
                    write_result(f"    Version: {version}")
                else:
                    version = None

                db.insert_banner(port_id, banner, version)
            else:
                with print_lock:
                    print(f"    └─ {YELLOW}No banner returned{RESET}")
                write_result("    No banner returned")

            if port in [80, 443, 8080, 8443]:
                enumerate_web(ip, port, port_id)

        sock.close()
    except Exception:
        pass


def scan_port_udp(ip, port, stealth, scan_id):
    try:
        if stealth:
            time.sleep(random.uniform(0.05, 0.3))

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(b"\x00", (ip, port))

        try:
            data, _ = sock.recvfrom(1024)
            host_id = db.upsert_host(ip)
            service = get_service(port)
            port_id = db.upsert_port(host_id, port, "udp", service)

            with print_lock:
                print(f"{GREEN}[UDP OPEN]{RESET} {ip}:{port} ({CYAN}{service}{RESET})")
                write_result(f"[UDP OPEN] {ip}:{port} ({service})")

            banner = data.decode(errors="ignore").strip()
            with print_lock:
                print(f"    └─ {CYAN}Response:{RESET} {banner}")
            write_result(f"    Response: {banner}")

            db.insert_banner(port_id, banner, None)

        except socket.timeout:
            pass

        sock.close()
    except Exception:
        pass
# =========================
# Worker Thread
# =========================
def worker(mode, stealth, scan_id):
    while True:
        ip, port = q.get()
        if mode == "tcp":
            scan_port_tcp(ip, port, stealth, scan_id)
        elif mode == "udp":
            scan_port_udp(ip, port, stealth, scan_id)
        q.task_done()


# =========================
# Main Program
# =========================
q = Queue()

print(f"{MAGENTA}Recon Scanner — TCP/UDP + Banners + Versions + Web Enum + OS Heuristic + SQLite{RESET}")

target_input = input("Enter target IP or subnet (e.g., 192.168.1.0/24): ").strip()

print("\nSelect scan preset:")
print("1) Fast Scan (TCP 1–1024)")
print("2) Full Scan (TCP 1–65535)")
print("3) Stealth Scan (TCP 1–1024, slow)")
print("4) UDP Scan (UDP 1–2000)")
print("5) Mixed Scan (TCP 1–2000)")
print("6) OS Detection Only (ping-based heuristic)")
print("7) Intel Placeholders Demo (no real intel)")

preset = input("Choose preset (1–7): ").strip()

scan_id = db.create_scan(preset, target_input)

# =========================
# OS Detection Only
# =========================
if preset == "6":
    try:
        network = ipaddress.ip_network(target_input, strict=False)
        targets = [str(ip) for ip in network.hosts()]
    except ValueError:
        targets = [target_input]

    for ip in targets:
        host_id = db.upsert_host(ip)
        detect_os_ping(ip, host_id)

    print(f"\n{MAGENTA}OS detection complete. Results saved to {output_file} and recon.db{RESET}")
    write_result("\nOS detection complete.")
    exit(0)

# =========================
# Intel Placeholder Demo
# =========================
if preset == "7":
    try:
        network = ipaddress.ip_network(target_input, strict=False)
        targets = [str(ip) for ip in network.hosts()]
    except ValueError:
        targets = [target_input]

    for ip in targets:
        host_id = db.upsert_host(ip)
        ssl_fingerprint(ip, 443, host_id)
        geoip_lookup(ip, host_id)
        asn_lookup(ip, host_id)
        cve_lookup("example_version", host_id)
        dns_enumeration("example.com", host_id)
        web_screenshot(f"http://{ip}", host_id)

    with print_lock:
        print(f"{CYAN}Intel placeholder functions recorded in recon.db (intel_placeholders table).{RESET}")
    write_result("Intel placeholders demo invoked.")
    exit(0)

# =========================
# Scan Preset Configuration
# =========================
if preset == "1":
    start_port, end_port = 1, 1024
    thread_count = 300
    mode = "tcp"
    stealth = False

elif preset == "2":
    start_port, end_port = 1, 65535
    thread_count = 500
    mode = "tcp"
    stealth = False

elif preset == "3":
    start_port, end_port = 1, 1024
    thread_count = 20
    mode = "tcp"
    stealth = True

elif preset == "4":
    start_port, end_port = 1, 2000
    thread_count = 200
    mode = "udp"
    stealth = False

elif preset == "5":
    start_port, end_port = 1, 2000
    thread_count = 300
    mode = "tcp"
    stealth = False

else:
    print(f"{YELLOW}Invalid preset.{RESET}")
    exit(1)

# =========================
# Target Expansion
# =========================
try:
    network = ipaddress.ip_network(target_input, strict=False)
    targets = [str(ip) for ip in network.hosts()]
except ValueError:
    targets = [target_input]

write_result(f"Scan Targets: {targets}")
write_result(f"Preset: {preset}")
write_result(f"Port Range: {start_port}-{end_port}")
write_result(f"Threads: {thread_count}")
write_result(f"Mode: {mode.upper()}")
write_result(f"Stealth: {stealth}")
write_result(f"Timestamp: {timestamp}")
write_result("")

print(f"\n{MAGENTA}Scanning {len(targets)} hosts using preset {preset}...{RESET}")
if stealth:
    print(f"{YELLOW}Stealth mode enabled — randomized delays active.{RESET}\n")
else:
    print(f"{CYAN}Normal mode — full speed scanning.{RESET}\n")

# =========================
# Thread Pool
# =========================
for _ in range(thread_count):
    t = threading.Thread(target=worker, args=(mode, stealth, scan_id))
    t.daemon = True
    t.start()

# =========================
# Queue Jobs
# =========================
for ip in targets:
    db.upsert_host(ip)
    for port in range(start_port, end_port + 1):
        q.put((ip, port))

q.join()

print(f"\n{MAGENTA}Scan complete. Results saved to {output_file} and recon.db{RESET}")
write_result("\nScan complete.")
