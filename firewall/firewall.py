import json
import sqlite3
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
import subprocess


# Add to firewall.py
def block_ip(ip):
    try:
        subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        # Already blocked
    except subprocess.CalledProcessError:
        # Not yet blocked, add rule
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        print(f"🔒 IP {ip} has been blocked via iptables.")


# Load rules from JSON file
def load_rules():
    with open("rules.json", "r") as f:
        return json.load(f)

# Log blocked or allowed packet to database
def log_packet(timestamp, src_ip, dst_ip, protocol, action, reason):
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            action TEXT,
            reason TEXT
        )
    ''')
    cursor.execute('''
        INSERT INTO logs (timestamp, src_ip, dst_ip, protocol, action, reason)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, dst_ip, protocol, action, reason))
    conn.commit()
    conn.close()

# Check if packet matches block rules
def packet_matches_rules(packet, rules):
    proto = None
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:
        proto = "TCP"
        port = packet[TCP].dport
    elif UDP in packet:
        proto = "UDP"
        port = packet[UDP].dport
    elif ICMP in packet:
        proto = "ICMP"
        port = None
    else:
        return False, "UNKNOWN"

    # Check rules
    if src_ip in rules["blocked_ips"]:
        return True, f"Blocked IP {src_ip}"
    if port and port in rules["blocked_ports"]:
        return True, f"Blocked port {port}"
    if proto in rules["blocked_protocols"]:
        return True, f"Blocked protocol {proto}"

    return False, "Allowed"

# Callback for each packet
def handle_packet(packet):
    if IP in packet:
        rules = load_rules()
        blocked, reason = packet_matches_rules(packet, rules)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "ICMP"
        if TCP in packet: proto = "TCP"
        elif UDP in packet: proto = "UDP"

        action = "BLOCKED" if blocked else "ALLOWED"

        if blocked:
            block_ip(src_ip)  # 🔒 Add iptables rule if matched

        log_packet(timestamp, src_ip, dst_ip, proto, action, reason)
        print(f"[{action}] {timestamp} {src_ip} → {dst_ip} [{proto}] — {reason}")


# Start sniffing
print("🔒 Starting Python Firewall... Press Ctrl+C to stop.")
sniff(filter="ip", prn=handle_packet, store=0)
